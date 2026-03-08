"""
aws-python/lambda_function.py

AWS Lambda entry point for the Fraud Sentinel service.

Handles two trigger types:
  - SQS:          Batch of fraud events from the queue
  - API Gateway:  Synchronous HTTP evaluation requests

The Rust core (fraud_sentinel) is loaded as a native extension built
via PyO3 + maturin. Build steps in README.

Environment Variables:
  DYNAMODB_TABLE  - Target table for processed events
  AWS_REGION      - Deployment region
  LOG_LEVEL       - DEBUG | INFO | WARNING (default: INFO)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

# Import the PyO3 Rust extension.
# Build with: `maturin build --release` inside rust-core/
from fraud_core import fraud_core as fraud_sentinel  # type: ignore  # noqa: E402  (native .so)

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Boto3 clients — initialized once per container (Lambda warm-path)
_dynamodb = boto3.resource("dynamodb", region_name=os.environ.get("AWS_REGION", "us-east-1"))
_table = _dynamodb.Table(os.environ.get("DYNAMODB_TABLE", "fraud-sentinel-events"))


# ── Lambda entry point ────────────────────────────────────────────────────────

def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    Unified handler. Routes to SQS or API Gateway processor based on
    the shape of the inbound Lambda event envelope.
    """
    if "Records" in event and event["Records"][0].get("eventSource") == "aws:sqs":
        return _handle_sqs_batch(event["Records"])

    if "requestContext" in event or "headers" in event:
        return _handle_api_gateway(event)

    logger.warning("Unrecognised event shape; falling back to direct processing")
    return _handle_raw(event)


# ── SQS batch processor ───────────────────────────────────────────────────────

def _handle_sqs_batch(records: list[dict]) -> dict[str, Any]:
    """
    Process a batch of SQS records. Failed items are reported back so
    SQS can re-drive only those messages (partial batch failure mode).
    """
    failures: list[dict] = []

    for record in records:
        message_id = record["messageId"]
        try:
            body = json.loads(record["body"])
            result = _evaluate_event(body)
            _persist_result(result, source="sqs")
            logger.info(
                "SQS event processed",
                extra={
                    "messageId": message_id,
                    "eventId": result.event_id,
                    "riskLevel": result.risk_level,
                    "action": result.recommended_action,
                },
            )
        except Exception as exc:
            logger.error("Failed to process SQS record %s: %s", message_id, exc)
            failures.append({"itemIdentifier": message_id})

    response: dict[str, Any] = {}
    if failures:
        response["batchItemFailures"] = failures

    return response


# ── API Gateway handler ───────────────────────────────────────────────────────

def _handle_api_gateway(event: dict[str, Any]) -> dict[str, Any]:
    """
    Synchronous evaluation endpoint.

    POST /evaluate
    {
        "user_id": "...",
        "ip_address": "...",
        "event_type": "transaction" | "login_attempt" | "api_call" | "account_change",
        "payload": { ... },
        "amount_cents": 12345,   // optional
        "country_code": "US"     // optional
    }
    """
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError as exc:
        return _error_response(400, f"Invalid JSON body: {exc}")

    try:
        result = _evaluate_event(body)
    except ValueError as exc:
        return _error_response(422, str(exc))
    except Exception as exc:
        logger.exception("Unexpected error during API Gateway evaluation")
        return _error_response(500, "Internal processing error")

    _persist_result(result, source="api_gateway")

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "X-Fraud-Risk-Level": result.risk_level,
        },
        "body": result.to_json(),
    }


# ── Raw event handler (local testing) ─────────────────────────────────────────

def _handle_raw(event: dict[str, Any]) -> dict[str, Any]:
    result = _evaluate_event(event)
    _persist_result(result, source="direct")
    return json.loads(result.to_json())


# ── Shared helpers ────────────────────────────────────────────────────────────

def _evaluate_event(body: dict[str, Any]) -> fraud_sentinel.FraudResult:
    """
    Extract fields from the normalised payload and call the Rust core.
    Raises ValueError for missing/bad fields (propagated to callers).
    """
    required = ("user_id", "ip_address", "event_type")
    missing = [f for f in required if not body.get(f)]
    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    payload_json = json.dumps(body.get("payload") or {})

    return fraud_sentinel.process_event(
        user_id=body["user_id"],
        ip_address=body["ip_address"],
        event_type=body["event_type"],
        payload_json=payload_json,
        amount_cents=body.get("amount_cents"),
        country_code=body.get("country_code"),
    )


def _persist_result(result: fraud_sentinel.FraudResult, source: str) -> None:
    """
    Write processed event to DynamoDB.
    TTL set to 90 days for automatic expiry of low-risk events.
    """
    import time

    try:
        _table.put_item(
            Item={
                "event_id": result.event_id,
                "user_id": result.user_id,
                "risk_score": str(result.risk_score),  # DynamoDB Decimal-safe
                "risk_level": result.risk_level,
                "triggered_rules": result.triggered_rules,
                "recommended_action": result.recommended_action,
                "source": source,
                "ttl": int(time.time()) + 90 * 86400,
            }
        )
    except Exception as exc:
        # Don't let storage failure kill the response
        logger.error("DynamoDB write failed for event %s: %s", result.event_id, exc)


def _error_response(status_code: int, message: str) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": message}),
    }
