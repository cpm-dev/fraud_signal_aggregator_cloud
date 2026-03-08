"""
aws-python/tests/test_lambda.py

Unit tests for the Lambda handler using a mocked fraud_sentinel module.
Run with: pytest tests/ -v
"""

import json
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# ── Stub out the native Rust extension for test environments ──────────────────

class _MockFraudResult:
    def __init__(self, risk_level="LOW", score=0.1, action="ALLOW"):
        self.event_id = "test-event-id-123"
        self.user_id = "user-42"
        self.risk_score = score
        self.risk_level = risk_level
        self.triggered_rules = []
        self.recommended_action = action

    def to_json(self):
        return json.dumps({
            "event_id": self.event_id,
            "user_id": self.user_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "triggered_rules": self.triggered_rules,
            "recommended_action": self.recommended_action,
        })


_fraud_core_mock = types.ModuleType("fraud_core")
_fraud_core_inner = types.ModuleType("fraud_core.fraud_core")
_fraud_core_inner.process_event = MagicMock(return_value=_MockFraudResult())
_fraud_core_inner.FraudResult = _MockFraudResult
_fraud_core_mock.fraud_core = _fraud_core_inner
sys.modules["fraud_core"] = _fraud_core_mock
sys.modules["fraud_core.fraud_core"] = _fraud_core_inner

# Also stub boto3 so tests don't need AWS creds
import boto3  # noqa: E402
boto3.resource = MagicMock()

import lambda_function  # noqa: E402  # imported after stubs


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestApiGatewayHandler(unittest.TestCase):

    def _apigw_event(self, body: dict) -> dict:
        return {
            "requestContext": {"http": {"method": "POST"}},
            "body": json.dumps(body),
        }

    def test_valid_login_event_returns_200(self):
        event = self._apigw_event({
            "user_id": "user-42",
            "ip_address": "1.2.3.4",
            "event_type": "login_attempt",
            "payload": {"attempt_count": 1},
        })
        response = lambda_function.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertIn("risk_level", body)

    def test_missing_user_id_returns_422(self):
        event = self._apigw_event({
            "ip_address": "1.2.3.4",
            "event_type": "login_attempt",
        })
        response = lambda_function.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 422)

    def test_invalid_json_body_returns_400(self):
        event = {
            "requestContext": {"http": {"method": "POST"}},
            "body": "not-json",
        }
        response = lambda_function.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 400)

    def test_risk_level_header_present(self):
        event = self._apigw_event({
            "user_id": "user-1",
            "ip_address": "5.6.7.8",
            "event_type": "transaction",
            "payload": {},
            "amount_cents": 1000,
        })
        response = lambda_function.lambda_handler(event, None)
        self.assertIn("X-Fraud-Risk-Level", response["headers"])


class TestSqsBatchHandler(unittest.TestCase):

    def _sqs_event(self, bodies: list[dict]) -> dict:
        return {
            "Records": [
                {
                    "messageId": f"msg-{i}",
                    "eventSource": "aws:sqs",
                    "body": json.dumps(body),
                }
                for i, body in enumerate(bodies)
            ]
        }

    def test_valid_batch_returns_no_failures(self):
        event = self._sqs_event([
            {
                "user_id": "user-1",
                "ip_address": "10.0.0.1",
                "event_type": "api_call",
                "payload": {"calls_per_minute": 10},
            }
        ])
        response = lambda_function.lambda_handler(event, None)
        self.assertNotIn("batchItemFailures", response)

    def test_invalid_record_reported_as_failure(self):
        _fraud_core_mock.side_effect = ValueError("bad input")
        event = self._sqs_event([
            {"user_id": "", "ip_address": "bad", "event_type": "???"}
        ])
        response = lambda_function.lambda_handler(event, None)
        self.assertIn("batchItemFailures", response)
        self.assertEqual(len(response["batchItemFailures"]), 1)
        # Reset for other tests
        _fraud_core_mock.side_effect = None
        _fraud_core_mock.fraud_core = _fraud_core_inner


if __name__ == "__main__":
    unittest.main()
