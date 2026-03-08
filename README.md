# 🛡️ Fraud Sentinel

**Real-time fraud signal aggregation across AWS and GCP — Rust core, Python Lambda, Go Cloud Run.**

A production-grade event processing service demonstrating multi-cloud architecture with a high-performance Rust scoring engine shared across cloud runtimes via PyO3 (Python) and CGO (Go).

---

## How It Works

```
Your POST request
      │
      ▼
API Gateway (AWS)
      │
      ▼
Lambda Function (Python 3.13)
      │  lambda_function.py
      │  parses the HTTP/SQS event
      │  calls fraud_core.process_event()
      │
      ▼
Rust Core (.so — Lambda Layer)
      │  validates the event
      │  runs 6-signal scoring pipeline
      │  returns risk_score, risk_level, triggered_rules
      │
      ▼
Lambda Function (Python) continued
      │  writes result to DynamoDB
      │  returns HTTP response
      │
      ▼
JSON response to caller
```

The Rust core is compiled to `fraud_core.cpython-313-x86_64-linux-gnu.so` and
deployed as a Lambda Layer mounted at `/opt/python/`. Python loads it like any
native module via PyO3 — AWS-specific logic stays in Python, business logic
runs in Rust.

---

## Architecture

```
                     ┌──────────────────┐
                     │   Fraud Events   │
                     │ (txn / login /   │
                     │  api / acct chg) │
                     └────────┬─────────┘
                              │
             ┌────────────────┴────────────────┐
             │                                 │
        ┌────▼────┐                      ┌─────▼────┐
        │   AWS   │                      │   GCP    │
        └────┬────┘                      └─────┬────┘
             │                                 │
   ┌─────────┴──────────┐         ┌────────────┴──────────┐
   │                    │         │                        │
┌──▼──────┐       ┌─────▼──┐  ┌──▼──────┐         ┌──────▼──┐
│API GW   │       │  SQS   │  │Pub/Sub  │         │Cloud Run│
│HTTP API │       │ Queue  │  │ Topic   │         │  HTTP   │
└──┬──────┘       └──┬─────┘  └──┬──────┘         └──┬──────┘
   │                 │           │                    │
┌──▼─────────────────▼──┐  ┌────▼────────────────────▼──┐
│  Lambda (Python 3.13) │  │   Cloud Run (Go 1.22)       │
│  lambda_function.py   │  │   main.go                   │
└──────────┬────────────┘  └────────────┬────────────────┘
           │                            │
           │         PyO3 / CGO         │
           └──────────────┬─────────────┘
                          │
               ┌──────────▼──────────┐
               │   Rust Core Library  │
               │  fraud-sentinel-core │
               │                      │
               │  validate()          │
               │  score_and_transform()│
               │  EventStore trait    │
               └──────────┬──────────┘
                          │
             ┌────────────┴────────────┐
             │                         │
      ┌──────▼──────┐          ┌───────▼──────┐
      │  DynamoDB   │          │  BigQuery /  │
      │  (AWS)      │          │  Cloud SQL   │
      └─────────────┘          └──────────────┘
```

---

## Project Structure

```
fraud-signal-aggregator/
├── build.sh                    # Builds Docker image + packages zips
├── deploy.sh                   # Full build + terraform apply + smoke test
├── smoke_test.sh               # 12-scenario test suite + volume burst
├── attach_policies.sh          # One-time IAM setup for rust_int_dev
├── main.tf                     # AWS Terraform (Lambda, SQS, DynamoDB, API GW)
│
├── rust-core/                  # Rust library (PyO3)
│   ├── Cargo.toml              # crate-type = ["cdylib", "rlib"] — required
│   ├── Dockerfile              # python:3.13-slim + Rust + maturin
│   └── src/
│       ├── lib.rs              # PyO3 bindings — #[pymodule] fn fraud_core
│       ├── models/mod.rs       # FraudEvent, RiskLevel, ProcessedFraudEvent
│       ├── validation/mod.rs   # Business rule validators
│       ├── transform/mod.rs    # 6-signal weighted scoring pipeline
│       └── storage/mod.rs      # EventStore trait (DynamoDB/BigQuery/InMemory)
│
├── aws-python/                 # AWS Lambda adapter
│   ├── lambda_function.py      # Unified handler: SQS batch + API Gateway
│   └── tests/
│       └── test_lambda.py      # Unit tests (mocked Rust extension)
│
├── gcp-go/                     # GCP Cloud Run adapter (Phase 2)
│   ├── main.go                 # Cloud Run HTTP server (Pub/Sub + HTTP)
│   └── terraform/main.tf       # Pub/Sub, Cloud Run, IAM
│
└── gcp-terraform/              # GCP infrastructure
    └── main.tf
```

---

## Fraud Scoring Engine

The Rust core evaluates six signals, each with a calibrated weight:

| Signal | Weight | Trigger |
|---|---|---|
| `HIGH_VALUE_TXN` | 0.35 | Transaction > $5,000 |
| `FAILED_LOGIN_BURST` | 0.30 | ≥5 login attempts |
| `SUSPICIOUS_COUNTRY` | 0.25 | High-risk country code (XX, YY, ZZ) |
| `RAPID_API_CALLS` | 0.20 | >120 API calls/min |
| `ACCOUNT_CHANGE_POST_TXN` | 0.15 | Account change <60s after transaction |
| `UNEXPECTED_IP_CLASS` | 0.10 | Unexpected IP range |

Scores accumulate and clamp to `[0.0, 1.0]`:

| Score | Risk Level | Action |
|---|---|---|
| < 0.25 | LOW | ALLOW |
| 0.25–0.55 | MEDIUM | STEP_UP_AUTH |
| 0.55–0.80 | HIGH | HOLD_FOR_REVIEW / REQUIRE_MFA |
| > 0.80 | CRITICAL | BLOCK_AND_ALERT |

---

## Prerequisites

| Tool | Install |
|---|---|
| Rust + maturin | https://rustup.rs then `pip install maturin` |
| Go | https://go.dev/dl/ |
| Docker Desktop | https://www.docker.com/products/docker-desktop |
| AWS CLI | `brew install awscli` |
| Terraform | `brew tap hashicorp/tap && brew install hashicorp/tap/terraform` |

---

## AWS Setup

### 1. Configure AWS CLI profiles
```bash
aws configure                            # admin (colin_payne_admin → default)
aws configure --profile rust_int_dev     # deployment user
```

### 2. Attach required policies to rust_int_dev
```bash
bash attach_policies.sh
```

Required policies: `IAMFullAccess`, `AmazonS3FullAccess`, `AWSLambda_FullAccess`,
`AmazonSQSFullAccess`, `AmazonDynamoDBFullAccess`, `AmazonAPIGatewayAdministrator`

---

## Build & Deploy

### Full build + deploy in one command
```bash
bash deploy.sh
```

This script:
1. Builds Docker image (`python:3.13-slim` + Rust + maturin)
2. Compiles Rust core targeting `x86_64-unknown-linux-gnu`
3. Extracts `.so` from wheel into correct Lambda layer structure
4. Packages `fraud-sentinel-layer.zip` and `fraud-sentinel-lambda.zip`
5. Runs `terraform apply`
6. Smoke tests the live endpoint

### Why Docker?
macOS Apple Silicon cannot compile for Linux x86_64 directly. Docker with
`--platform linux/amd64` handles the cross-compilation.

### Lambda layer structure
```
python/
└── fraud_core/
    ├── __init__.py
    └── fraud_core.cpython-313-x86_64-linux-gnu.so
```

---

## What Gets Deployed (Terraform)

| Resource | Name | Purpose |
|---|---|---|
| Lambda | `fraud-sentinel-dev` | Python 3.13 handler |
| Lambda Layer | `fraud-sentinel-core` | Rust `.so` |
| API Gateway | `fraud-sentinel-api-dev` | `POST /evaluate` |
| SQS Queue | `fraud-sentinel-events-dev` | Async event ingestion |
| SQS DLQ | `fraud-sentinel-dlq-dev` | Failed message retry |
| DynamoDB | `fraud-sentinel-events-dev` | Processed event storage |
| IAM Role | `fraud-sentinel-lambda-dev` | Lambda permissions |

---

## Testing

### Run all scenarios
```bash
bash smoke_test.sh
```

Covers 12 scenarios across LOW / MEDIUM / HIGH / CRITICAL risk levels
plus a 20-request concurrent burst.

### Manual curl test
```bash
# High risk — should return HOLD_FOR_REVIEW
curl -s -X POST https://xydmka4s4c.execute-api.us-east-1.amazonaws.com/evaluate \
  -H 'Content-Type: application/json' \
  -d '{
    "user_id": "user-99",
    "ip_address": "1.2.3.4",
    "event_type": "transaction",
    "payload": {},
    "amount_cents": 750000,
    "country_code": "XX"
  }' | python3 -m json.tool
```

### Run Python unit tests
```bash
PYTHONPATH=aws-python pytest aws-python/tests/test_lambda.py -v
```

### Check Lambda logs
```bash
aws logs tail /aws/lambda/fraud-sentinel-dev --follow --profile rust_int_dev
```

---

## Event Payload Reference

```json
{
  "user_id": "user-42",
  "ip_address": "203.0.113.5",
  "event_type": "transaction",
  "payload": {
    "merchant": "acme-corp",
    "attempt_count": 1
  },
  "amount_cents": 750000,
  "country_code": "US"
}
```

`event_type` values: `transaction` | `login_attempt` | `api_call` | `account_change`

---

## Deployment Status

| Component | Status |
|---|---|
| Rust core (PyO3) | ✅ Live |
| Python Lambda (AWS) | ✅ Live |
| API Gateway | ✅ Live |
| SQS + DLQ | ✅ Live |
| DynamoDB | ✅ Live |
| Go Cloud Run (GCP) | 🔜 Phase 2 |
| GCP Terraform | 🔜 Phase 2 |

---

## Why This Stack

| Decision | Rationale |
|---|---|
| **Rust core** | Sub-millisecond scoring, memory-safe, single compiled artifact runs everywhere |
| **PyO3 for Lambda** | Python is the dominant Lambda runtime — PyO3 gives Rust performance with Python ergonomics |
| **Go for Cloud Run** | Google's preferred Cloud Run language, excellent Pub/Sub SDK, CGO bridges to Rust |
| **SQS / Pub/Sub** | Industry-standard async fan-out, both support DLQ and partial batch failure |
| **DynamoDB / BigQuery** | DynamoDB for low-latency hot lookups, BigQuery for analytics and audit |
| **Terraform** | Consistent, repeatable infrastructure across both clouds |
| **Docker build** | Cross-compile Rust for Lambda from macOS Apple Silicon |

---

## Additional Information

**"Why Rust for the core?"**
> The scoring pipeline runs on every event before any I/O. Rust gives deterministic sub-millisecond latency with no GC pauses. The same compiled artifact runs as a Python `.so` via PyO3 — so we get native performance in Lambda without duplicating logic.

**"Why Python for Lambda?"**
> Python is the most operationally familiar Lambda runtime. PyO3 lets us keep correctness-critical business logic in Rust while the Python layer handles AWS-specific concerns like SQS event parsing and DynamoDB writes.

**"How does multi-cloud parity work?"**
> The Rust core is completely cloud-agnostic — it operates on `FraudEvent` structs. Cloud differences are isolated to thin adapter layers. Adding Azure would mean a new adapter, not touching the scoring engine.


