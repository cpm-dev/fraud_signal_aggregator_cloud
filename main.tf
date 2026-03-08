# aws-python/terraform/main.tf
# Fraud Sentinel — AWS Infrastructure
# Provisions: Lambda (Python), SQS queue, DynamoDB table, IAM roles

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

variable "environment" {
  default = "dev"
}

variable "lambda_zip_path" {
  description = "Path to the Lambda deployment zip (built by build.sh)"
  default     = "./rust-core/dist/fraud-sentinel-lambda.zip"
}

variable "layer_zip_path" {
  description = "Path to the Lambda layer zip containing the Rust .so"
  default     = "./rust-core/dist/fraud-sentinel-layer.zip"
}

# ── DynamoDB table ────────────────────────────────────────────────────────────

resource "aws_dynamodb_table" "fraud_events" {
  name           = "fraud-sentinel-events-${var.environment}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  global_secondary_index {
    name            = "UserIdIndex"
    hash_key        = "user_id"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Project     = "fraud-sentinel"
    Environment = var.environment
  }
}

# ── SQS queue (with DLQ) ─────────────────────────────────────────────────────

resource "aws_sqs_queue" "fraud_events_dlq" {
  name                      = "fraud-sentinel-dlq-${var.environment}"
  message_retention_seconds = 1209600 # 14 days
}

resource "aws_sqs_queue" "fraud_events" {
  name                       = "fraud-sentinel-events-${var.environment}"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 345600 # 4 days

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.fraud_events_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Project     = "fraud-sentinel"
    Environment = var.environment
  }
}

# ── IAM role for Lambda ───────────────────────────────────────────────────────

resource "aws_iam_role" "lambda_exec" {
  name = "fraud-sentinel-lambda-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "fraud-sentinel-lambda-policy"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.fraud_events.arn
      },
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query"
        ]
        Resource = [
          aws_dynamodb_table.fraud_events.arn,
          "${aws_dynamodb_table.fraud_events.arn}/index/*"
        ]
      }
    ]
  })
}

# ── Lambda function ───────────────────────────────────────────────────────────

resource "aws_lambda_function" "fraud_sentinel" {
  function_name    = "fraud-sentinel-${var.environment}"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.13"
  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.fraud_events.name
      LOG_LEVEL      = "INFO"
    }
  }

  layers = [
    # The PyO3 Rust extension is bundled as a Lambda layer
    aws_lambda_layer_version.rust_core.arn
  ]

  tags = {
    Project     = "fraud-sentinel"
    Environment = var.environment
  }
}

resource "aws_lambda_layer_version" "rust_core" {
  filename            = var.layer_zip_path
  layer_name          = "fraud-sentinel-core"
  compatible_runtimes = ["python3.12"]
  description         = "Rust core (fraud_sentinel.so) built with PyO3 + maturin"
}

# ── SQS → Lambda trigger ──────────────────────────────────────────────────────

resource "aws_lambda_event_source_mapping" "sqs_trigger" {
  event_source_arn                   = aws_sqs_queue.fraud_events.arn
  function_name                      = aws_lambda_function.fraud_sentinel.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 5

  # Report individual failures; don't retry the whole batch
  function_response_types = ["ReportBatchItemFailures"]
}

# ── API Gateway (HTTP API) ────────────────────────────────────────────────────

resource "aws_apigatewayv2_api" "fraud_api" {
  name          = "fraud-sentinel-api-${var.environment}"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id             = aws_apigatewayv2_api.fraud_api.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.fraud_sentinel.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "evaluate" {
  api_id    = aws_apigatewayv2_api.fraud_api.id
  route_key = "POST /evaluate"
  target    = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.fraud_api.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_lambda_permission" "apigw" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fraud_sentinel.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.fraud_api.execution_arn}/*"
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "api_endpoint" {
  value = aws_apigatewayv2_stage.default.invoke_url
}

output "sqs_queue_url" {
  value = aws_sqs_queue.fraud_events.url
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.fraud_events.name
}
