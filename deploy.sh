#!/bin/bash
# deploy.sh — full rebuild and deploy in one shot
# Run from repo root: bash deploy.sh

set -e

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_CORE="$REPO/rust-core"
AWS_PYTHON="$REPO/aws-python"
DIST="$RUST_CORE/dist"
LAYER="$REPO/lambda-layer"

echo "==> [1/5] Building Docker image..."
docker build --no-cache --platform linux/amd64 -t fraud-core-builder "$RUST_CORE"

echo "==> [2/5] Extracting artifacts from container..."
rm -rf "$LAYER"
docker run --rm --platform linux/amd64 \
  -v "$LAYER":/layer-out \
  fraud-core-builder \
  bash -c "cp -r /artifacts/python /layer-out/"

SO=$(find "$LAYER" -name "*.so" | head -1)
if [ -z "$SO" ]; then
  echo "ERROR: No .so found — check Dockerfile"
  exit 1
fi
echo "    Found: $SO"

echo "==> [3/5] Packaging Lambda layer..."
mkdir -p "$DIST"
rm -f "$DIST/fraud-sentinel-layer.zip"
cd "$LAYER" && zip -r "$DIST/fraud-sentinel-layer.zip" python/ && cd "$REPO"
unzip -l "$DIST/fraud-sentinel-layer.zip"

echo "==> [4/5] Packaging Lambda handler..."
rm -f "$DIST/fraud-sentinel-lambda.zip"
zip -j "$DIST/fraud-sentinel-lambda.zip" "$AWS_PYTHON/lambda_function.py"

echo "==> [5/5] Deploying with Terraform..."
terraform apply -var="environment=dev" -auto-approve

echo ""
echo "==> Done! Testing endpoint..."
API=$(terraform output -raw api_endpoint)
curl -s -X POST "$API/evaluate" \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"user-42","ip_address":"1.2.3.4","event_type":"transaction","payload":{},"amount_cents":750000,"country_code":"XX"}' | python3 -m json.tool
