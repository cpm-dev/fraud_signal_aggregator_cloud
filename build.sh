#!/bin/bash
# build.sh
# Builds the Rust core via Docker and packages the Lambda layer + handler zip.
# Run from anywhere — paths are resolved relative to this script.
#
# Usage: bash build.sh
# Requirements: Docker, zip

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUST_CORE_DIR="$SCRIPT_DIR/rust-core"
AWS_PYTHON_DIR="$SCRIPT_DIR/aws-python"
DIST_DIR="$RUST_CORE_DIR/dist"
LAYER_DIR="$SCRIPT_DIR/lambda-layer"

echo "==> fraud-sentinel build"
echo "    Root:      $SCRIPT_DIR"
echo "    Rust core: $RUST_CORE_DIR"
echo "    Output:    $DIST_DIR"
echo ""

echo "==> [1/3] Building Rust core (Python 3.12 / x86_64 Linux) via Docker..."
docker build \
  --no-cache \
  --platform linux/amd64 \
  -t fraud-core-builder \
  "$RUST_CORE_DIR"

echo "==> [2/3] Packaging Lambda layer..."
rm -rf "$LAYER_DIR"
mkdir -p "$DIST_DIR"

docker run --rm \
  --platform linux/amd64 \
  -v "$LAYER_DIR":/layer-out \
  fraud-core-builder \
  bash -c "cp -r /artifacts/python /layer-out/"

SO_FILE=$(find "$LAYER_DIR" -name "*.so" | head -1)
if [ -z "$SO_FILE" ]; then
  echo "ERROR: No .so found after Docker extraction — check Dockerfile build output"
  exit 1
fi
echo "    Found .so: $SO_FILE"

cd "$LAYER_DIR"
zip -r "$DIST_DIR/fraud-sentinel-layer.zip" python/
cd "$SCRIPT_DIR"

echo "    Layer contents:"
unzip -l "$DIST_DIR/fraud-sentinel-layer.zip"

echo "==> [3/3] Packaging Lambda handler..."
zip -j "$DIST_DIR/fraud-sentinel-lambda.zip" "$AWS_PYTHON_DIR/lambda_function.py"

echo ""
echo "==> Build complete!"
ls -lh "$DIST_DIR"/*.zip
echo ""
echo "Next: terraform apply -var=environment=dev"