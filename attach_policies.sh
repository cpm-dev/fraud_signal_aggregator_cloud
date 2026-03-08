#!/bin/bash
# attach_policies.sh
# Attaches missing AWS policies to rust_int_dev using colin_payne_admin
# Usage: bash attach_policies.sh

set -e

ADMIN_PROFILE="default"
TARGET_USER="rust_int_dev"

POLICIES=(
  "arn:aws:iam::aws:policy/AmazonSQSFullAccess"
  "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
  "arn:aws:iam::aws:policy/AmazonAPIGatewayAdministrator"
)

echo "Attaching policies to $TARGET_USER using profile $ADMIN_PROFILE..."
echo ""

for POLICY_ARN in "${POLICIES[@]}"; do
  POLICY_NAME=$(basename "$POLICY_ARN")
  echo "  → Attaching $POLICY_NAME..."
  aws iam attach-user-policy \
    --user-name "$TARGET_USER" \
    --policy-arn "$POLICY_ARN" \
    --profile "$ADMIN_PROFILE"
  echo "    ✓ Done"
done

echo ""
echo "Verifying all attached policies for $TARGET_USER..."
echo ""
aws iam list-attached-user-policies \
  --user-name "$TARGET_USER" \
  --profile "$ADMIN_PROFILE"
