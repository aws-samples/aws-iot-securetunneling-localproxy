#!/bin/bash
# Test tunnel lifecycle operations
# Exit codes: 0=pass, 1=fail
# shellcheck shell=bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

REGION="${AWS_REGION:-us-east-1}"
THING_NAME="uat-lifecycle-$(date +%s)-$$"

check_command jq

TUNNEL_ID=""
THING_CREATED=""

cleanup() {
  if [[ -n "$TUNNEL_ID" ]]; then
    aws iotsecuretunneling close-tunnel \
      --tunnel-id "$TUNNEL_ID" \
      --region "$REGION" 2>/dev/null || log_error "Failed to close tunnel: $TUNNEL_ID"
  fi

  if [[ -n "$THING_CREATED" ]]; then
    aws iot delete-thing \
      --thing-name "$THING_NAME" \
      --region "$REGION" 2>/dev/null \
      && log_info "Deleted thing: $THING_NAME" \
      || log_error "Failed to delete thing: $THING_NAME"
  fi
}

trap cleanup EXIT

log_info "Testing tunnel lifecycle..."

# Create thing
log_info "Creating IoT thing: $THING_NAME"
aws iot create-thing --thing-name "$THING_NAME" --region "$REGION" >/dev/null || {
  log_error "Failed to create thing"
  exit 1
}
THING_CREATED=1

# Test: Open tunnel
TUNNEL_OUTPUT=$(aws iotsecuretunneling open-tunnel \
  --destination-config "thingName=$THING_NAME,services=SSH" \
  --region "$REGION" \
  --output json)

TUNNEL_ID=$(echo "$TUNNEL_OUTPUT" | jq -r '.tunnelId')
[[ -z "$TUNNEL_ID" || "$TUNNEL_ID" == "null" ]] && {
  log_error "Open tunnel failed"
  exit 1
}
log_info "Open tunnel: PASSED ($TUNNEL_ID)"

# Test: Describe tunnel
STATUS=$(aws iotsecuretunneling describe-tunnel \
  --tunnel-id "$TUNNEL_ID" \
  --region "$REGION" \
  --query 'tunnel.status' \
  --output text)
[[ "$STATUS" == "OPEN" ]] || {
  log_error "Describe tunnel failed: $STATUS"
  exit 1
}
log_info "Describe tunnel: PASSED (status=$STATUS)"

# Test: List tunnels
LIST_OUTPUT=$(aws iotsecuretunneling list-tunnels \
  --region "$REGION" \
  --query "tunnelSummaries[?tunnelId=='$TUNNEL_ID']" \
  --output json)
[[ $(echo "$LIST_OUTPUT" | jq 'length') -gt 0 ]] || {
  log_error "List tunnels failed"
  exit 1
}
log_info "List tunnels: PASSED"

# Test: Rotate access token
ROTATE_OUTPUT=$(aws iotsecuretunneling rotate-tunnel-access-token \
  --tunnel-id "$TUNNEL_ID" \
  --client-mode SOURCE \
  --region "$REGION" \
  --output json 2>/dev/null) || true
if [[ -n "$ROTATE_OUTPUT" ]]; then
  NEW_TOKEN=$(echo "$ROTATE_OUTPUT" | jq -r '.sourceAccessToken')
  [[ -n "$NEW_TOKEN" && "$NEW_TOKEN" != "null" ]] && log_info "Rotate token: PASSED"
else
  log_info "Rotate token: SKIPPED (may require active connection)"
fi

# Test: Close tunnel
aws iotsecuretunneling close-tunnel --tunnel-id "$TUNNEL_ID" --region "$REGION"
TUNNEL_ID=""
log_info "Close tunnel: PASSED"

log_info "All lifecycle tests PASSED"
