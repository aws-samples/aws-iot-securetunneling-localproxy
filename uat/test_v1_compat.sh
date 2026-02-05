#!/bin/bash
# Test V1 backward compatibility mode
# Exit codes: 0=pass, 1=fail
# shellcheck shell=bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

LOCALPROXY="${SCRIPT_DIR}/../build/bin/localproxy"
REGION="${AWS_REGION:-us-east-1}"
THING_NAME="uat-v1compat-$(date +%s)-$$"
SOURCE_PORT="${SOURCE_PORT:-5556}"

THING_CREATED=""

cleanup() {
  if [[ -n "$SOURCE_PID" ]]; then
    kill "$SOURCE_PID" 2>/dev/null
    wait "$SOURCE_PID" 2>/dev/null || log_error "Failed to stop source proxy"
  fi

  if [[ -n "$TUNNEL_ID" ]]; then
    aws iotsecuretunneling close-tunnel --tunnel-id "$TUNNEL_ID" --region "$REGION" 2>/dev/null || log_error "Failed to close tunnel: $TUNNEL_ID"
    aws iotsecuretunneling delete-tunnel --tunnel-id "$TUNNEL_ID" --region "$REGION" 2>/dev/null || log_error "Failed to delete tunnel: $TUNNEL_ID"
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

log_info "Testing V1 backward compatibility..."

check_prerequisites() {
  log_info "Checking prerequisites..."
  check_command aws
  check_command jq
  check_localproxy "$LOCALPROXY"
  check_aws_credentials
}

check_prerequisites

# Create thing
log_info "Creating IoT thing: $THING_NAME"
aws iot create-thing --thing-name "$THING_NAME" --region "$REGION" >/dev/null || {
  log_error "Failed to create thing"
  exit 1
}
THING_CREATED=1

# Open tunnel with single service (V1 compatible)
TUNNEL_OUTPUT=$(aws iotsecuretunneling open-tunnel \
  --destination-config "thingName=$THING_NAME,services=SSH" \
  --region "$REGION" \
  --output json)

TUNNEL_ID=$(echo "$TUNNEL_OUTPUT" | jq -r '.tunnelId')
SOURCE_TOKEN=$(echo "$TUNNEL_OUTPUT" | jq -r '.sourceAccessToken')

[[ -z "$TUNNEL_ID" || "$TUNNEL_ID" == "null" ]] && {
  log_error "Failed to open tunnel"
  exit 1
}
log_info "Tunnel opened: $TUNNEL_ID"

# Start source proxy with V1 destination client type
AWSIOT_TUNNEL_ACCESS_TOKEN="$SOURCE_TOKEN" "$LOCALPROXY" \
  -r "$REGION" -s "$SOURCE_PORT" --destination-client-type V1 -v 5 \
  >"${LOG_DIR}/v1_source.log" 2>&1 &
SOURCE_PID=$!

if wait_for_log "${LOG_DIR}/v1_source.log" "Successfully established websocket connection" 15; then
  log_info "V1 backward compatibility test PASSED"
  exit 0
fi

log_error "V1 backward compatibility test FAILED"
cat "${LOG_DIR}/v1_source.log"
exit 1
