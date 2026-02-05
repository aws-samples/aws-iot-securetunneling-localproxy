#!/bin/bash
# Test multi-port tunneling (V2/V3 feature)
# Exit codes: 0=pass, 1=fail
# shellcheck shell=bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

LOCALPROXY="${SCRIPT_DIR}/../build/bin/localproxy"
REGION="${AWS_REGION:-us-east-1}"
THING_NAME="uat-multiport-$(date +%s)-$$"

check_command jq
check_localproxy "$LOCALPROXY"

THING_CREATED=""

cleanup() {
  if [[ -n "$SOURCE_PID" ]]; then
    kill "$SOURCE_PID" 2>/dev/null
    wait "$SOURCE_PID" 2>/dev/null || log_error "Failed to stop source proxy"
  fi

  if [[ -n "$DEST_PID" ]]; then
    kill "$DEST_PID" 2>/dev/null
    wait "$DEST_PID" 2>/dev/null || log_error "Failed to stop destination proxy"
  fi

  if [[ -n "$TUNNEL_ID" ]]; then
    aws iotsecuretunneling close-tunnel --tunnel-id "$TUNNEL_ID" --delete --region "$REGION" 2>/dev/null \
      && log_info "Deleted tunnel: $TUNNEL_ID" \
      || log_error "Failed to close tunnel: $TUNNEL_ID"
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

log_info "Testing multi-port tunneling..."

# Create thing
log_info "Creating IoT thing: $THING_NAME"
aws iot create-thing --thing-name "$THING_NAME" --region "$REGION" >/dev/null || {
  log_error "Failed to create thing"
  exit 1
}
THING_CREATED=1

# Open tunnel with multiple services
TUNNEL_OUTPUT=$(aws iotsecuretunneling open-tunnel \
  --destination-config "thingName=$THING_NAME,services=SSH1,HTTP1" \
  --region "$REGION" \
  --output json)

TUNNEL_ID=$(echo "$TUNNEL_OUTPUT" | jq -r '.tunnelId')
SOURCE_TOKEN=$(echo "$TUNNEL_OUTPUT" | jq -r '.sourceAccessToken')
DEST_TOKEN=$(echo "$TUNNEL_OUTPUT" | jq -r '.destinationAccessToken')

log_info "Multi-port tunnel opened: $TUNNEL_ID"

# Start destination proxy with multiple service mappings
AWSIOT_TUNNEL_ACCESS_TOKEN="$DEST_TOKEN" "$LOCALPROXY" \
  -r "$REGION" -d "SSH1=127.0.0.1:22,HTTP1=127.0.0.1:80" -v 5 \
  >"${LOG_DIR}/multiport_dest.log" 2>&1 &
DEST_PID=$!

# Start source proxy with multiple service mappings
AWSIOT_TUNNEL_ACCESS_TOKEN="$SOURCE_TOKEN" "$LOCALPROXY" \
  -r "$REGION" -s "SSH1=5557,HTTP1=5558" -v 5 \
  >"${LOG_DIR}/multiport_source.log" 2>&1 &
SOURCE_PID=$!

if wait_for_log "${LOG_DIR}/multiport_dest.log" "Successfully established websocket connection" 15 \
  && wait_for_log "${LOG_DIR}/multiport_source.log" "Successfully established websocket connection" 15; then
  log_info "Multi-port tunneling test PASSED"
  exit 0
else
  log_error "Multi-port tunneling test FAILED"
  cat "${LOG_DIR}/multiport_dest.log"
  cat "${LOG_DIR}/multiport_source.log"
  exit 1
fi
