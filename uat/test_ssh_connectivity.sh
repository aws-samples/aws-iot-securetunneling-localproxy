#!/bin/bash
# Test SSH connectivity through tunnel (key-based and password-based)
# Exit codes: 0=pass, 1=fail
# shellcheck shell=bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

LOCALPROXY="${SCRIPT_DIR}/../build/bin/localproxy"
REGION="${AWS_REGION:-us-east-1}"
THING_NAME="uat-ssh-$(date +%s)-$$"
SOURCE_PORT_KEY="${SOURCE_PORT_KEY:-5560}"
SOURCE_PORT_PASS="${SOURCE_PORT_PASS:-5561}"
SSH_HOST="${SSH_HOST:-127.0.0.1}"
SSH_PORT="${SSH_PORT:-22}"
SSH_USER="${SSH_USER:-$(whoami)}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
SSH_PASS="${SSH_PASS:-}"

check_command jq
check_command ssh
check_command sshpass
check_localproxy "$LOCALPROXY"
check_aws_credentials

[[ -f "$SSH_KEY" ]] || {
  log_error "SSH key not found: $SSH_KEY"
  exit 1
}
[[ -n "$SSH_PASS" ]] || {
  log_error "SSH_PASS env var required for password test"
  exit 1
}

THING_CREATED=""
TUNNEL_ID_KEY=""
TUNNEL_ID_PASS=""

cleanup() {
  for pid_var in SOURCE_PID_KEY DEST_PID_KEY SOURCE_PID_PASS DEST_PID_PASS; do
    pid="${!pid_var}"
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
  done
  for tid in "$TUNNEL_ID_KEY" "$TUNNEL_ID_PASS"; do
    [[ -n "$tid" ]] && aws iotsecuretunneling close-tunnel --tunnel-id "$tid" --delete --region "$REGION" 2>/dev/null && log_info "Deleted tunnel: $tid" || true
  done
  [[ -n "$THING_CREATED" ]] && aws iot delete-thing --thing-name "$THING_NAME" --region "$REGION" 2>/dev/null && log_info "Deleted thing: $THING_NAME" || true
}

trap cleanup EXIT

start_tunnel() {
  local name="$1" src_port="$2" log_prefix="$3"
  local tunnel_output tunnel_id src_token dst_token

  tunnel_output=$(aws iotsecuretunneling open-tunnel \
    --destination-config "thingName=$THING_NAME,services=SSH" \
    --region "$REGION" --output json)
  tunnel_id=$(echo "$tunnel_output" | jq -r '.tunnelId')
  src_token=$(echo "$tunnel_output" | jq -r '.sourceAccessToken')
  dst_token=$(echo "$tunnel_output" | jq -r '.destinationAccessToken')

  [[ -z "$tunnel_id" || "$tunnel_id" == "null" ]] && {
    log_error "Failed to open $name tunnel"
    return 1
  }
  log_info "$name tunnel opened: $tunnel_id" >&2

  AWSIOT_TUNNEL_ACCESS_TOKEN="$dst_token" "$LOCALPROXY" \
    -r "$REGION" -d "$SSH_HOST:$SSH_PORT" -v 5 >"${LOG_DIR}/${log_prefix}_dest.log" 2>&1 &
  eval "${name^^}_DEST_PID=$!"

  AWSIOT_TUNNEL_ACCESS_TOKEN="$src_token" "$LOCALPROXY" \
    -r "$REGION" -s "$src_port" -b 127.0.0.1 -v 5 >"${LOG_DIR}/${log_prefix}_source.log" 2>&1 &
  eval "${name^^}_SOURCE_PID=$!"

  wait_for_log "${LOG_DIR}/${log_prefix}_dest.log" "Successfully established websocket connection" 15 || {
    log_error "$name dest proxy failed"
    return 1
  }
  wait_for_log "${LOG_DIR}/${log_prefix}_source.log" "Successfully established websocket connection" 15 || {
    log_error "$name source proxy failed"
    return 1
  }

  echo "$tunnel_id"
}

log_info "Testing SSH connectivity through tunnel..."

# Create thing
log_info "Creating IoT thing: $THING_NAME"
aws iot create-thing --thing-name "$THING_NAME" --region "$REGION" >/dev/null || {
  log_error "Failed to create thing"
  exit 1
}
THING_CREATED=1

# Test 1: Key-based SSH
log_info "=== Test 1: Key-based SSH ==="
TUNNEL_ID_KEY=$(start_tunnel "key" "$SOURCE_PORT_KEY" "ssh_key") || exit 1
SOURCE_PID_KEY=$KEY_SOURCE_PID
DEST_PID_KEY=$KEY_DEST_PID

if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i "$SSH_KEY" -p "$SOURCE_PORT_KEY" "$SSH_USER@127.0.0.1" "echo SSH_KEY_SUCCESS" 2>/dev/null | grep -q "SSH_KEY_SUCCESS"; then
  log_info "Key-based SSH test PASSED"
else
  log_error "Key-based SSH test FAILED"
  exit 1
fi

# Test 2: Password-based SSH
log_info "=== Test 2: Password-based SSH ==="
TUNNEL_ID_PASS=$(start_tunnel "pass" "$SOURCE_PORT_PASS" "ssh_pass") || exit 1
SOURCE_PID_PASS=$PASS_SOURCE_PID
DEST_PID_PASS=$PASS_DEST_PID

if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o PreferredAuthentications=password -p "$SOURCE_PORT_PASS" "$SSH_USER@127.0.0.1" "echo SSH_PASS_SUCCESS" 2>/dev/null | grep -q "SSH_PASS_SUCCESS"; then
  log_info "Password-based SSH test PASSED"
else
  log_error "Password-based SSH test FAILED"
  exit 1
fi

log_info "All SSH connectivity tests PASSED"
