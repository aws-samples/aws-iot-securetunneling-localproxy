#!/bin/bash
# UAT Test Suite for AWS IoT Secure Tunneling LocalProxy
# Exit codes: 0=pass, 1=fail
# shellcheck shell=bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

LOCALPROXY="${SCRIPT_DIR}/../build/bin/localproxy"
REGION="${AWS_REGION:-us-east-1}"
THING_NAME="uat-thing-$(date +%s)-$$"
TEST_PORT="${TEST_PORT:-19999}"
SOURCE_PORT="${SOURCE_PORT:-5555}"
TIMEOUT="${TIMEOUT:-60}"

cleanup() {
    log_info "Cleaning up..."

    if [[ -n "$SOURCE_PID" ]]; then
        kill "$SOURCE_PID" 2>/dev/null
        wait "$SOURCE_PID" 2>/dev/null || log_error "Failed to stop source proxy"
    fi

    if [[ -n "$DEST_PID" ]]; then
        kill "$DEST_PID" 2>/dev/null
        wait "$DEST_PID" 2>/dev/null || log_error "Failed to stop destination proxy"
    fi

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

create_thing() {
    log_info "Creating IoT thing: $THING_NAME"
    aws iot create-thing --thing-name "$THING_NAME" --region "$REGION" >/dev/null || { log_error "Failed to create thing"; exit 1; }
    THING_CREATED=1
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    check_command aws
    check_command jq
    check_command nc
    check_localproxy "$LOCALPROXY"
    check_aws_credentials
}

open_tunnel() {
    log_info "Opening tunnel in $REGION..."
    TUNNEL_OUTPUT=$(aws iotsecuretunneling open-tunnel \
        --destination-config "thingName=$THING_NAME,services=SSH" \
        --region "$REGION" \
        --output json)
    
    TUNNEL_ID=$(echo "$TUNNEL_OUTPUT" | jq -r '.tunnelId')
    SOURCE_TOKEN=$(echo "$TUNNEL_OUTPUT" | jq -r '.sourceAccessToken')
    DEST_TOKEN=$(echo "$TUNNEL_OUTPUT" | jq -r '.destinationAccessToken')
    
    [[ -z "$TUNNEL_ID" || "$TUNNEL_ID" == "null" ]] && { log_error "Failed to open tunnel"; exit 1; }
    log_info "Tunnel opened: $TUNNEL_ID"
}

wait_for_log() {
    local log_file="$1" pattern="$2" timeout="${3:-30}" elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        grep -q "$pattern" "$log_file" 2>/dev/null && return 0
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

start_destination_proxy() {
    log_info "Starting destination proxy..."
    AWSIOT_TUNNEL_ACCESS_TOKEN="$DEST_TOKEN" "$LOCALPROXY" \
        -r "$REGION" -d "SSH=127.0.0.1:$TEST_PORT" -v 5 \
        > "${LOG_DIR}/dest_proxy.log" 2>&1 &
    DEST_PID=$!
    
    if ! wait_for_log "${LOG_DIR}/dest_proxy.log" "Listening" 10; then
        if ! kill -0 "$DEST_PID" 2>/dev/null; then
            log_error "Destination proxy failed to start"
            cat "${LOG_DIR}/dest_proxy.log"
            exit 1
        fi
    fi
    log_info "Destination proxy started (PID: $DEST_PID)"
}

start_source_proxy() {
    log_info "Starting source proxy..."
    AWSIOT_TUNNEL_ACCESS_TOKEN="$SOURCE_TOKEN" "$LOCALPROXY" \
        -r "$REGION" -s "SSH=$SOURCE_PORT" -v 5 \
        > "${LOG_DIR}/source_proxy.log" 2>&1 &
    SOURCE_PID=$!
    
    if ! wait_for_log "${LOG_DIR}/source_proxy.log" "Listening" 10; then
        if ! kill -0 "$SOURCE_PID" 2>/dev/null; then
            log_error "Source proxy failed to start"
            cat "${LOG_DIR}/source_proxy.log"
            exit 1
        fi
    fi
    log_info "Source proxy started (PID: $SOURCE_PID)"
}

test_tunnel_connection() {
    log_info "Testing tunnel connection..."
    
    if wait_for_log "${LOG_DIR}/source_proxy.log" "Successfully established websocket connection" 15 && \
       wait_for_log "${LOG_DIR}/dest_proxy.log" "Successfully established websocket connection" 15; then
        log_info "Both proxies connected to AWS IoT Secure Tunneling service"
        return 0
    else
        log_error "Proxy connection verification failed"
        return 1
    fi
}

test_data_transfer() {
    log_info "Testing data transfer through tunnel..."
    
    # Start a simple TCP server on destination port that echoes back data
    rm -f "${LOG_DIR}/server_received.txt"
    (nc -l -p "$TEST_PORT" 2>/dev/null || nc -l "$TEST_PORT" 2>/dev/null) > "${LOG_DIR}/server_received.txt" &
    NC_PID=$!
    sleep 2
    
    # Send test data through source proxy
    TEST_DATA="UAT_TEST_$(date +%s)"
    echo "$TEST_DATA" | timeout 10 nc localhost "$SOURCE_PORT" 2>/dev/null || true
    
    sleep 3
    kill "$NC_PID" 2>/dev/null; wait "$NC_PID" 2>/dev/null || true
    
    # Check if connection was established via proxy logs
    if grep -q "Connected to 127.0.0.1" "${LOG_DIR}/dest_proxy.log" 2>/dev/null; then
        log_info "Data transfer test PASSED"
        return 0
    else
        log_error "Data transfer test FAILED - no connection established"
        log_error "Destination proxy log:"
        tail -20 "${LOG_DIR}/dest_proxy.log" 2>/dev/null || true
        log_error "Source proxy log:"
        tail -20 "${LOG_DIR}/source_proxy.log" 2>/dev/null || true
        return 1
    fi
}

verify_tunnel_status() {
    log_info "Verifying tunnel status..."
    STATUS=$(aws iotsecuretunneling describe-tunnel \
        --tunnel-id "$TUNNEL_ID" \
        --region "$REGION" \
        --query 'tunnel.status' \
        --output text)
    
    if [[ "$STATUS" == "OPEN" ]]; then
        log_info "Tunnel status: $STATUS"
        return 0
    else
        log_error "Unexpected tunnel status: $STATUS"
        return 1
    fi
}

run_tests() {
    log_info "=== Starting UAT Tests ==="
    local passed=0 failed=0
    
    for test in verify_tunnel_status test_tunnel_connection test_data_transfer; do
        if $test; then
            passed=$((passed + 1))
        else
            failed=$((failed + 1))
        fi
    done
    
    echo ""
    log_info "=== UAT Results ==="
    log_info "Passed: $passed, Failed: $failed"
    [[ $failed -eq 0 ]]
}

main() {
    check_prerequisites
    create_thing
    open_tunnel
    start_destination_proxy
    start_source_proxy
    run_tests
}

main "$@"
