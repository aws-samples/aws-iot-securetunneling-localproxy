#!/bin/bash
# UAT: Multiplexed tunnel establishment + file-transfer integrity
#
# Opens a SINGLE AWS IoT secure tunnel that carries MULTIPLE services
# (multiplexing), then pushes a distinct random payload through every service
# CONCURRENTLY and verifies each payload arrives byte-for-byte intact (sha256)
# on its own service with no cross-service contamination.
#
# This exercises the multiplexer end-to-end and would catch data-corruption
# regressions where one connection's bytes leak into another (e.g. the
# historical shared `static write_done` handler bug).
#
# Exit codes: 0=pass, 1=fail
# shellcheck shell=bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

LOCALPROXY="${SCRIPT_DIR}/../build/bin/localproxy"
REGION="${AWS_REGION:-us-east-1}"
THING_NAME="uat-multiplex-$(date +%s)-$$"

# Space-separated service IDs multiplexed over ONE tunnel (configurable).
read -r -a SERVICES <<<"${SERVICES:-DATA1 DATA2 DATA3}"
SRC_PORT_BASE="${SRC_PORT_BASE:-6001}" # source proxy listen ports start here
DST_PORT_BASE="${DST_PORT_BASE:-7001}" # destination service ports start here
FILE_SIZE="${FILE_SIZE:-131072}"       # bytes of random data per service (128 KiB)
TRANSFER_TIMEOUT="${TRANSFER_TIMEOUT:-60}"
WORK_DIR="$(mktemp -d)"

declare -A SVC_SRC_PORT SVC_DST_PORT
declare -A SEND_SUM RECV_SUM

THING_CREATED=""
TUNNEL_ID=""
SOURCE_PID=""
DEST_PID=""
LISTENER_PIDS=()

cleanup() {
  log_info "Cleaning up..."
  for pid in "${LISTENER_PIDS[@]}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
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
    aws iot delete-thing --thing-name "$THING_NAME" --region "$REGION" 2>/dev/null \
      && log_info "Deleted thing: $THING_NAME" \
      || log_error "Failed to delete thing: $THING_NAME"
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# ---- netcat flavor handling --------------------------------------------------
# nc syntax differs across implementations; detect once and adapt.
NC_FLAVOR=""
detect_nc() {
  check_command nc
  local help
  help="$(nc -h 2>&1 || true)"
  if printf '%s' "$help" | grep -qi 'ncat'; then
    NC_FLAVOR="ncat" # nmap ncat: `nc -l PORT`, closes on stdin EOF
  elif printf '%s' "$help" | grep -q -- '-N'; then
    NC_FLAVOR="openbsd" # netcat-openbsd: `nc -l PORT`, `-N` half-closes on EOF
  else
    NC_FLAVOR="traditional" # GNU/traditional: `nc -l -p PORT`, `-q 0` quits on EOF
  fi
  log_info "Detected netcat flavor: $NC_FLAVOR"
}

# nc_listen <port> <outfile> : accept one connection, write payload to file.
nc_listen() {
  local port="$1" out="$2"
  case "$NC_FLAVOR" in
    traditional) timeout "$TRANSFER_TIMEOUT" nc -l -p "$port" >"$out" 2>/dev/null ;;
    *) timeout "$TRANSFER_TIMEOUT" nc -l "$port" >"$out" 2>/dev/null ;;
  esac
}

# nc_send <port> <infile> : connect to source proxy port, stream file, close.
nc_send() {
  local port="$1" in="$2"
  case "$NC_FLAVOR" in
    openbsd) timeout "$TRANSFER_TIMEOUT" nc -N 127.0.0.1 "$port" <"$in" 2>/dev/null ;;
    traditional) timeout "$TRANSFER_TIMEOUT" nc -q 0 127.0.0.1 "$port" <"$in" 2>/dev/null ;;
    ncat) timeout "$TRANSFER_TIMEOUT" nc 127.0.0.1 "$port" <"$in" 2>/dev/null ;;
  esac
}

# ---- setup helpers -----------------------------------------------------------
check_prerequisites() {
  log_info "Checking prerequisites..."
  check_command aws
  check_command jq
  check_command sha256sum
  detect_nc
  check_localproxy "$LOCALPROXY"
  check_aws_credentials
  if [[ "${#SERVICES[@]}" -lt 2 ]]; then
    log_error "Multiplex test needs at least 2 services (got ${#SERVICES[@]})"
    exit 1
  fi
}

create_thing() {
  log_info "Creating IoT thing: $THING_NAME"
  aws iot create-thing --thing-name "$THING_NAME" --region "$REGION" >/dev/null || {
    log_error "Failed to create thing"
    exit 1
  }
  THING_CREATED=1
}

build_service_maps() {
  DST_MAP=""
  SRC_MAP=""
  local i=0 svc src dst
  for svc in "${SERVICES[@]}"; do
    src=$((SRC_PORT_BASE + i))
    dst=$((DST_PORT_BASE + i))
    SVC_SRC_PORT["$svc"]=$src
    SVC_DST_PORT["$svc"]=$dst
    DST_MAP+="${svc}=127.0.0.1:${dst},"
    SRC_MAP+="${svc}=${src},"
    i=$((i + 1))
  done
  DST_MAP="${DST_MAP%,}"
  SRC_MAP="${SRC_MAP%,}"
  log_info "Destination map: $DST_MAP"
  log_info "Source map:      $SRC_MAP"
}

open_tunnel() {
  local svc_csv
  svc_csv=$(
    IFS=,
    echo "${SERVICES[*]}"
  )
  log_info "Opening multiplexed tunnel in $REGION (services=$svc_csv)..."
  local out
  out=$(aws iotsecuretunneling open-tunnel \
    --destination-config "thingName=$THING_NAME,services=$svc_csv" \
    --region "$REGION" --output json)
  TUNNEL_ID=$(echo "$out" | jq -r '.tunnelId')
  SOURCE_TOKEN=$(echo "$out" | jq -r '.sourceAccessToken')
  DEST_TOKEN=$(echo "$out" | jq -r '.destinationAccessToken')
  [[ -z "$TUNNEL_ID" || "$TUNNEL_ID" == "null" ]] && {
    log_error "Failed to open tunnel"
    exit 1
  }
  log_info "Tunnel opened: $TUNNEL_ID"
}

start_proxies() {
  log_info "Starting destination proxy..."
  AWSIOT_TUNNEL_ACCESS_TOKEN="$DEST_TOKEN" "$LOCALPROXY" \
    -r "$REGION" -d "$DST_MAP" -v 5 \
    >"${LOG_DIR}/multiplex_dest.log" 2>&1 &
  DEST_PID=$!

  log_info "Starting source proxy..."
  AWSIOT_TUNNEL_ACCESS_TOKEN="$SOURCE_TOKEN" "$LOCALPROXY" \
    -r "$REGION" -s "$SRC_MAP" -b 127.0.0.1 -v 5 \
    >"${LOG_DIR}/multiplex_source.log" 2>&1 &
  SOURCE_PID=$!
}

# Test 1: both proxies establish the multiplexed websocket session.
test_establishment() {
  log_info "=== Test 1: Multiplexed tunnel establishment ==="
  if wait_for_log "${LOG_DIR}/multiplex_dest.log" "Successfully established websocket connection" 15 \
    && wait_for_log "${LOG_DIR}/multiplex_source.log" "Successfully established websocket connection" 15; then
    log_info "Establishment test PASSED"
    return 0
  fi
  log_error "Establishment test FAILED"
  log_error "--- dest log tail ---"
  tail -20 "${LOG_DIR}/multiplex_dest.log" 2>/dev/null || true
  log_error "--- source log tail ---"
  tail -20 "${LOG_DIR}/multiplex_source.log" 2>/dev/null || true
  return 1
}

# Test 2: concurrent file transfer through every service + integrity check.
test_integrity() {
  log_info "=== Test 2: Concurrent multiplexed file-transfer integrity ==="

  # Generate a distinct random payload per service and record its checksum.
  local svc
  for svc in "${SERVICES[@]}"; do
    head -c "$FILE_SIZE" /dev/urandom >"${WORK_DIR}/send_${svc}.bin"
    SEND_SUM["$svc"]=$(sha256sum "${WORK_DIR}/send_${svc}.bin" | awk '{print $1}')
  done
  log_info "Generated ${#SERVICES[@]} payloads of ${FILE_SIZE} bytes each"

  # Start a receiver on every destination service port BEFORE sending.
  for svc in "${SERVICES[@]}"; do
    nc_listen "${SVC_DST_PORT[$svc]}" "${WORK_DIR}/recv_${svc}.bin" &
    LISTENER_PIDS+=("$!")
  done
  sleep 2 # let listeners bind

  # Fire all transfers CONCURRENTLY to exercise the multiplexer.
  local send_pids=()
  for svc in "${SERVICES[@]}"; do
    nc_send "${SVC_SRC_PORT[$svc]}" "${WORK_DIR}/send_${svc}.bin" &
    send_pids+=("$!")
  done
  log_info "Launched ${#send_pids[@]} concurrent transfers; waiting for completion..."
  for pid in "${send_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  for pid in "${LISTENER_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done

  # Verify integrity + detect cross-service contamination.
  local failed=0
  for svc in "${SERVICES[@]}"; do
    local recv="${WORK_DIR}/recv_${svc}.bin"
    if [[ ! -s "$recv" ]]; then
      log_error "[$svc] no data received"
      failed=$((failed + 1))
      continue
    fi
    RECV_SUM["$svc"]=$(sha256sum "$recv" | awk '{print $1}')
    local recv_size send_size
    recv_size=$(wc -c <"$recv")
    send_size=$(wc -c <"${WORK_DIR}/send_${svc}.bin")

    if [[ "${RECV_SUM[$svc]}" == "${SEND_SUM[$svc]}" ]]; then
      log_info "[$svc] integrity OK (${recv_size} bytes, sha256 match)"
    else
      log_error "[$svc] integrity FAILED (sent ${send_size} bytes / recv ${recv_size} bytes; sha256 mismatch)"
      failed=$((failed + 1))
      # Cross-talk detection: did this service receive ANOTHER service's payload?
      local other
      for other in "${SERVICES[@]}"; do
        [[ "$other" == "$svc" ]] && continue
        if [[ "${RECV_SUM[$svc]}" == "${SEND_SUM[$other]}" ]]; then
          log_error "[$svc] CROSS-TALK: received payload intended for [$other] (multiplexer data corruption)"
        fi
      done
    fi
  done

  if [[ $failed -eq 0 ]]; then
    log_info "Integrity test PASSED for all ${#SERVICES[@]} services"
    return 0
  fi
  log_error "Integrity test FAILED for $failed/${#SERVICES[@]} services"
  return 1
}

main() {
  log_info "Testing multiplexed tunnel + file-transfer integrity..."
  check_prerequisites
  create_thing
  build_service_maps
  open_tunnel
  start_proxies

  local passed=0 failed=0
  for t in test_establishment test_integrity; do
    if $t; then passed=$((passed + 1)); else failed=$((failed + 1)); fi
  done

  echo ""
  log_info "=== UAT Results (multiplex integrity) ==="
  log_info "Passed: $passed, Failed: $failed"
  [[ $failed -eq 0 ]]
}

main "$@"
