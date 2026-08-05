#!/bin/bash
# Test CLI argument handling: informational flags and usage errors.
# Needs no AWS credentials or tunnel; every case exits before connecting.
# Exit codes: 0=pass, 1=fail
# shellcheck shell=bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

LOCALPROXY="${SCRIPT_DIR}/../build/bin/localproxy"
LOG_FILE="${LOG_DIR}/cli_usage.log"

check_localproxy "$LOCALPROXY"

: >"$LOG_FILE"
FAILURES=0

# A 100-char dummy token: long enough to pass access-token validation, so cases
# that exercise later checks are not short-circuited by the token check.
DUMMY_TOKEN=$(printf 'a%.0s' {1..100})

# run_case <name> <expected_exit> <expected_pattern> -- <args...>
# Asserts the exit code and that stdout+stderr matches (or, for an empty
# pattern, that no error/usage text was produced).
run_case() {
  local name="$1" expected_exit="$2" pattern="$3"
  shift 4 # drop name, exit, pattern and the -- separator

  local output status
  set +e
  output=$(timeout 20 "$LOCALPROXY" "$@" 2>&1)
  status=$?
  set -e

  {
    echo "=== ${name}"
    echo "\$ localproxy $*"
    echo "$output"
    echo "exit=${status}"
    echo
  } >>"$LOG_FILE"

  if [[ $status -ne $expected_exit ]]; then
    log_error "${name}: expected exit ${expected_exit}, got ${status}"
    FAILURES=$((FAILURES + 1))
    return
  fi

  if [[ -n "$pattern" ]]; then
    if ! grep -qF -- "$pattern" <<<"$output"; then
      log_error "${name}: output missing \"${pattern}\""
      FAILURES=$((FAILURES + 1))
      return
    fi
  elif grep -qiE 'fatal|\[error\]|Try .localproxy --help' <<<"$output"; then
    log_error "${name}: unexpected error output"
    FAILURES=$((FAILURES + 1))
    return
  fi

  log_info "${name}: PASSED"
}

log_info "Testing CLI argument handling..."

# Informational flags exit 0 immediately and print no error. The version banner
# is printed unconditionally by main(), so --version/-V only has to stop there.
run_case "--version exits 0" 0 "" -- --version
run_case "-V exits 0" 0 "" -- -V
run_case "--help exits 0" 0 "Show help message" -- --help
run_case "-h exits 0" 0 "Show help message" -- -h

# A bad invocation names the option actually at fault and points at --help.
run_case "no args reports missing token" 1 \
  "the option '--access-token' is required but missing" --
run_case "no args suggests help" 1 \
  "Try 'localproxy --help'" --

run_case "unknown option is reported" 1 "unrecognised option '-Z'" -- -Z

# -v stays bound to --verbose; it takes an argument and is not a version flag.
run_case "-v requires an argument" 1 \
  "the required argument for option '--verbose' is missing" -- -v

# Cases below supply a token so validation reaches the check under test.
export AWSIOT_TUNNEL_ACCESS_TOKEN="$DUMMY_TOKEN"

run_case "region and endpoint are exclusive" 1 \
  "Must specify one and only one of --region/-r or --proxy-endpoint/-e" \
  -- -r us-east-1 -e data.tunneling.iot.us-east-1.amazonaws.com -s 5555
run_case "region or endpoint is required" 1 \
  "Must specify one and only one of --region/-r or --proxy-endpoint/-e" \
  -- -s 5555
run_case "a mode source is required" 1 \
  "Must specify one of --source-listen-port/-s or --destination-app/-d or --mode" \
  -- -r us-east-1
run_case "-s and -d are exclusive" 1 \
  "Must specify one and only one of --source-listen-port/-s or --destination-app/-d" \
  -- -r us-east-1 -s 5555 -d 127.0.0.1:22
run_case "invalid --mode is reported" 1 \
  "Mode value is wrong! Allowed values are: src, dst, source, destination" \
  -- -r us-east-1 -m bogus
run_case "-s with dst mode mismatches" 1 \
  "-s and --mode have mismatched mode. Mode is set to destination!" \
  -- -r us-east-1 -s 5555 -m dst

unset AWSIOT_TUNNEL_ACCESS_TOKEN

if [[ $FAILURES -gt 0 ]]; then
  log_error "${FAILURES} CLI test(s) FAILED (see ${LOG_FILE})"
  exit 1
fi

log_info "All CLI argument tests PASSED"
