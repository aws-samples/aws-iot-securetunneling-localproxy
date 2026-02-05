#!/bin/bash
# Common functions for UAT test scripts
# shellcheck shell=bash

# Create logs directory
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "$LOG_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

wait_for_log() {
  local log_file="$1" pattern="$2" timeout="${3:-30}" elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    grep -q "$pattern" "$log_file" 2>/dev/null && return 0
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

check_command() {
  command -v "$1" >/dev/null || {
    log_error "$1 not found"
    exit 1
  }
}

check_localproxy() {
  local path="$1"
  [[ -x "$path" ]] || {
    log_error "localproxy binary not found at $path"
    exit 1
  }
}

check_aws_credentials() {
  aws sts get-caller-identity >/dev/null || {
    log_error "AWS credentials not configured"
    exit 1
  }
}
