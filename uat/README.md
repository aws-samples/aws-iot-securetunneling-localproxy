# UAT Testing Infrastructure for AWS IoT Secure Tunneling LocalProxy

End-to-end testing suite using AWS CLI to validate localproxy binary
functionality.

## Prerequisites

- AWS CLI configured with credentials
- IAM permissions (see [Minimum IAM Permissions](#minimum-iam-permissions))
- Built localproxy binary at `../build/bin/localproxy`
- `jq` and `nc` (netcat) installed

## Minimum IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iot:OpenTunnel",
        "iot:DescribeTunnel",
        "iot:CloseTunnel",
        "iot:RotateTunnelAccessToken"
      ],
      "Resource": "arn:aws:iot:*:*:tunnel/*"
    },
    {
      "Effect": "Allow",
      "Action": "iot:ListTunnels",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["iot:OpenTunnel", "iot:CreateThing", "iot:DeleteThing"],
      "Resource": "arn:aws:iot:*:*:thing/uat-*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

## Quick Start

```bash
cd uat
chmod +x *.sh
./run_uat.sh
```

## Test Scripts

| Script                        | Description                                                                                                                                                                                               |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `run_uat.sh`                  | Main E2E test: opens tunnel, starts both proxies, verifies connection                                                                                                                                     |
| `test_cli_usage.sh`           | Tests CLI argument handling: `--help`/`-h` and `--version`/`-V` exit 0 immediately; bad invocations name the offending option and point at `--help`. Needs no AWS credentials                             |
| `test_lifecycle.sh`           | Tests AWS API operations: open, describe, list, rotate, close                                                                                                                                             |
| `test_v1_compat.sh`           | Tests V1 backward compatibility with `--destination-client-type V1`                                                                                                                                       |
| `test_multiport.sh`           | Tests multi-port tunneling with multiple service IDs                                                                                                                                                      |
| `test_ssh_connectivity.sh`    | Tests SSH through tunnel (key-based and password-based auth)                                                                                                                                              |
| `test_multiplex_integrity.sh` | Multiplexes several services over ONE tunnel, transfers a distinct random payload through each one concurrently, and verifies byte-for-byte integrity (sha256) with cross-service contamination detection |

## Configuration

| Variable      | Required | Default        | Description                               |
| ------------- | -------- | -------------- | ----------------------------------------- |
| `AWS_REGION`  | No       | us-east-1      | AWS region                                |
| `THING_NAME`  | No       | uat-test-thing | IoT thing name                            |
| `TEST_PORT`   | No       | 22             | Destination service port                  |
| `SOURCE_PORT` | No       | 5555           | Source listening port                     |
| `SSH_PASS`    | Yes      | -              | SSH password (`test_ssh_connectivity.sh`) |
| `SSH_KEY`     | No       | ~/.ssh/id_rsa  | SSH private key path                      |
| `SSH_USER`    | No       | current user   | SSH username                              |

### `test_multiplex_integrity.sh` variables

| Variable           | Required | Default             | Description                                              |
| ------------------ | -------- | ------------------- | -------------------------------------------------------- |
| `SERVICES`         | No       | `DATA1 DATA2 DATA3` | Space-separated service IDs multiplexed over one tunnel  |
| `SRC_PORT_BASE`    | No       | 6001                | First source-proxy listen port (incremented per service) |
| `DST_PORT_BASE`    | No       | 7001                | First destination service port (incremented per service) |
| `FILE_SIZE`        | No       | 131072 (128 KiB)    | Random bytes transferred per service                     |
| `TRANSFER_TIMEOUT` | No       | 60                  | Per-transfer timeout in seconds                          |

## Examples

```bash

# CLI argument handling only (no AWS credentials needed)
./test_cli_usage.sh

# With custom region and thing name
AWS_REGION=us-west-2 THING_NAME=my-device ./run_uat.sh

# Tunnel lifecycle test
./test_lifecycle.sh

# SSH connectivity with password
SSH_PASS=password ./test_ssh_connectivity.sh

# SSH connectivity with key
SSH_KEY=~/.ssh/my_key SSH_USER=ubuntu ./test_ssh_connectivity.sh

# Multiplexed tunnel + file-transfer integrity (default 3 services, 128 KiB each)
./test_multiplex_integrity.sh

# Multiplex integrity with custom services and larger payloads
SERVICES="A B C D" FILE_SIZE=20971520 ./test_multiplex_integrity.sh
```

## Logs

All logs are stored in the `uat/logs/` directory (created automatically on test
run). Each test script redirects localproxy stdout/stderr to log files with
test-specific prefixes:

| Test Script                   | Log Files                                                                            |
| ----------------------------- | ------------------------------------------------------------------------------------ |
| `run_uat.sh`                  | `source_proxy.log`, `dest_proxy.log`                                                 |
| `test_cli_usage.sh`           | `cli_usage.log`                                                                      |
| `test_v1_compat.sh`           | `v1_source.log`                                                                      |
| `test_multiport.sh`           | `multiport_source.log`, `multiport_dest.log`                                         |
| `test_multiplex_integrity.sh` | `multiplex_source.log`, `multiplex_dest.log`                                         |
| `test_ssh_connectivity.sh`    | `ssh_key_source.log`, `ssh_key_dest.log`, `ssh_pass_source.log`, `ssh_pass_dest.log` |

Logs are overwritten on each test run. Verbosity is set to `-v 5` (debug level)
by default.
