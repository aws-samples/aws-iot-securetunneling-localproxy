# UAT Testing Infrastructure for AWS IoT Secure Tunneling LocalProxy

End-to-end testing suite using AWS CLI to validate localproxy binary functionality.

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
            "Action": [
                "iot:OpenTunnel",
                "iot:CreateThing",
                "iot:DeleteThing"
            ],
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

## Exit Codes

All scripts return:
- `0` - All tests passed
- `1` - One or more tests failed or prerequisites not met

## Quick Start

```bash
cd uat
chmod +x *.sh
./run_uat.sh
```

## Test Scripts

| Script | Description |
|--------|-------------|
| `run_uat.sh` | Main E2E test: opens tunnel, starts both proxies, verifies connection |
| `test_lifecycle.sh` | Tests AWS API operations: open, describe, list, rotate, close |
| `test_v1_compat.sh` | Tests V1 backward compatibility with `--destination-client-type V1` |
| `test_multiport.sh` | Tests multi-port tunneling with multiple service IDs |

## Configuration

Environment variables:
- `AWS_REGION` - AWS region (default: us-east-1)
- `THING_NAME` - IoT thing name (default: uat-test-thing)
- `TEST_PORT` - Destination service port (default: 22)
- `SOURCE_PORT` - Source listening port (default: 5555)

## Example

```bash
AWS_REGION=us-west-2 THING_NAME=my-device ./run_uat.sh
```

## Logs

Test logs are written to:
- `source_proxy.log` - Source proxy output
- `dest_proxy.log` - Destination proxy output
