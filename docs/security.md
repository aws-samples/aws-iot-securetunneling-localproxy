# Security Considerations

## Quick Reference

| Topic | Recommendation |
|-------|----------------|
| Access Token | Use `AWSIOT_TUNNEL_ACCESS_TOKEN` env var, not `-t` flag |
| Client Token | Use UUID, pass via `-i` flag or `AWSIOT_TUNNEL_CLIENT_TOKEN` env var |
| Privileges | Run with least privileges, use ports >1024 |
| Network | Use `-b` to bind to specific interface |
| Isolation | Consider containers, sandboxes, or chroot jail |

## Certificate Setup

A likely issue with the local proxy running on Windows or macOS systems is the lack of native OpenSSL support and default configuration. This will prevent the local proxy from being able to properly perform TLS/SSL host verification with the service. To fix this, set up a certificate authority (CA) directory and direct the local proxy to use it via the `--capath <dir>` CLI argument:

1. Create a new folder or directory to store the root certificates that the local proxy can access. For example: `D:\certs` on Windows
2. Download Amazon CA certificates for server authentication from here: https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs
3. Utilize the `c_rehash` script for Windows or `openssl rehash` command for macOS. This script is part of the OpenSSL development toolset

**macOS:**
```bash
openssl rehash ./certs
```

**Windows:**
```cmd
D:\lib\openssl>set OPENSSL=D:\lib\openssl\apps\openssl.exe

D:\lib\openssl>tools\c_rehash.pl D:\certs
Doing D:\certs
```

**Note:** c_rehash.pl script on Windows does not seem to cooperate with spaces in the path for the openssl.exe executable

After preparing this directory, point to it when running the local proxy with the `-c` option:
- **macOS:** `./localproxy -r us-east-1 -s 3389 -c ./certs`
- **Windows:** `.\localproxy.exe -r us-east-1 -s 3389 -c D:\certs`

---

## Runtime Environment

- Avoid using the **-t** argument to pass in the access token. We recommend setting the **AWSIOT_TUNNEL_ACCESS_TOKEN** environment variable to specify the client access token with the least visibility
- Run the local proxy executable with the least privileges in the OS or environment
    - If your client application normally connects to a port less than 1024, this would normally require running the local proxy with admin privileges to listen on the same port. This can be avoided if the client application allows you to override the port to connect to. Choose any available port greater than 1024 for the source local proxy to listen to without administrator access. Then you may direct the client application to connect to that port. e.g. For connecting to a source local proxy with an SSH client, the local proxy can be run with `-s 5000` and the SSH client should be run with `-p 5000`
- On devices with multiple network interfaces, use the **-b** argument to bind the TCP socket to a specific network address restricting the local proxy to only proxy connections on an intended network
- Consider running the local proxy on separate hosts, containers, sandboxes, chroot jail, or a virtualized environment

---

## Access Tokens

- After localproxy uses an access token, it will no longer be valid without an accompanying Client Token.
- You can revoke an existing token and get a new valid token by calling [RotateTunnelAccessToken](https://docs.aws.amazon.com/iot/latest/apireference/API_iot-secure-tunneling_RotateTunnelAccessToken.html).
- Refer to the [Developer Guide](https://docs.aws.amazon.com/iot/latest/developerguide/iot-secure-tunneling-troubleshooting.html) for troubleshooting connectivity issues that can be due to an invalid token.

---

## Client Tokens

### Client Token Properties

| Property | Value |
|----------|-------|
| Required | No (optional) |
| Uniqueness | Must be unique across all open tunnels per AWS account |
| Format | Regex: `^[a-zA-Z0-9-]{32,128}$` |
| Recommendation | Use UUID |
| CLI Option | `-i` argument |
| Environment Variable | `AWSIOT_TUNNEL_CLIENT_TOKEN` |

- The client token is an added security layer to protect the tunnel by ensuring that only the agent that generated the client token can use a particular access token to connect to a tunnel.
- Only one client token value may be present in the request. Supplying multiple values will cause the handshake to fail.
- The client token is optional.
- The client token must be unique across all the open tunnels per AWS account.
- It's recommended to use a UUID to generate the client token.
- The client token can be any string that matches the regex `^[a-zA-Z0-9-]{32,128}$`
- If a client token is provided, then local proxy needs to pass the same client token for subsequent retries (This is yet to be implemented in the current version of local proxy)
- If a client token is not provided, then the access token will become invalid after a successful handshake, and localproxy won't be able to reconnect using the same access token.
- The Client Token may be passed using the **-i** argument from the command line or setting the **AWSIOT_TUNNEL_CLIENT_TOKEN** environment variable.
