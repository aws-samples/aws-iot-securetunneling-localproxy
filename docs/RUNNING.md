# Running the local proxy

The response of OpenTunnel via the AWS IoT Secure Tunneling management API is
acquisition of a pair of client access tokens to use to connect two local proxy
clients to the ends of the tunnel. One token is designated for the source local
proxy, and the other is for the destination. They must be supplied with the
matching local proxy run mode argument, otherwise connecting to the service will
fail. Additionally, the region parameter supplied to the local proxy must match
the AWS region the tunnel was opened in. In a production configuration, delivery
of one or both tokens and launching the local proxy process may be automated.

The sections below describe how to run the local proxy on both ends of a tunnel.
For every available option see [CONFIGURATION.md](CONFIGURATION.md); for
multiplexing several streams over one tunnel see
[MULTIPLEXING.md](MULTIPLEXING.md).

## Runtime dependencies

A local proxy built the recommended way (`-DLINK_STATIC_OPENSSL=OFF`, see
[BUILD.md](BUILD.md#building)) loads OpenSSL, zlib and libstdc++ from the
platform at run time. **This includes the prebuilt binaries attached to the
GitHub releases and workflow runs** (`localproxy-linux-x86_64`, `-aarch64`,
`-armv7`), which are built with `-DLINK_STATIC_OPENSSL=OFF` — downloading one
does not spare you these packages.

Install these on every host that runs the binary:

```bash
# Debian/Ubuntu
sudo apt install -y libssl3 zlib1g libstdc++6

# Fedora/Amazon Linux/RHEL
sudo dnf install -y openssl-libs zlib libstdc++
```

| Dependency      | Minimum version                       |
| --------------- | ------------------------------------- |
| OpenSSL         | 1.0.1 (3.x for the released binaries) |
| zlib            | 1.2.13                                |
| glibc           | 2.35 for the released binaries        |
| libstdc++       | GCC 11 for the released binaries      |
| CA certificates | any current bundle                    |

## Terms

**V1 local proxy:** local proxy uses Sec-WebSocket-Protocol
_aws.iot.securetunneling-1.0_ when communicating with AWS IoT Tunneling Service.

**V2 local proxy:** local proxy uses Sec-WebSocket-Protocol
_aws.iot.securetunneling-2.0_ when communicating with AWS IoT Tunneling Service.

**V3 local proxy:** local proxy uses Sec-WebSocket-Protocol
_aws.iot.securetunneling-3.0_ when communicating with AWS IoT Tunneling Service.

**Source local proxy:** local proxy that runs in source mode.

**Destination local proxy:** local proxy that runs in destination mode.

---

## Destination service and destination mode local proxy

Destination local proxy is responsible for forwarding application data received
from tunnel to destination service. For V1 local proxy, only 1 stream is allowed
over the tunnel. With V2 local proxy, more than one streams can be transferred
at the same time. For more details, please read
[Multi-port tunneling feature support](MULTIPLEXING.md#multi-port-tunneling-feature-support).

Example 1:

    ./localproxy -r us-east-1 -d localhost:3389 -t <destination_client_access_token>

This is an example command to run the local proxy in destination mode, on a
tunnel created in us-east-1, and forward data packets received from the tunnel
to a locally running application/service on port 3389.

Example 2:

    ./localproxy -r us-east-1 -d HTTP1=80,SSH1=22 -t <destination_client_access_token>

This is an example command to run the local proxy in destination mode, on a
tunnel created in us-east-1, and forward:

- data packets belongs to service ID HTTP1 to a locally running
  application/service on port 80.
- data packets belongs to service ID SSH1 to a locally running
  application/service on port 22.

We recommend starting the destination application or server before starting the
destination local proxy to ensure that when the local proxy attempts to connect
to the destination port, it will succeed. When the local proxy starts in
destination mode, it will first connect to the service, and then begin listening
for a new connection request over the tunnel. Upon receiving a request, it will
attempt to connect to the configured destination address and port. If
successful, it will transmit data between the TCP connection and tunnel
bi-directionally.

For a multiplexed tunnel, one connection drop or connect will not affect the
other connections that share the same tunnel. All connections/streams in a
multiplexed tunnel is independent.

---

## Client application and source mode local proxy

Source local proxy is responsible for relaying application data to the tunnel.
For V1 local proxy, only 1 stream is allowed over the tunnel. With V2 local
proxy, more than one streams can be transferred at the same time. For more
details, please read
[Multi-port tunneling feature support](MULTIPLEXING.md#multi-port-tunneling-feature-support).

Example 1:

    ./localproxy -r us-east-1 -s 3389 -t <source_client_access_token>

This is an example command to run the local proxy in source mode, on a tunnel
created in us-east-1, waiting for a connection on port 3389.

Example 2:

    ./localproxy -r us-east-1 -s HTTP1=5555,SSH1=3333 -t <source_client_access_token>

This is an example command to run the local proxy in source mode, on a tunnel
created in us-east-1,

- waiting for a connection on port 5555, for service ID HTTP1.
- waiting for a connection on port 3333, for service ID SSH1.

When the local proxy starts in source mode, it will first connect to the
service, and then begin listening for a new connection on the specified port and
bind address. While the local proxy is running, use the client application (e.g.
RemoteDesktopClient, ssh client) to connect to the source local proxy's
listening port. After accepting the TCP connection, the local proxy will forward
the connection request over the tunnel and immediately transmit data the TCP
connection data through the tunnel bidirectionally. Source mode can manage more
than one connection/stream at a time, if V2 local proxy is used. If the
established TCP connection is terminated for any reason, it will send a
disconnect message over the tunnel so the service or server running on the other
side can react appropriately. Similarly, if a notification that a disconnect
happened on the other side is received by the source local proxy it will close
the local TCP connection. Regardless of a local I/O failures, or if a
notification of a disconnect comes from the tunnel, after the local TCP
connection closes, it will begin listening again on the specified listen port
and bind address.

- If a new connection request sent over the tunnel results in the remote
  (destination) side being unable to connect to a destination service, it will
  send a disconnect message back through the tunnel. The exact timing behavior
  of this depends on the TCP retry settings of the destination local proxy.
- For a multiplexed tunnel, one connection drop or connect will not affect the
  other connections that share the same tunnel. All connections/streams in a
  multiplexed tunnel is independent.

---

## Stopping the local proxy process

The local proxy process can be stopped using various methods:

- Sending a SIGTERM signal to the process
- Closing a tunnel explicitly via CloseTunnel API. This will result in the local
  proxy dropping the connection to the service and exiting the process
  successfully.
- A tunnel expires after its lifetime expiry. This will result in the local
  proxy dropping the connection to the service and exiting the process
  successfully.

---

## HTTP proxy support

The local proxy relies on the HTTP tunneling mechanism described by the
[HTTP/1.1 specification](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.6).
To comply with the specifications, your web proxy must allow devices to use the
CONNECT method. For more details on how that works and how to configure it
properly, please refer to
"[Configure local proxy for devices that use web proxy](https://docs.aws.amazon.com/iot/latest/developerguide/configure-local-proxy-web-proxy.html)".

---

## IPv6 support

The local proxy uses IPv4 and IPv6 dynamically based on how addresses are
specified directly by the user, or how are they resolved on the system. For
example, if 'localhost' resolves to '127.0.0.1' then IPv4 will is being used to
connect or as the listening address. If localhost resolves to '::1' then IPv6
will be used.

**Note:** Specifying any argument that normally accepts _address:port_ will not
work correctly if _address_ is specified using an IPv6 address. The one
exception is the web proxy URL (for example the `HTTPS_PROXY` environment
variable), which accepts a bracketed IPv6 literal such as `http://[::1]:8080`.

**Note:** Systems that support both IPv4 and IPv6 may cause connectivity
confusion if explicit address/port combinations are not used with the local
proxy, client application, or destination service. Each component may behave
differently with respect to support IP stack and default behaviors. Listening on
the local IPv4 interface _127.0.0.1_ will not accept connection attempts to IPv6
loopback address _::1_. To add further complexity, hostname resolution may hide
that this is happening, and different tools may prefer different IP stacks. To
help with this from the local proxy, use verbose logging on the local proxy _(-v
6 CLI argument)_ to inspect how hostname resolution is happening and examine the
address format being output.
