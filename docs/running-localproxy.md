# Running the Local Proxy

The response of OpenTunnel via the AWS IoT Secure Tunneling management API is
acquisition of a pair of client access tokens to use to connect two local proxy
clients to the ends of the tunnel. One token is designated for the source local
proxy, and the other is for the destination. They must be supplied with the
matching local proxy run mode argument, otherwise connecting to the service will
fail. Additionally, the region parameter supplied to the local proxy must match
the AWS region the tunnel was opened in. In a production configuration, delivery
of one or both tokens and launching the local proxy process may be automated.
The following sections describe how to run the local proxy on both ends of a
tunnel.

---

## Terms

| Term                        | Description                                                                                                             |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **V1 local proxy**          | Local proxy uses Sec-WebSocket-Protocol `aws.iot.securetunneling-1.0` when communicating with AWS IoT Tunneling Service |
| **V2 local proxy**          | Local proxy uses Sec-WebSocket-Protocol `aws.iot.securetunneling-2.0` when communicating with AWS IoT Tunneling Service |
| **V3 local proxy**          | Local proxy uses Sec-WebSocket-Protocol `aws.iot.securetunneling-3.0` when communicating with AWS IoT Tunneling Service |
| **Source local proxy**      | Local proxy that runs in source mode                                                                                    |
| **Destination local proxy** | Local proxy that runs in destination mode                                                                               |

---

## Protocol Version Feature Matrix

| Feature                      | V1  | V2  | V3  |
| ---------------------------- | :-: | :-: | :-: |
| Single stream                |  ✓  |  ✓  |  ✓  |
| Multi-port tunneling         |  ✗  |  ✓  |  ✓  |
| Simultaneous TCP connections |  ✗  |  ✗  |  ✓  |

---

## V1 Protocol Support

As of December 2024, the following software distributions only support the V1
protocol:

- AWS IoT Device Client
- AWS IoT Secure Tunneling Component OR Greengrass V2 Secure Tunneling Component
- Browser-based Secure Tunneling from the AWS Console
- Any Secure Tunneling demo code written before 2022
- 1.x versions of the localproxy

**Hence a device using any of the above mentioned variations as one end of the
secure tunnel is actually using the V1 protocol for connection to the tunnel.**

---

## Multi-port Tunneling Feature Support

Multi-port tunneling feature allows more than one data stream multiplexed on
same tunnel. This feature is only supported with V2 (and V3) local proxy. If you
have a device at one end of the tunnel using V1 local proxy, and the device at
the other end using V2 local proxy, i.e. when V2 local proxy talks to V1 local
proxy, the backward compatibility is maintained. For more details, please refer
to section
[backward compatibility](multi-port-tunneling.md#backward-compatibility) and
[devices supporting V1 protocol](#v1-protocol-support).

Note that even though backward compatibility is maintained here, this connection
is only viable **given you are trying to establish only a single stream over
single service connection over the tunnel.**

---

## Simultaneous TCP Connections Feature Support

Simultaneous TCP is a feature that allows application layer (e.g. HTTP)
protocols to open multiple TCP connections over a single stream. This feature is
only supported with V3 local proxy. If you have some device using V1/V2 local
proxy, and the other end device using V3 local proxy, i.e. when V3 local proxy
talks to V1/V2 local proxy, the backward compatibility is maintained as long as
users specify `V1` or `V2` as the value for `destination-client-type`. For more
details, please refer to section
[backward compatibility](multi-port-tunneling.md#backward-compatibility) and
[devices supporting V1 protocol](#v1-protocol-support).

Note that even though backward compatibility is maintained here, this connection
is only viable **given you are trying to establish only a single stream over
single service connection over the tunnel in case of V3 talking to V1 protocol
OR you are trying to establish multiple services connections (each with single
stream only) in case of V3 talking to V2 protocol.**

---

## Destination Service and Destination Mode Local Proxy

Destination local proxy is responsible for forwarding application data received
from tunnel to destination service. For V1 local proxy, only 1 stream is allowed
over the tunnel. With V2 local proxy, more than one streams can be transferred
at the same time. For more details, please read section
[Multi-port tunneling feature support](#multi-port-tunneling-feature-support).

**Example 1:**

```bash
./localproxy -r us-east-1 -d localhost:3389 -t <destination_client_access_token>
```

This is an example command to run the local proxy in destination mode, on a
tunnel created in us-east-1, and forward data packets received from the tunnel
to a locally running application/service on port 3389.

**Example 2:**

```bash
./localproxy -r us-east-1 -d HTTP1=80,SSH1=22 -t <destination_client_access_token>
```

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

## Client Application and Source Mode Local Proxy

Source local proxy is responsible for relaying application data to the tunnel.
For V1 local proxy, only 1 stream is allowed over the tunnel. With V2 local
proxy, more than one streams can be transferred at the same time. For more
details, please read section
[Multi-port tunneling feature support](#multi-port-tunneling-feature-support).

**Example 1:**

```bash
./localproxy -r us-east-1 -s 3389 -t <source_client_access_token>
```

This is an example command to run the local proxy in source mode, on a tunnel
created in us-east-1, waiting for a connection on port 3389.

**Example 2:**

```bash
./localproxy -r us-east-1 -s HTTP1=5555,SSH1=3333 -t <source_client_access_token>
```

This is an example command to run the local proxy in source mode, on a tunnel
created in us-east-1:

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

## Stopping the Local Proxy Process

The local proxy process can be stopped using various methods:

| Method                 | Result                                  |
| ---------------------- | --------------------------------------- |
| Send SIGTERM signal    | Process terminates gracefully           |
| CloseTunnel API        | Drops connection and exits successfully |
| Tunnel lifetime expiry | Drops connection and exits successfully |

- Sending a SIGTERM signal to the process
- Closing a tunnel explicitly via CloseTunnel API. This will result in the local
  proxy dropping the connection to the service and existing the process
  successfully.
- A tunnel expires after its lifetime expiry. This will result in the local
  proxy dropping the connection to the service and exiting the process
  successfully.

---

## HTTP Proxy Support

The local proxy relies on the HTTP tunneling mechanism described by the
[HTTP/1.1 specification](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.6).
To comply with the specifications, your web proxy must allow devices to use the
CONNECT method. For more details on how that works and how configure it
properly, please refer to
"[Configure local proxy for devices that use web proxy](https://docs.aws.amazon.com/iot/latest/developerguide/configure-local-proxy-web-proxy.html)"

---

## IPv6 Support

The local proxy uses IPv4 and IPv6 dynamically based on how addresses are
specified directly by the user, or how are they resolved on the system. For
example, if 'localhost' resolves to '127.0.0.1' then IPv4 will is being used to
connect or as the listening address. If localhost resolves to '::1' then IPv6
will be used.

**Note:** Specifying any argument that normally accepts _address:port_ will not
work correctly if _address_ is specified using an IPv6 address.

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
