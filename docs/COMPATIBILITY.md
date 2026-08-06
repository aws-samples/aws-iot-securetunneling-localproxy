# Protocol versions and backward compatibility

The local proxy speaks one of three WebSocket subprotocols (V1, V2 or V3 — see
[Terms](RUNNING.md#terms)). Which one the peer at the other end of the tunnel
speaks determines whether you need to pass `--destination-client-type`, and
which features are available.

The wire protocols themselves are documented in
[V1WebSocketProtocolGuide.md](../V1WebSocketProtocolGuide.md),
[V2WebSocketProtocolGuide.md](../V2WebSocketProtocolGuide.md) and
[V3WebSocketProtocolGuide.md](../V3WebSocketProtocolGuide.md).

---

## Distributions that only support the V1 protocol

As of December 2024, the following software distributions only support the V1
protocol:

- AWS IoT Device Client
- AWS IoT Secure Tunneling Component OR Greengrass V2 Secure Tunneling Component
- Browser-based Secure Tunneling from the AWS Console
- Any Secure Tunneling demo code written before 2022
- 1.x versions of the localproxy

**Hence a device using any of the above mentioned variations as one end of the
secure tunnel is actually using the V1 protocol for connection to the tunnel.**

As of the 3.1.2 May 2024 update, `--destination-client-type V1` is a
**required** parameter when connecting to any of them.

---

## Backward compatibility

V2 local proxy is able to communicate with V1 local proxy if only one connection
needs to be established over the tunnel. This means when you open a tunnel, no
more than one service should be passed in the **services** list.

Example 1:

     aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH1,SSH2

In this example, two service IDs are used (SSH1 and SSH2). Backward
compatibility is NOT supported.

Example 2:

    aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH2

In this example, one service ID is used (SSH2). Backward compatibility is
supported.

Example 3:

    aws iotsecuretunneling open-tunnel

In this example, no service ID is used. Backward compatibility is supported.

V3 local proxy is able to communicate with V1 and V2 local proxy if only one
connection/stream needs to be established over the tunnel. When connecting to
older versions, you will need to pass the `destination-client-type` CLI arg if
and only if starting the localproxy in source mode. The same rules listed above
still apply when connecting over V1.

Example when targeting a V1 destination, like Device Client of the Greengrass
Secure Tunneling Component:

    ./localproxy -s 3333 --destination-client-type V1 -v 6 -r us-east-1

Example when targeting a V2 destination:

    ./localproxy -s 3333 --destination-client-type V2 -v 6 -r us-east-1

---

## Feature availability by version

### Multi-port tunneling

Requires V2 or V3 on both ends. A V2 proxy talking to a V1 one stays compatible,
but only for a single stream over a single service connection. See
[MULTIPLEXING.md](MULTIPLEXING.md#multi-port-tunneling-feature-support) for the
full rule and how to configure it.

### Simultaneous TCP connections

Simultaneous TCP is a feature that allows application layer (e.g. HTTP)
protocols to open multiple TCP connections over a single stream. This feature is
only supported with V3 local proxy. If you have some device using V1/V2 local
proxy, and the other end device using V3 local proxy, i.e. when V3 local proxy
talks to V1/V2 local proxy, the backward compatibility is maintained as long as
users specify `V1` or `V2` as the value for `destination-client-type`.

Note that eventhough backward compatibility is maintained here, this connection
is only viable **given you are trying to establish only a single stream over
single service connection over the tunnel in case of V3 talking to V1 protocol
OR you are trying to establish multiple services connections (each with single
stream only) in case of V3 talking to V2 protocol.**
