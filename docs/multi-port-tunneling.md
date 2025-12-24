# Multi-port Tunneling

## Overview

| Feature         | Description                                        |
| --------------- | -------------------------------------------------- |
| Purpose         | Multiplex multiple data streams on a single tunnel |
| Minimum Version | V2 local proxy                                     |
| Max Service IDs | 3 per tunnel (as of December 2024)                 |

## Service Identifier (Service ID)

If you need to use multi-port tunneling feature, service ID is needed to start
local proxy. A service identifier will be used as the new format to specify the
source listening port or destination service when start local proxy. The
identifier is like an alias for the source listening port or destination
service. For the format requirement of service ID, please refer to AWS public
doc
[services in DestinationConfig](https://docs.aws.amazon.com/iot/latest/apireference/API_iot-secure-tunneling_DestinationConfig.html).
There is no restriction on how this service ID should be named, as long as it
can help uniquely identifying a connection or stream.

A maximum of 3 service IDs can be configured while creating a Secure Tunnel (as
of December 2024).

### Service ID Examples

**Example 1: `SSH1`**

You can use the following format: protocol name + connection number. For
example, if two SSH connections needed to be multiplexed over a tunnel, you can
choose SSH1 and SSH2 as the service IDs.

**Example 2: `ae5957ef-d6e3-42a5-ba0c-edc667d2b3fb`**

You can use a UUID to uniquely identify a connection/stream.

**Example 3: `ip-172-31-6-23.us-west-2.compute.internal`**

You can use remote host name to uniquely identify a stream.

---

## Backward Compatibility

### Compatibility Matrix

| Source Version | Destination Version | Compatible | Conditions                                                    |
| :------------: | :-----------------: | :--------: | ------------------------------------------------------------- |
|       V3       |         V3          |     ✓      | Full feature support                                          |
|       V3       |         V2          |     ✓      | Use `--destination-client-type V2`, single stream per service |
|       V3       |         V1          |     ✓      | Use `--destination-client-type V1`, single service only       |
|       V2       |         V2          |     ✓      | Full V2 feature support                                       |
|       V2       |         V1          |     ✓      | Single service only                                           |
|       V1       |         V1          |     ✓      | Single stream only                                            |

V2 local proxy is able to communicate with V1 local proxy if only one connection
needs to be established over the tunnel. This means when you open a tunnel, no
more than one service should be passed in the **services** list.

**Example 1 (NOT backward compatible):**

```bash
aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH1,SSH2
```

In this example, two service IDs are used (SSH1 and SSH2). Backward
compatibility is NOT supported.

**Example 2 (backward compatible):**

```bash
aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH2
```

In this example, one service ID is used (SSH2). Backward compatibility is
supported.

**Example 3 (backward compatible):**

```bash
aws iotsecuretunneling open-tunnel
```

In this example, no service ID is used. Backward compatibility is supported.

V3 local proxy is able to communicate with V1 and V2 local proxy if only one
connection/stream needs to be established over the tunnel. When connecting to
older versions, you will need to pass the `destination-client-type` CLI arg if
and only if starting the localproxy in source mode. The same rules listed above
still apply when connecting over V1.

**Example when targeting a V1 destination**, like Device Client of the
Greengrass Secure Tunneling Component:

```bash
./localproxy -s 3333 --destination-client-type V1 -v 6 -r us-east-1
```

**Example when targeting a V2 destination:**

```bash
./localproxy -s 3333 --destination-client-type V2 -v 6 -r us-east-1
```

---

## Limits for Multiplexed Tunnels

### Quick Reference

| Limit                        | Value                                                                                    |        Adjustable         |
| ---------------------------- | ---------------------------------------------------------------------------------------- | :-----------------------: |
| Maximum bandwidth per tunnel | See [AWS docs](https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html) | Yes (contact AWS support) |
| Maximum services per tunnel  | 3 (as of December 2024)                                                                  | Yes (contact AWS support) |
| Load balancing               | Not supported                                                                            |            N/A            |

### Bandwidth Limits

If the tunnel multi-port feature is enabled, multiplexed tunnels have the same
bandwidth limit as non-multiplexed tunnels. This limit is mentioned in
[AWS public doc](https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html)
section **AWS IoT Secure Tunneling**, row _Maximum bandwidth per tunnel_. The
bandwidth for a multiplexed tunnel is the bandwidth consumed by all active
streams that transfer data over the tunnel connection. If you need this limit
increased, please reach out to AWS support and ask for a limit increase.

### Service ID Limits

There are limits on the maximum streams that can be multiplexed on a tunnel
connection. This limit is mentioned in
[AWS public doc](https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html)
section **AWS IoT Secure Tunneling**, row _Maximum services per tunnel_. As of
December 2024, this limit is set to 3 Service IDs per tunnel. If you need this
limit increased, please reach out to AWS support and ask for a limit increase.

### Load Balancing in Multiplexed Streams

If more than one stream is transferred at the same time, local proxy will not
load balance between these streams. If you have one stream that is dominating
the bandwidth, the other streams sharing the same tunnel connection may see
latency of data packet delivery.
