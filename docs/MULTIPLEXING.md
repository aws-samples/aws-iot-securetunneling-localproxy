# Multi-port tunneling and service IDs

Multi-port tunneling lets more than one data stream share a single tunnel, each
identified by a **service ID**. The feature requires a V2 or V3 local proxy on
both ends; see [COMPATIBILITY.md](COMPATIBILITY.md) for what happens when one
end is older.

---

## Multi-port tunneling feature support

Multi-port tunneling feature allows more than one data stream multiplexed on
same tunnel. This feature is only supported with V2 (and V3) local proxy. If you
have a device at one end of the tunnel using V1 local proxy, and the device at
the other end using V2 local proxy, i.e. when V2 local proxy talks to V1 local
proxy, the backward compatibility is maintained. For more details, please refer
to [backward compatibility](COMPATIBILITY.md#backward-compatibility) and
[devices supporting V1 protocol](COMPATIBILITY.md#distributions-that-only-support-the-v1-protocol).

Note that eventhough backward compatibility is maintained here, this connection
is only viable **given you are trying to establish only a single stream over
single service connection over the tunnel.**

---

## Service identifier (Service ID)

If you need to use multi-port tunneling feature, service ID is needed to start
local proxy. A service identifier will be used as the new format to specify the
source listening port or destination service when start local proxy. The
identifier is like an alias for the source listening port or destination
service. For the format requirement of service ID, please refer to AWS public
doc
[services in DestinationConfig](https://docs.aws.amazon.com/iot/latest/apireference/API_iot-secure-tunneling_DestinationConfig.html).
There is no restriction on how this service ID should be named, as long as it
can help uniquely identifying a connection or stream. A maximum of 3 service IDs
can be configured while creating a Secure Tunnel (as of December 2024).

Example 1: _SSH1_

You can use the following format: protocol name + connection number. For
example, if two SSH connections needed to be multiplexed over a tunnel, you can
choose SSH1 and SSH2 as the service IDs.

Example 2: _ae5957ef-d6e3-42a5-ba0c-edc667d2b3fb_

You can use a UUID to uniquely identify a connection/stream.

Example 3: _ip-172-31-6-23.us-west-2.compute.internal_

You can use remote host name to uniquely identify a stream.

Service IDs are passed to the local proxy through `-s`/`-d`
([CLI arguments](CONFIGURATION.md#options-set-via-command-line-arguments)) or
fixed in configuration files
([`--config-dir`](CONFIGURATION.md#options-set-via---config-dir)).

---

## Limits for multiplexed tunnels

### Bandwidth limits

If the tunnel multi-port feature is enabled, multiplexed tunnels have the same
bandwidth limit as non-multiplexed tunnels. This limit is mentioned in
[AWS public doc](https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html)
section **AWS IoT Secure Tunneling**, row _Maximum bandwidth per tunnel_. The
bandwidth for a multiplexed tunnel is the bandwidth consumed by all active
streams that transfer data over the tunnel connection. If you need this limit
increased, please reach out to AWS support and ask for a limit increase.

### Service ID limits

There are limits on the maximum streams that can be multiplexed on a tunnel
connection. This limit is mentioned in
[AWS public doc](https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html)
section **AWS IoT Secure Tunneling**, row _Maximum services per tunnel_. As of
December 2024, this limit is set to 3 Service IDs per tunnel. If you need this
limit increased, please reach out to AWS support and ask for a limit increase.

### Load balancing in multiplexed streams

If more than one stream is transferred at the same time, local proxy will not
load balance between these streams. If you have one stream that is dominating
the bandwidth, the other streams sharing the same tunnel connection may see
latency of data packet delivery.
