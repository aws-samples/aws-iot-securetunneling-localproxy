The reference implementation of the local proxy provides features that may require OS facilities not available on all device runtime environments in the industry. This guide provides details about the communication that occurs between the service and client to enable integration without or beyond the local proxy reference implementation choices. This protocol guide is only applicable for v2 local proxy. 

## Core implementation requirements

In order to properly connect with and interpret messages from the AWS IoT Secure Tunneling service, the bare minimum is required:

**Communications Protocols:**
* Websocket protocol ([RFC6455](https://tools.ietf.org/html/rfc6455)) over TCP/IP
* TLS 1.1+ 

**Data processing**
* ProtocolBuffers library
    * Message size requirements are dependent on tunnel peer message sizes

## Protocol Design

The AWS IoT Secure Tunneling's usage of WebSocket is in part a subprotocol as defined by [RFC6455](https://tools.ietf.org/html/rfc6455), and there are additional restrictions when communicating with the service called out in this document. The data messages on top of WebSocket use [ProtocolBuffers](https://developers.google.com/protocol-buffers/) with a 2-byte length prefix. The messages themselves carry data and communicate tunnel connectivity information to enable tunnel clients to leverage full duplex communication. The protocol is designed to adapt TCP socket operations over a tunnel, but it is not limited to being used only for TCP based client or server applications. It is possible to implement the protocol directly and provide a network library or API to use directly in a napplication rather than a standalone process. This guide is intended to assist in those interested in directly interfacing with the WebSocket layer of AWS IoT Secure Tunneling. This document is not a programming guide so it is expected that you are familiar with the following:

-   AWS IoT Secure Tunneling service and its major concepts. Particularly the local proxy
-   HTTP and WebSocket and how to use it in your preferred language and API (connect, send, and receive data)
-   ProtocolBuffers and how to use it in your preferred language (generate code, parse messages, create messages)
-   Conceptual familiarity with TCP sockets, and ideally API familiarity in your preferred language

## Connecting to the proxy server and tunnel: WebSocket handshake

The handshake performed to connect to a AWS IoT Secure Tunneling server is a standard WebSocket protocol handshake with additional requirements on the HTTP request. These requirements ensure proper access to a tunnel given a client access token:

- The tunneling service only accepts connections secured with TLS 1.1 or higher
- The HTTP path of the upgrade request must be `/tunnel`. Requests made to any other path will result in a 400 HTTP response
- There must be a URL parameter `local-proxy-mode` specifying the tunnel connection (local proxy) mode. The value of this parameter must be `source` or `destination`
- There must be an access token specified in the request either via cookie, or an HTTP request header
    - Set the access token via HTTP request header named 'access-token' or via cookie named 'awsiot-tunnel-token'
    - Only one token value may be present in the request. Supplying multiple values for either the access-token header or the cookie, or both combined will cause the handshake to fail.
    - Local proxy mode must match the mode of the access token or the handshake will fail.
- The HTTP request size must not exceed 4k bytes in length. Requests larger than this will be rejected
- The 'Sec-WebSocket-Protocol' header must contain at least one valid protocol string based on what is supported by the service
    - Valid value: 'aws.iot.securetunneling-3.0'
- The AWS IoT Secure Tunneling server accepts a `client-token` header for specifying the client token.
  - The client token is an added security layer to protect the tunnel by ensuring that only the agent that generated the client token can use a particular access token to connect to a tunnel.
  - Only one client token value may be present in the request. Supplying multiple values will cause the handshake to fail.
  - The client token is optional.
  - The client token must be unique across all the open tunnels per AWS account
  - It's recommended to use a UUIDv4 to generate the client token.
  - The client token can be any string that matches the regex `^[a-zA-Z0-9-]{32,128}$`
  - If a client token is provided, then local proxy needs to pass the same client token for subsequent retries
  - If a client token is not provided, then the access token will become invalid after a successful handshake, and localproxy won't be able to reconnect using the same access token.

An example URI of where to connect is as follows:

`wss://data.tunneling.iot.us-east-1.amazonaws.com:443`

The regional endpoint selected must match the region where the OpenTunnel call was made to acquire the client access tokens.

An example WebSocket handshake request coming from a local proxy:

```
GET /tunnel?local-proxy-mode=source HTTP/1.1
Host: data.tunneling.iot.us-east-1.amazonaws.com
Upgrade: websocket
Connection: upgrade
Sec-WebSocket-Key: 9/h0zvwMEXrg06G+RjnmcA==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: aws.iot.securetunneling-3.0
access-token: AQGAAXiVzSmRL1VaJ22G7eRb\_CrPABsAAgABQQAMOTAwNTgyMDkxNTM4AAFUAANDQVQAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtZWFzdC0xOjcwMTU0NTg5ODcwNzprZXkvMmU4ZTAxMDEtYzE3YS00NjU1LTlhYWQtNjA2N2I2NGVhZWQyALgBAgEAeAJ2EsT4f5oCWm65Y8zRx\_nNaCjcG4FIeNV\_zMyhoOslAVAr521wChjzvogy-2-mxyoAAAB-MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwfBUUjMYI9gDEp0xwCARCAO1VX0NAiSjfU-Ar9PWYaNI5j9v77CxLcucht3tWZd57-Zq3aRQZBM4SQiy-D0Cgv31IfZ8pgWu8asm5FAgAAAAAMAAAQAAAAAAAAAAAAAAAAACniTwIAksExcMygMJ2uHs3\_\_\_\_\_AAAAAQAAAAAAAAAAAAAAAQAAAC9e5K3Isg5gHqO9LYX0geH4hrfthPEUhdrl9ZLksPxcVrk6XC4VugzrmUvEUPuR00J3etgVQZH\_RfxWrVt7Jmg=
client-token: 2da438cf-9a30-4148-b236-c338182f243c
User-Agent: localproxy Mac OS 64-bit/boost-1.68.0/openssl-3.0.0/protobuf-3.17.3
```

An example of a handshake request coming from a browser's WebSocket client may specify the following:

```
GET /tunnel?local-proxy-mode=source HTTP/1.1
Host: data.tunneling.iot.us-east-1.amazonaws.com
Upgrade: websocket
Connection: upgrade
Sec-WebSocket-Key: 9/h0zvwMEXrg06G+RjnmcA==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: aws.iot.securetunneling-3.0
Cookie: awsiot-tunnel-token=AQGAAXiVzSmRL1VaJ22G7eRb\_CrPABsAAgABQQAMOTAwNTgyMDkxNTM4AAFUAANDQVQAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtZWFzdC0xOjcwMTU0NTg5ODcwNzprZXkvMmU4ZTAxMDEtYzE3YS00NjU1LTlhYWQtNjA2N2I2NGVhZWQyALgBAgEAeAJ2EsT4f5oCWm65Y8zRx\_nNaCjcG4FIeNV\_zMyhoOslAVAr521wChjzvogy-2-mxyoAAAB-MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwfBUUjMYI9gDEp0xwCARCAO1VX0NAiSjfU-Ar9PWYaNI5j9v77CxLcucht3tWZd57-Zq3aRQZBM4SQiy-D0Cgv31IfZ8pgWu8asm5FAgAAAAAMAAAQAAAAAAAAAAAAAAAAACniTwIAksExcMygMJ2uHs3\_\_\_\_\_AAAAAQAAAAAAAAAAAAAAAQAAAC9e5K3Isg5gHqO9LYX0geH4hrfthPEUhdrl9ZLksPxcVrk6XC4VugzrmUvEUPuR00J3etgVQZH\_RfxWrVt7Jmg=
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0
```

On success, an example of a successful handshake response is:

```
HTTP/1.1 101 Switching Protocols
Date: Thu, 16 May 2019 20:56:03 GMT
Content-Length: 0
Connection: upgrade
channel-id: 0ea2b3fffe6adc0e-0000125a-00005adb-c2f218c35b921565-17c807e1
upgrade: websocket 
sec-websocket-accept: akN+XFrGEeDLcMVNKV9HkQCOLaE=
sec-websocket-protocol: aws.iot.securetunneling-3.0
```

The aspects of the response to consider above a standard successful WebSocket handshake response are:

-   The `channel-id` response header is a unique identifier for the WebSocket session with the service. It may be useful when troubleshooting any suspected issues through AWS Support
-   The 'sec-websocket-protocol' response header will contain one of the values specified in the request. That the proxy  Clients must understand and properly implement the subprotocol returned in this response header to ensure valid communication over the tunnel.

After a successful WebSocket handshake with the tunneling service, full duplex communication is possible over WebSocket. Tunnel communication messages are delivered reliably and in order.

### Handshake error responses

* If the handshake HTTP response code is within the 500-599 range, the client should retry using an exponential backoff retry strategy.
* If the handshake HTTP response code is within the 400-499 range, the service is rejecting the clients request, or access to the tunnel is not possible or denied. Do not retry unless the problem is understood and the request changes (i.e. use another region endpoint or different client access token)
* Many handshake error responses will contain the `channel-id` header which may be helpful for AWS Support troubleshooting

## WebSocket Subprotocol: aws.iot.securetunneling-3.0

While connected to the service with this protocol selected, the following restrictions apply or capabilities must be supported by clients. Violations may result in the server closing the connection abnormally, or your WebSocket client interface behaving improperly and crashing:

-   WebSocket frames will not have a payload exceeding 131076 bytes from the service
-   The server will not accept WebSocket frames with a payload over 131076 bytes
-   WebSocket frames of up to 131076 bytes may be sent to clients
    -   The peer tunnel clients do not dictate WebSocket frame sizes. The service may aggregate data and construct frames of different sizes than sent from the tunnel peer 
-   The service will respond to WebSocket ping frames with a pong reply containing a copy of the ping frame payload
    -   The local proxy reference implementation uses this to measure server response latency
    -   Clients may need to send ping frames to keep the connection alive
    -   It is not an error for the proxy server to not respond to a ping frame
-   Pong frames sent to the service will not illicit a response
-   Ping/pong frames received by the service are included in bandwidth consumption for traffic rate limiting
-   The server will not normally initiate ping requests to clients, but clients should send a pong reply
-   The proxy server will not send text WebSocket frames. This protocol operates entirely with binary messages. If any text frames are received, clients SHOULD close the WebSocket connection
-   All non-control WebSocket frames sent to the service must be binary

### Protocol behavior model: Tunneling data streams

The core activity during tunneling is sending ProtocolBuffers messages back and forth carrying either data, or messages that manage the connection state (called _control messages_) over the WebSocket connection to the service. This WebSocket connection to the service is synonymous with being connected to the tunnel. The process to support an application data transfer successfully over the tunnel can be divided into three steps. 

####  Step 1: Establish tunnel connection and perform validations 
Local proxy will initiate a web socket handshake to connect to the tunnel, using Sec-WebSocket-Protocol _aws.iot.securetunneling-3.0_. The Secure Tunneling service will acknowledge this request after authentication and validation. At this point, we can say the tunnel connection is established. After this, the Secure Tunneling service will send back control message _SERVICE_IDS_, containing a list of service IDs used in OpenTunnel API call, specified by **services** in [DestinationConfig](https://docs.aws.amazon.com/iot/latest/apireference/API_iot-secure-tunneling_DestinationConfig.html). These service IDs will be used as the source of truth of what service IDs are allowed to start local proxy. Upon receving these service IDs, local proxy will validate the service IDs provided through either configuration files or command line arguements. A validation failure on service IDs will cause local proxy fails to start. Below are two possible cases:
1. Service IDs received from the AWS IoT Secure Tunneling server does not match service IDs used to start local proxy. 
    For example, in OpenTunnel API call, service IDs SSH1, SSH2 are provided. When local proxy starts, it specifies the service IDs as SSH3, through _-s_ or _-d_ parameter. In this case, since SSH3 does not match SSH1 and SSH2, local proxy will fail to start. Even though there is no enforcement on the naming convetion of service ID, the value of service IDs and number of service IDs have to match between OpenTunnel call and local proxy.  
2. Local proxy cannot find the port mapping for all the service IDs. 
    This is more likely to happen in the destination local proxy with invalid configuration files. For example, in OpenTunnel API call, service ID SSH1, SSH2 are provided. However, no port mapping is configured for service ID SSH1, neither through configuration files nor _-d_ parameter. Failing to find a port mapping for SSH1 will cause local proxy fails to start, as local proxy does not know where to route the traffic to. For source local proxy, this is unlikely to happen. When source local proxy fails to find port mapping for certain service ID, it will automatically pick up available port to use when it starts. 

####  Step 2: Start a stream 
Once started successfully, source local proxy will listen for incoming connections on the configured ports. Destination local proxy, on the other hand, will wait for control message  _StreamStart_. When client application connecting to a configured listening port, source local proxy will accept the TCP connection and sends a _StreamStart_ message with `connection_id = 1` to destination local proxy, for this specific service ID. When preparing to send _StreamStart_ message, source local proxy will also store service ID -> stream ID mapping for book keeping. 
If multiple ports are used to start local proxy, each stream will send its own  _StreamStart_ message when the TCP connection on the configured port is accepted. A  _StreamStart_ message contains _streamID_, _serviceID_, and _connectionID_. _serviceID_ helps uniquely identify a service transferred over a tunnel . _streamID_ helps to reset a stream and identify stale data. _connectionID_ is uniquely mapped to each `boost::tcp_connection` object within a _serviceID_.

#### Every serviceID is tied to its own streamID
In summary, every _serviceID_ has a one-to-one mapping with an active _streamID_, as this example describes below.

1. The user opens a tunnel and defines SSH1 and SSH2 service id's.
2. They then start running localproxy.
3. Upon startup, the source localproxy sends two stream start messages for SSH1 and SSH2, with _streamID_ 1 for both.
4. After sending the stream start messages, the mapping looks like:  _serviceID_ SSH1 -> active _streamID_ 1 and _serviceID_SSH2 -> active _streamID_ 1.
5. The client applications start sending data for both service ids.
6. Eventually the ssh client for _serviceID_ SSH2 sends a signal that triggers the delivery of a stream_reset message.
7. This will mark _streamID_ 1 for _serviceID_ SSH2 as inactive and the source localproxy will send another stream_start message with _streamID_ 2 as part of the reset process.
8. After this the new mapping will be:  _serviceID_ SSH1 -> active _streamID_ 1 and  _serviceID_ SSH2 -> active _streamID_ 2.
9. Every data message received for SSH2 that has a _streamID_ of 1 thereafter will be ignored.

####  Step 3: End to end data transfer over the tunnel 

On receiving a StreamStart, the destination local proxy will update the service ID --> Stream ID mapping, add a new connection ID --> tcp_connection mapping, and connect to the configured destination service for a service ID.  The destination local proxy does not send a reply to the source local proxy on successful connection. Immediately after the source local proxy sends StreamStart and immediately after the destination establishes a valid TCP connection, each side respectively can begin to send and receive incoming messages on the active data stream. When the data stream is closed or disrupted (for the local proxy, this is a TCP close or I/O error on the TCP socket), a ConnectionReset control message with the currently stored stream ID, service ID, and connection ID should be sent through the tunnel so the tunnel peer can react appropriately and end the data stream. Control messages associated with a stream should be processed with the same stream ID filter.
Protocol V3 now supports the dynamic creation of more than one TCP connection at a time. The first TCP SYN packet sent by the client will initiate creation of the stream with a StreamStart message. Any subsequent TCP SYN packets sent while the stream is alive will build a new TCP connection a forward the signal to the destination with a ConnectionStart message.

Here are some important things to know for a high-level understanding of tunneling data stream handling:

- The service may use the Service ID to decide how to route traffic between connected tunnel clients. 
  - For example,  when local proxy received a data packet with Service ID  SSH1, it will look up the configuration for SSH1 and see which port this service ID is mapped to. If SSH1 is mapped to port 22 on local host, then this data packet will be forward to port 22 on local host.
- A stream start message may include one of the service ID's defined as part of the tunnel, or no service ID. It may not, however, include any other service ID not defined during tunnel creation.
- If a stream is started without a service ID and then a subsequent message is sent with a service ID, the secure tunnel service closes the socket.
  - As a best practice, the destination client should close all active streams attached to a service ID
  - If the destination is operating in V1 mode and a new stream start message arrives with a service ID, the destination client should close the V1 stream and start a new active stream with that service ID.
- Any subsequent data messages must include a service ID associated with an active or previously active stream (a stream start message for the specific service ID must be sent first). Otherwise, the service will disconnect the client from the tunnel.
- The local proxy uses the service ID -> stream ID mapping to check the current active stream ID for a specific service ID. 
- The stream ID validation for a certain stream(service ID) will only be performed on message type _StreamReset_ and _Data_. If a received message failed the stream ID validation, this message is considered to be stale and will be discarded by local proxy. 
- The local proxy, and library clients may use stream ID to determine how to respond to or filter incoming messages
  - For example: if a source sends a _StreamStart_ with a stream ID of 345 in response to a newly accepted TCP connection, and afterwards receives a _Data_ message marked with stream ID of 565, that data should be ignored. It's origin is tied to a prior connection over the tunnel from the perspective of the tunnel peer that originated it
  - Another example: if a source local proxy sends a _StreamStart_ with a stream ID of 345 in response to a newly accepted TCP connection, and afterwards receives a _StreamReset_ message marked with stream ID of 565, that message should be ignored. Only a _StreamReset_ with a stream ID of 345 should cause the client to close its local connection
- The local proxy, and library clients may use connection ID to determine how to respond to or filter incoming messages in a similar manner to that of stream id.
- Ending a TCP Connection (normally or abnormally) is accomplished by either side sending a _ConnectionReset_ with the service ID, stream ID and connection ID that is meant to be closed.
- Local TCP socket errors are communicated by sending _StreamReset_ over the tunnel using the active stream ID associated with a service ID if one exists.
- If there is a network issue with the WebSocket connection, no control message is necessary to send. However, all active streams should be considered invalid and closed. The localproxy will then reconnect to the tunnel via the service and start a new stream.
- StreamReset will immediately close all connections associated with the service.

### Reconnecting to the secure tunnel

When the websocket is active, the local proxy will periodically send ping-pong message frames to keep the connection alive. The latency to the proxy server is also calculated during this time.
In the event of a network outage or connection timeout, the local proxy will keep running, close the active stream, and execute a retry loop to reestablish the websocket connection.
By default, the retry interval is 2.5 seconds, and there is no limit to the maximum number of retries. These defaults are configurable in the ProxySettings source file constant declarations.

### Recovering from a crash or unintended program exit

If the local proxy unexpectedly terminates, the tunnel peer will close its tcp sockets and upon reconnection, invalidate and reset all active streams.
If the user wants to restart the client and reconnect to the tunnel, certain actions may be needed:
- If the local proxy terminated on the source side, the user is free to restart the local proxy with the same version and config.
    - If the user wants to reconnect with an older version of the local proxy, they may need to restart the destination local proxy with a matching configuration. For example if using v1, remove any _serviceID_ -> port mappings.
- If the local proxy terminated on the destination side, the user needs to restart both the source and destination local proxies.
    - The is because currently the tunnel peers have no knowledge if the other side has disconnected, and the source side will resend a stream start message as a result. While passing state information is technically possible through the payload of data messages, we do not support that at the moment.

### Tunneling message frames

WebSocket binary frames contain a sequence of tunnel frames or messages. Each data message has a **2-byte unsigned short, big endian** data length prefix, followed by sequence of bytes whose length is specified by the data length. These bytes must be parsed into a ProtocolBuffers object that uses the schema shown in this document. Every message received must be processed, and should be processed in order for data stream integrity. If the order of messages is lost or cannot be understood during processing by the client, it should end the data stream with a _StreamReset_. Messages may control the state of the data stream, or it may contain actual stream data. Inspecting the message's type is the first step in processing a message. A single data length + bytes parsed into a ProtocolBuffers message represents an entire tunneling message frame, and the beginning of the next frame's length prefix follows immediately. This is a visual diagram of a single frame:

    |-----------------------------------------------------------------|
    | 2-byte data length   |     N byte ProtocolBuffers message       |
    |-----------------------------------------------------------------|

Tunneling message frames are very loosely coupled with WebSocket frames. It is not required that a WebSocket frame contain an entire tunneling message frame. The start and end of a WebSocket frame does not have to be aligned with a tunneling frame and vice versa. A WebSocket frame may contain multiple tunneling frames, or it may contain only a slice of a tunneling frame started in a previous WebSocket frame and will finish in a later WebSocket frame. This means that processing the WebSocket data must be done as pure a sequence of bytes that sequentially construct tunneling frames regardless of what the WebSocket fragmentation is.

Additionally, the WebSocket framing decided by one tunnel peer is not guaranteed to be the same as those received by the other side. For example, the maximum WebSocket frame size in the `aws.iot.securetunneling-3.0` protocol is 131076 bytes, and the service may aggregate data to a point that aggregates multiple messages to this size into a single frame. The tunneling message frames generated by a tunnel peer are maintained by the service and cannot be aggregated or fragmented. This enables known tunnel peers to operate under more restrictive guidelines than what is valid in this protocol guide. One example of this is reducing the maximum payload of a tunneling message to 16kb down from 64kb to enable local proxy implementations to reduce the size of processing buffers.

### ProtocolBuffers Message Schema

The data that must be parsed into a ProtocolBuffers message conforms to the following schema:

```
syntax = "proto3";

package com.amazonaws.iot.securedtunneling;

option java_outer_classname = "Protobuf";
option optimize_for = LITE_RUNTIME;

message Message {
    Type    type         = 1;
    int32   streamId     = 2;
    bool    ignorable    = 3;
    bytes   payload      = 4;
    string  serviceId    = 5;
    repeated string availableServiceIds = 6;
    uint32 connectionId = 7;
    
    enum Type {
        UNKNOWN = 0;
        DATA = 1;
        STREAM_START = 2;
        STREAM_RESET = 3;
        SESSION_RESET = 4;
        SERVICE_IDS = 5;
        CONNECTION_START = 6;
        CONNECTION_RESET = 7;
    }
}
```

Tunneling frames (without the data length prefix) must parse into a _Message_ object and satisfy the following rules:

- _Type_ field must be set to a non-zero enum value. Due to ProtocolBuffers schema recommendation, the keyword 'required' is not used in the actual schema
- It is invalid for a client connected with mode=destination to send a message with _Type_ = _StreamStart_ over the tunnel.
- It is invalid for any client to send message types associated with a stream (_StreamStart_, _ConnectionStart_, _Data_, _StreamReset_, _ConnectionReset_) with a stream ID of 0
- Sending a message type (_StreamStart_, _ConnectionStart_, _Data_, _ConnectionReset_) without a connection ID or with a connection ID of 0 will always make destination v3 localproxy reinterpret it as connection ID set to 1. This is intended behavior.
- It is invalid for any client to send _SessionReset_.
- They payload of any message may not contain more than 63kb (64512 bytes) of data.
- It is invalid to extend the schema with additional fields and send them through the tunnel. The service will close the WebSocket connection if this occurs.
- Avoid negative stream ID numbers for message size efficiency. Stream ID of 0 is invalid. Connection ID of 0 will be ignored.
- It is invalid for any local proxy to send message types _SERVICE_IDS_. It can only be sent from the Secure Tunneling service. 
- Change the tag numbers of existing field of ProtocolBuffers will cause backward compatibility issue between V1 and V2 local proxy. Fore more information, please read [Extending a Protocol Buffer](https://developers.google.com/protocol-buffers/docs/cpptutorial#extending-a-protocol-buffer).

### Backward compatibility

Backwards compatibility does NOT apply if the client decides to send a previous version message format in the middle of an active websocket session.
Any attempts to do so will be rejected.
The following sections assume that both the source and destination have been configured prior to connecting to the websocket.
Any further configuration changes will require restarting the local proxy.

#### Backward compatibility between V2 and V3 local proxy
V2 local proxy protocol uses Sec-WebSocket-Protocol _aws.iot.securetunneling-2.0_ when communicates with AWS IoT Tunneling Service.
V3 local proxy protocol uses Sec-WebSocket-Protocol _aws.iot.securetunneling-3.0_ when communicates with AWS IoT Tunneling Service.
The communication between V2 and V3 local proxy is supported for a multiplexed tunnel with a single TCP connection per stream.
- _aws.iot.securetunneling-2.0_ and _aws.iot.securetunneling-3.0_ subprotocol are interoperable.
- An empty connection ID field or connection ID set to 0 in a message should be interpreted as the connection ID field is not present. This is because in protocol buffers _proto3_, it can not tell if  a field is set with 0 or a field is not present at all.\
- If existing local proxy receives a StreamStart message from proposed local proxy, it will ignore the connection ID field.
- The local proxy should not use a connection ID when sending to v2 protocol. Using the local proxy with simultaneous TCP services to communicate with v2 local proxy is not supported.
- If a v3 local proxy sends a StreamStart to a v2 local proxy, the first TCP connection will be established and the tunnel functions as existing until the v3 local proxy sends ConnectionStart or ConnectionReset. In this case, destination local proxy does not recognize the new message type and sends StreamReset.
- An empty connection ID field in a StreamStart message should be interpreted as a message sent from a v2 local proxy. In that case, v3 local proxy should ignore the connection ID field. All the subsequent messages should not contain connection ID (will be ignored by the v3 local proxy if they do). ConnectionStart or ConnectionReset should be treated as error. And vice versa, if the local proxy sends the first StreamStart with connection ID, then all subsequent messages should contain the connection ID field. If the subsequent messages does not contain connection ID, local proxy should see the peer as non-compliant and close the stream.

### Message type reference

#### StreamStart

* _StreamStart_ is the first message sent to start and establish the new and active data stream. For local proxies, this message carries across similar meaning to a TCP SYN packet.
* When to send
    * When the source tunnel client wants to initiate a new data stream with the destination,  it does this by sending a _StreamStart_ with a temporally unique stream ID and service ID. Stream ID should be chosen in a way that is unlikely to repeat through a tunnel's lifetime. Service ID is determined by which port accepts the TCP connection. For example, if you configure SSH1 to listen on port 5555, SSH2 to listen on port 6666, when the connection from port 5555 is accepted, service ID will be choosen to be SSH1. 
* Behavior on receive:
    * Destination local proxy should treat this as a request to initiate a new stream to a configured destination service and establish the given stream ID as the current.
    * If the destination mode tunnel client already has an already open/active stream and receives a _StreamStart_, it should consider the current data stream to have closed and immediately start a new active stream with the new stream ID. A _StreamReset_ MAY be sent for the replaced stream ID.
    * Source mode tunnel clients SHOULD treat receiving _StreamStart_ as an error and close the active data stream and WebSocket connection.
* Notes
    * After the source client sends _StreamStart_, it may immediately send request data and assume the destination will connect. Failure will result in a _StreamReset_ coming back, and success (with data response) results in receiving data on the stream ID
* Example: Message(type=STREAM_START, streamId=1, connectionId=1, payload=<unset>,  serviceId=ssh1, availableServiceIds=<unset>, ignorable=<unset>)

#### StreamReset

* _StreamReset_ messages conveys that the data stream has ended, either in error, or closed intentionally for the tunnel peer. It is also sent to the source tunnel peer if an attempt to establish a new data stream fails on the destination side.
* When to send:
    * During a stream's data transmission, if anything happens that makes it impossible to process a data stream's data correctly or in order (I/O error, logic error), a _StreamReset_ should be sent with the active stream ID and valid service ID. 
    * While attempting to establish a new data stream, if the destination tunnel client fails to establish a local connection, it should send a _StreamReset_ back over the tunnel with the requested stream ID and service ID.
* Behavior on receive:
    * Both tunnel client modes should respond to a _StreamReset_ message by closing the active data stream or connection when the stream ID matches the current stream
        * After closing the current stream, the current stream ID should be unset internally
        * The tunnel client SHOULD perform an orderly shutdown of the data stream or connection and flush any local connection buffers before closing
    * If the receiver does not have an active stream, it is safe to ignore a _StreamReset_ message
* Notes
    * The proxy server may generate _StreamReset_ messages in the following scenarios:
        * The tunnel peer is replaced (likely has reconnected) by a new peer bearing a valid access token
        * An internal error has disrupted the internal routing for the tunnel
* Example: Message(type=STREAM_RESET, streamId=1, payload=<unset>, serviceId=ssh1, availableServiceIds=<unset>, ignorable=<unset>)

#### ConnectionStart

* _ConnectionStart_ is the message sent to start and establish a new and active connection when the stream has been established and there’s one active connection in the stream. To start the first connection, use StreamStart. For local proxies, this message carries across similar meaning to a TCP SYN packet.
* When to send
    * When the source tunnel client wants to initiate a new data stream with the destination, local proxy does this by sending a ConnectionStart with the current stream ID and connection ID. Connection ID should be chosen in a way that is unlikely to repeat through a tunnel's lifetime. Connection ID is used to identify the TCP connection at the source tunnel client.

* Behavior on receive:
    * Destination local proxy should treat this as a request to initiate a TCP connection to a configured destination service and associate the new TCP connection with the given connection ID.
    * If the destination mode tunnel client already has an already open/active TCP connection with the given connection ID, it should consider it an error and send ConnectionReset for the given connection ID to tunnel peer.
    * Source mode tunnel clients SHOULD treat receiving ConnectionStart as an error and close the active connection for the given connection ID.
* Example: Message(type=CONNECTION_START, streamId=1, connectionId=1, payload=<unset>, serviceId=ssh1, availableServiceIds=<unset>, ignorable=<unset>)

#### ConnectionReset

* _ConnectionReset_ message conveys that the connection has ended, either in error, or closed intentionally for the tunnel peer. It is also sent to the source tunnel peer if an attempt to establish a new connection fails on the destination side. For local proxies, this message carries across similar meaning to a TCP RST packet.
* When to send:
    * During a connection's data transmission, if anything happens that makes it impossible to process a connection's data correctly or in order (I/O error, logic error), a ConnectionReset should be sent with the active stream ID and valid connection ID.
    * While attempting to establish a new connection, if the destination tunnel client fails to establish a local connection, it should send a ConnectionReset back over the tunnel with the requested stream ID and connection ID.

* Behavior on receive:
    * Both tunnel client modes should respond to a ConnectionReset message by closing the active connection when the stream ID matches the current stream and connection ID matches an active connection.
        * After closing the connection, the connection ID should be unset internally
        * The tunnel client SHOULD perform an orderly shutdown of the connection and flush any local connection buffers before closing
    * If the receiver does not have an active stream or matching connection, it is safe to ignore a ConnectionReset message
* Example: Message(type=CONNECTION_RESET, streamId=1, connectionId=1, payload=<unset>, serviceId=ssh1, availableServiceIds=<unset>, ignorable=<unset>)
  
#### SessionReset

* _SessionReset_ messages can only originate from Secure Tunneling service if an internal data transmission error is detected
* When to send:
    * N/A - tunnel client cannot send this message through the service
* Behavior on receive:
    * This message should be handled the same as _StreamReset_ except that it carries no stream ID association so any active stream should be closed
* Notes
    * This message type should rarely be observed.
    * If the receiver does not have an active stream, it is safe to ignore a _SessionReset_ message
* Example: Message(type=SESSION_RESET, streamId=<unset>, payload=<unset>, serviceId=<unset>, availableServiceIds=<unset>, ignorable=<unset>)


#### Data

* _Data_ messages carry a payload with a sequence of bytes to write to the active data stream when received by local proxy. When local proxy reads data from its local connection, those bytes should be inserted into the payload of a _Data_ message and sent over a tunnel
* When to send:
    * When a tunnel client reads data on the (non-WebSocket) data stream (e.g. the TCP connection for the local proxy), it must construct _Data_ messages with the sequence of bytes put into the payload - up to 63kb in size - and set the active stream ID and valid service ID on the message.
* Behavior on receive:
    * When a local proxy receives _Data_ messages, it must write the payload data directly to the (non-WebSocket) data stream
* Example: Message(type=DATA, streamId=1, connectionId=1, payload=[byte sequence], serviceId=ssh1, availableServiceIds=<unset>,  ignorable=<unset>)

#### ServiceIDs
* _ServiceIDs_ message carry a list of unique service IDs used when open a tunnel with **services** in [DestinationConfig](https://docs.aws.amazon.com/iot/latest/apireference/API_iot-secure-tunneling_DestinationConfig.html) parameter. It's sent to local proxy for providing the source of truth of what service IDs can be used in local proxy. 
* When to send:
    * N/A - tunnel client cannot send this message through the service
* Behavior on receive:
    * Validate user input. If there is a mismatch between service ID list in OpenTunnel API and local proxy, local proxy will fail to start. 
    * Build or update in-memory ports mapping for book keeping. It will build or update an unordered map, with service ID as the key, and the configured port as the value. In the future, when a data packet is received from the tunnel, local proxy will extract the service ID from a data packet and find which port should this packet be forwarded using this map. 

* Example: Message(type=SERVICE_IDS, streamId=<unset>, payload=<unset>, serviceId=<unset>, availableServiceIds=ssh1, ssh2,  ignorable=<unset>)


### Ignorable field

If a message is received and its type is unrecognized, and this field is set to true, it is ok for the tunnel client to ignore the message safely. The tunnel client MAY still treat the unrecognized message as an error out of caution. If this field is unset, it must be considered as false.
