The reference implementation of the local proxy provides features that may require OS facilities not available on all device runtime environments in the industry. This guide provides details about the communication that occurs between the service and client to enable integration without or beyond the local proxy reference implementation choices. This protocol guide is only applicable for v1 local proxy. 

## Core implementation requirements

In order to properly connect with and interpret messages from the AWS IoT Secure Tunneling service, the following is required:

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

-   The tunneling service only accepts connections secured with TLS 1.1 or higher
-   The HTTP path of the upgrade request must be `/tunnel`. Requests made to any other path will result in a 400 HTTP response
-   There must be a URL parameter `local-proxy-mode` specifying the tunnel connection (local proxy) mode. The value of this parameter must be `source` or `destination`
-   There must be an access token specified in the request either via cookie, or an HTTP request header
    -   Set the access token via HTTP request header named 'access-token' or via cookie named 'awsiot-tunnel-token'
    -   Only one token value may be present in the request. Supplying multiple values for either the access-token header or the cookie, or both combined will cause the handshake to fail.
    -   Local proxy mode must match the mode of the access token or the handshake will fail.
-   The HTTP request size must not exceed 4k bytes in length. Requests larger than this will be rejected
-   The 'Sec-WebSocket-Protocol' header must contain at least one valid protocol string based on what is supported by the service
    -   Currently valid value: 'aws.iot.securetunneling-1.0'

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
Sec-WebSocket-Protocol: aws.iot.securetunneling-1.0
access-token: AQGAAXiVzSmRL1VaJ22G7eRb\_CrPABsAAgABQQAMOTAwNTgyMDkxNTM4AAFUAANDQVQAAQAHYXdzLWttcwBLYXJuOmF3czprbXM6dXMtZWFzdC0xOjcwMTU0NTg5ODcwNzprZXkvMmU4ZTAxMDEtYzE3YS00NjU1LTlhYWQtNjA2N2I2NGVhZWQyALgBAgEAeAJ2EsT4f5oCWm65Y8zRx\_nNaCjcG4FIeNV\_zMyhoOslAVAr521wChjzvogy-2-mxyoAAAB-MHwGCSqGSIb3DQEHBqBvMG0CAQAwaAYJKoZIhvcNAQcBMB4GCWCGSAFlAwQBLjARBAwfBUUjMYI9gDEp0xwCARCAO1VX0NAiSjfU-Ar9PWYaNI5j9v77CxLcucht3tWZd57-Zq3aRQZBM4SQiy-D0Cgv31IfZ8pgWu8asm5FAgAAAAAMAAAQAAAAAAAAAAAAAAAAACniTwIAksExcMygMJ2uHs3\_\_\_\_\_AAAAAQAAAAAAAAAAAAAAAQAAAC9e5K3Isg5gHqO9LYX0geH4hrfthPEUhdrl9ZLksPxcVrk6XC4VugzrmUvEUPuR00J3etgVQZH\_RfxWrVt7Jmg=
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
Sec-WebSocket-Protocol: aws.iot.securetunneling-1.0
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
sec-websocket-protocol: aws.iot.securetunneling-1.0
```

The aspects of the response to consider above a standard successful WebSocket handshake response are:

-   The `channel-id` response header is a unique identifier for the WebSocket session with the service. It may be useful when troubleshooting any suspected issues through AWS Support
-   The 'sec-websocket-protocol' response header will contain one of the values specified in the request. That the proxy  Clients must understand and properly implement the subprotocol returned in this response header to ensure valid communication over the tunnel.

After a successful WebSocket handshake with the tunneling service, full duplex communication is possible over WebSocket. Tunnel communication messages are delivered reliably and in order.

### Handshake error responses

* If the handshake HTTP response code is within the 500-599 range, the client should retry using an exponential backoff retry strategy.
* If the handshake HTTP response code is within the 400-499 range, the service is rejecting the clients request, or access to the tunnel is not possible or denied. Do not retry unless the problem is understood and the request changes (i.e. use another region endpoint or different client access token)
* Many handshake error responses will contain the `channel-id` header which may be helpful for AWS Support troubleshooting

## WebSocket Subprotocol: aws.iot.securetunneling-1.0

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

The core activity during tunneling is sending ProtocolBuffers messages back and forth carrying either data, or messages that manage the connection state (called _control messages_) over the WebSocket connection to the service. This WebSocket connection to the service is synonymous with being connected to the tunnel. Once both peers are connected to a tunnel, the first thing that must happen is initiating a data stream from source to destination. Using the local proxy, this would be when a client application connects to the listen port of the source mode local proxy. The source local proxy accepts the TCP connection and sends a _StreamStart_ message containing a unique identifier called the _stream ID_ to identify the data stream and future messages associated with it.  On receiving a _StreamStart_ the destination local proxy side the tunnel will connect to a destination service listening on a port. If this operation succeeds, the destination local proxy must store the stream ID and validate future messages originating from the tunnel peer through the service. The destination local proxy does not send a reply to the source local proxy on successful connection. Immediately after the source local proxy sends _StreamStart_ and immediately after the destination establishes a valid TCP connection, each side respectively can begin to send and receive incoming messages on the active data stream. When the data stream is closed or disrupted (for the local proxy, this is a TCP close or I/O error on the TCP socket), a _StreamReset_ control message with the currently stored stream ID should be sent through the tunnel so the tunnel peer can react appropriately and end the data stream. Control messages associated with a stream should be processed with the same stream ID filter, though some control messages carry meaning that should apply to whatever the active stream ID is. (_SessionReset_) is one example.

Here are some important things to know for a high-level understanding of tunneling data stream handling:

-   The service may use the stream ID to decide how to route traffic between connected tunnel clients
-   The local proxy, and library clients may use stream ID to determine how to respond to or filter incoming messages
    -   For example: if a source sends a _StreamStart_ with a stream ID of 345 in response to a newly accepted TCP connection, and afterwards receives a _Data_ message marked with stream ID of 565, that data should be ignored. It's origin is tied to a prior connection over the tunnel from the perspective of the tunnel peer that originated it
    -   Another example: if a source local proxy sends a _StreamStart_ with a stream ID of 345 in response to a newly accepted TCP connection, and afterwards receives a _StreamReset_ message marked with stream ID of 565, that message should be ignored. Only a _StreamReset_ with a stream ID of 345 should cause the client to close its local connection
-   Ending a data stream (normally or abnormally) is accomplished by either side sending a _StreamReset_ with the stream ID that is meant to be closed
-   During a WebSocket connection to a tunnel, multiple streams may be started and ended, but only one active stream is supported at a time
-   Locally detected network failures are communicated by sending _StreamReset_ over the tunnel using the active stream ID if one is active.
    -   If there is a network issue with the WebSocket connection, no control message is necessary to send. However, the active stream should be considered invalid and closed. Reconnect to the tunnel via the service and start a new stream

### Tunneling message frames

WebSocket binary frames contain a sequence of tunnel frames or messages. Each data message has a **2-byte unsigned short, big endian** data length prefix, followed by sequence of bytes whose length is specified by the data length. These bytes must be parsed into a ProtocolBuffers object that uses the schema shown in this document. Every message received must be processed, and should be processed in order for data stream integrity. If the order of messages is lost or cannot be understood during processing by the client, it should end the data stream with a _StreamReset_. Messages may control the state of the data stream, or it may contain actual stream data. Inspecting the message's type is the first step in processing a message. A single data length + bytes parsed into a ProtocolBuffers message represents an entire tunneling message frame, and the beginning of the next frame's length prefix follows immediately. This is a visual diagram of a single frame:

    |-----------------------------------------------------------------|
    | 2-byte data length   |     N byte ProtocolBuffers message       |
    |-----------------------------------------------------------------|

Tunneling message frames are very loosely coupled with WebSocket frames. It is not required that a WebSocket frame contain an entire tunneling message frame. The start and end of a WebSocket frame does not have to be aligned with a tunneling frame and vice versa. A WebSocket frame may contain multiple tunneling frames, or it may contain only a slice of a tunneling frame started in a previous WebSocket frame and will finish in a later WebSocket frame. This means that processing the WebSocket data must be done as pure a sequence of bytes that sequentially construct tunneling frames regardless of what the WebSocket fragmentation is.

Additionally, the WebSocket framing decided by one tunnel peer is not guaranteed to be the same as those received by the other side. For example, the maximum WebSocket frame size in the `aws.iot.securetunneling-1.0` protocol is 131076 bytes, and the service may aggregate data to a point that aggregates multiple messages to this size into a single frame. The tunneling message frames generated by a tunnel peer are maintained by the service and cannot be aggregated or fragmented. This enables known tunnel peers to operate under more restrictive guidelines than what is valid in this protocol guide. One example of this is reducing the maximum payload of a tunneling message to 16kb down from 64kb to enable local proxy implementations to reduce the size of processing buffers.

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

    enum Type {
        UNKNOWN = 0;
        DATA = 1;
        STREAM_START = 2;
        STREAM_RESET = 3;
        SESSION_RESET = 4;
    }
}
```

Tunneling frames (without the data length prefix) must parse into a _Message_ object and satisfy the following rules:

-   _Type_ field must be set to a non-zero enum value. Due to ProtocolBuffers schema recommendation, the keyword 'required' is not used in the actual schema
-   It is invalid for a client connected with mode=destination to send a message with _Type_ = _StreamStart_ over the tunnel.
-   It is invalid for any client to send messages types associated with a stream (_StreamStart_, _Data_, _StreamReset_) with a stream ID of 0
-   It is invalid for any client to send _SessionReset_
-   They payload of any message may not contain more than 63kb (64512 bytes) of data.
-   It is invalid to extend the schema with additional fields and send them through the tunnel. The service will close the WebSocket connection if this occurs
-   Avoid negative stream ID numbers for message size efficiency. Stream ID of 0 is invalid

### Message type reference

#### StreamStart

* _StreamStart_ is the first message sent to start and establish the new and active data stream. For local proxies, this message carries across similar meaning to a TCP SYN packet.
* When to send
    * When the source tunnel client wants to initiate a new data stream with the destination it does this by sending a _StreamStart_ with a temporally unique stream ID. Stream ID should be chosen in a way that is unlikely to repeat through a tunnel's lifetime. 
* Behavior on receive:
    * Destination mode tunnel clients should treat this as a request to initiate a new stream to a configured destination service and establish the given stream ID as the current
        * If the destination mode tunnel client already has an already open/active stream and receives a _StreamStart_, it should consider the current data stream to have closed and immediately start a new active stream with the new stream ID
            * A _StreamReset_ MAY be sent for the replaced stream ID
    * Source mode tunnel clients SHOULD treat receiving _StreamStart_ as an error and close the active data stream and WebSocket connection
* Notes
    * After the source client sends _StreamStart_, it may immediately send request data and assume the destination will connect. Failure will result in a _StreamReset_ coming back, and success (with data response) results in receiving data on the stream ID
* Example: Message(type=STREAM_START, streamId=1, payload=<unset>, ignorable=<unset>)

#### StreamReset

* _StreamReset_ messages conveys that the data stream has ended, either in error, or closed intentionally for the tunnel peer. It is also sent to the source tunnel peer if an attempt to establish a new data stream fails on the destination side.
* When to send:
    * During a stream's data transmission, if anything happens that makes it impossible to process a data stream's data correctly or in order (I/O error, logic error), a _StreamReset_ should be sent with the active stream ID
    * While attempting to establish a new data stream, if the destination tunnel client fails to establish a local connection, it should send a _StreamReset_ back over the tunnel with the requested stream ID
* Behavior on receive:
    * Both tunnel client modes should respond to a _StreamReset_ message by closing the active data stream or connection when the stream ID matches the current stream
        * After closing the current stream, the current stream ID should be unset internally
        * The tunnel client SHOULD perform an orderly shutdown of the data stream or connection and flush any local connection buffers before closing
    * If the receiver does not have an active stream, it is safe to ignore a _StreamReset_ message
* Notes
    * The proxy server may generate _StreamReset_ messages in the following scenarios:
        * The tunnel peer is replaced (likely has reconnected) by a new peer bearing a valid access token
        * An internal error has disrupted the internal routing for the tunnel
* Example: Message(type=STREAM_RESET, streamId=1, payload=<unset>, ignorable=<unset>)

#### SessionReset

* _SessionReset_ messages can only originate from Secure Tunneling service if an internal data transmission error is detected
* When to send:
    * N/A - tunnel client cannot send this message through the service
* Behavior on receive:
    * This message should be handled the same as _StreamReset_ except that it carries no stream ID association so any active stream should be closed
* Notes
    * This message type should rarely be observed.
    * If the receiver does not have an active stream, it is safe to ignore a _SessionReset_ message
* Example: Message(type=SESSION_RESET, streamId=<unset>, payload=<unset>, ignorable=<unset>)

#### Data

* _Data_ messages carry a payload with a sequence of bytes to write to the active data stream when received by a tunnel client. When a tunnel client reads data from its local connection, those bytes should be inserted into the payload of a _Data_ message and sent over a tunnel
* When to send:
    * When a tunnel client reads data on the (non-WebSocket) data stream (e.g. the TCP connection for the local proxy), it must construct _Data_ messages with the sequence of bytes put into the payload - up to 63kb in size - and set the active stream ID on the message.
* Behavior on receive:
    * When a local proxy receives _Data_ messages, it must write the payload data directly to the (non-WebSocket) data stream
* Example: Message(type=DATA, streamId=1, payload=[byte sequence], ignorable=<unset>)

### Ignorable field

If a message is received and its type is unrecognized, and this field is set to true, it is ok for the tunnel client to ignore the message safely. The tunnel client MAY still treat the unrecognized message as an error out of caution. If this field is unset, it must be considered as false.

