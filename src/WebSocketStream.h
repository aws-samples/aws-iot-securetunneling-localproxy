// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "LocalproxyConfig.h"

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <utility>
#include <boost/variant.hpp>

using tcp = boost::asio::ip::tcp;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;
namespace websocket = boost::beast::websocket;
using std::unique_ptr;
using std::shared_ptr;
using std::function;
using BoostCallbackFunc = function<void(boost::system::error_code)>;
typedef ssl::stream<tcp::socket&> single_ssl_stream_type;
typedef ssl::stream<ssl::stream<tcp::socket&>&> double_ssl_stream_type;
typedef websocket::stream<tcp::socket&> websocket_stream_type;
typedef  websocket::stream<single_ssl_stream_type&> websocket_stream_single_ssl_type;
typedef  websocket::stream<double_ssl_stream_type&> websocket_stream_double_ssl_type;
#ifdef _AWSIOT_TUNNELING_NO_SSL
typedef boost::variant<unique_ptr<websocket_stream_type>, unique_ptr<websocket_stream_single_ssl_type>> websocket_variant;
#else
typedef boost::variant<unique_ptr<websocket_stream_double_ssl_type>, unique_ptr<websocket_stream_single_ssl_type>> websocket_variant;
#endif
using logger = boost::log::sources::severity_logger<boost::log::trivial::severity_level>;

namespace aws {
    namespace iot {
        namespace securedtunneling {
            /**
             * This is a wrapper around boost::beast::websocket::stream class. Based on whether TLS will be used
             * in the connection between the localproxy and the web proxy or the connection between the localproxy
             * and the proxy server, we will need a different subtemplate of the websocket stream class for each case.
             * And because those subtemplates don't share a common interface, we can't rely on polymorphic calls to
             * determine at run time which subtemplate to use. So the solution to that is to wrap all of that in a
             * a separate class that will take care of that complexity and determine which stream type to use/return
             * based on the localproxy configurations.
             *
             * Many of the methods in this class simply pass the the argument to the correct Boost implementation
             * and return the result as it.
             */
            class WebSocketStream : public std::enable_shared_from_this<WebSocketStream> {
                /**
                 * A single SSL stream, used when
                 * 1. THe localproxy connects directly to the proxy server
                 * 2. The localproxy connects via web proxy and the connection with the web proxy is not over TLS.
                 */
                shared_ptr<single_ssl_stream_type> single_ssl_stream;
#ifndef _AWSIOT_TUNNELING_NO_SSL
                /**
                 * A double SSL stream (an SSL stream within another SSL stream, i.e. doubly encrypted), used when
                 * 1. The localproxy connects via web proxy and the connection with the web proxy is over TLS.
                 */
                shared_ptr<double_ssl_stream_type> double_ssl_stream;
#endif
                /**
                 * A boost variant for the websocket stream, it's a convenient way to store object where the type
                 * will be determined at run time based on some condition.
                 */
                websocket_variant wss;
                const LocalproxyConfig localproxyConfig;
                /**
                 * SSL Context, used for all SSL streams.
                 */
                ssl::context ssl_context;
                /**
                 * A reference to Boost I/O Context, provided by the consumer of this class.
                 */
                boost::asio::io_context &io_context;
                tcp::socket socket;
                /**
                 * A pointer to Boost logger.
                 */
                logger *log;
            public:
                WebSocketStream(LocalproxyConfig config,
                                logger *log,
                                boost::asio::io_context &io_ctx);

                /**
                 * Checks whether the websocket stream is open or not
                 * @return true of the stream is open, false otherwise
                 */
                bool is_open();

                /**
                 * Get a reference to the lowest layer
                 * @return a reference to a basic_socket type, which is the lowest layer.
                 */
                boost::asio::basic_socket<tcp> &lowest_layer();

                /**
                 * Asynchronous method for sending websocket ping messages, returns immediately.
                 * @param payload the websocket ping frame payload
                 * @param handler the handler that will be called when the async operation is complete
                 */
                void async_ping(const websocket::ping_data &payload, const BoostCallbackFunc &handler);

                /**
                 * Asynchronous method for sending websocket pong messages, returns immediately.
                 * @param payload the websocket pong frame payload
                 * @param handler the handler that will be called when the async operation is complete
                 */
                void async_pong(const websocket::ping_data &payload, const BoostCallbackFunc &handler);

                /**
                 * Set a callback to be invoked on each incoming control frame.
                 * @param cb The function object to call
                 */
                void control_callback(const function<void(websocket::frame_type ws_message_type,
                                                          boost::beast::string_view payload)> &cb);

                /**
                 * Set the binary message write option.
                 * @param ualue `true` if outgoing messages should indicate
                 *            binary, or `false` if they should indicate text.
                 */
                void binary(const bool &value);

                /**
                 * Determines if outgoing message payloads are broken up into multiple pieces.
                 * @param value A `bool` indicating if auto fragmentation should be on.
                 */
                void auto_fragment(const bool &value);

#ifndef _AWSIOT_TUNNELING_NO_SSL
                /**
                 * Sets the SSL verification mode for the SSL stream/layer used for the connection between the
                 * proxy server and the localproxy.
                 * @param v the SSL verification mode.
                 */
                void set_ssl_verify_mode(const ssl::verify_mode &v);

                /**
                 * Sets the SSL verification callback for the SSL stream/layer used for the connection between the
                 * proxy server and the localproxy.
                 * @param callback the SSL callback.
                 */
                void set_verify_callback(const ssl::rfc2818_verification &callback);

                /**
                 * Performs the SSL handshake between the localproxy and the proxy server asynchronously.
                 * @param type The handshake type
                 * @param handler the callback handler when the async operation is complete.
                 */
                void
                async_ssl_handshake(const ssl::stream_base::handshake_type &type, const BoostCallbackFunc &handler);
#endif

                /**
                 * Perform the websocket an asynchronous handshake with the proxy server.
                 * @param res_type The response type
                 * @param host the host subdoman and domain
                 * @param target the URL path and query parameters
                 * @param decorator A function object which will be called to modify the HTTP request object generated by the implementation.
                 * @param handler The handler to be called when the request completes.
                 */
                void async_handshake_ex(websocket::response_type &res_type, const std::string &host,
                                        const std::string &target,
                                        const function<void(websocket::request_type &request)> &decorator,
                                        const BoostCallbackFunc &handler);

                /**
                 * Read part of a message asynchronously from the proxy server.
                 * @param buffer A dynamic buffer to hold the message data after any masking or decompression has been applied.
                 * @param size An upper limit on the number of bytes this function will append into the buffer.
                 * @param handler  handler to be called when the read operation completes.
                 */
                void async_read_some(boost::beast::multi_buffer &buffer, const std::size_t &size,
                                     const function<void(boost::system::error_code, std::size_t)> &handler);

                /**
                 * Write a complete message asynchronously.
                 * @param buffer A buffer sequence containing the entire message payload.
                 * @param handler The completion handler to invoke when the operation completes.
                 */
                void async_write(const boost::asio::const_buffer &buffer,
                                 const function<void(boost::system::error_code, std::size_t)> &handler);

                /**
                 * Returns the close reason received from the peer.
                 * @return websocket::close_reason
                 */
                websocket::close_reason const &reason();

                /**
                 * Start tearing down a stream(s) underlying the websocket stream.
                 * @param role The role of the local endpoint
                 * @param handler The handler to be called when the request completes.
                 */
                void async_teardown(const boost::beast::role_type &role, const BoostCallbackFunc &handler);
                /**
                 * A getter for the socket.
                 * @return Returns a reference to the underlying TCP socket
                 */
                tcp::socket & get_tcp_socket();
                /**
                 * A getter for the SSL stream used by the web proxy.
                 * @return Returns a shared_ptr to the SSL stream or nullptr if the web proxy have TLS ports.
                 */
                shared_ptr<single_ssl_stream_type> get_web_proxy_ssl_stream();
            };
        }
    }
}
