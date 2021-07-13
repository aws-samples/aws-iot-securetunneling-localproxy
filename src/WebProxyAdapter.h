// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "LocalproxyConfig.h"
#include "WebSocketStream.h"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

using std::shared_ptr;
using std::unique_ptr;
using std::function;
using boost::system::error_code;
using tcp = boost::asio::ip::tcp;
using logger = boost::log::sources::severity_logger<boost::log::trivial::severity_level>;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;
using BoostCallbackFunc = function<void(error_code)>;

namespace aws {
    namespace iot {
        namespace securedtunneling {
            /**
             * This class will act as an adapter to do the extra work needed to establish a TCP tunnel and then
             * hand control back to the caller to continue its execution. This class is designed to fit in boost asio's
             * single-threaded event loop model so it's not thread-safe and it's the responsibility of the consumer to
             * synchronize if they decided to access it from different threads.
             */
            class WebProxyAdapter {
            private:
                /**
                 * A pointer the boost logger that will be used by this adapter for logging.
                 */
                logger* log;
                /**
                 * A copy of the localproxy configurations
                 */
                const LocalproxyConfig &localproxy_config;
                /**
                 * A request object that will be used while establishing the TCP tunnel, it needs to be a member field
                 * because all work is done asynchronously so this object needs to outlive the function scope.
                 */
                http::request<http::empty_body> request;
                /**
                 * A response object that will be used while establishing the TCP tunnel, it needs to be a member field
                 * because all work is done asynchronously so this object needs to outlive the function scope.
                 */
                http::response<http::string_body> response;
                /**
                 * A request buffer that will be used while establishing the TCP tunnel, it needs to be a member field
                 * because all work is done asynchronously so this object needs to outlive the function scope.
                 */
                boost::asio::mutable_buffer read_buffer;
                WebSocketStream* websocket_stream = nullptr;
                unique_ptr<BoostCallbackFunc> on_tcp_tunnel = nullptr;
                /**
                 * An async member function that will be invoked internally once a TCP connection is established between
                 * the localproxy and the Web proxy, it's responsible for sending the HTTP CONNECT request to
                 * start the the TCP tunnel.
                 *
                 * @param on_tcp_tunnel The callback that will be invoked once the tcp tunnel is established
                 */
                void on_tcp_connect();
                /**
                 * A async function that will be invoked internally once the the HTTP CONNECT request is sent, it is
                 * responsible for reading and parsing the response of the CONNECT request and handing back control the
                 * the callback provided by the adapter consumer "on_tcp_tunnel" with the appropirate input based on
                 * whether the TCP tunnel was established successfully or not.
                 *
                 * @param on_tcp_tunnel The callback that will be invoked once the tcp tunnel is established
                 */
                void on_http_connect_write();
                void async_ssl_handshake();
            public:
                /**
                 * The public constructor
                 *
                 * @param log A pointer the boost logger that will be used by this adapter for logging.
                 * @param localproxy_config the localproxy configurations
                 */
                WebProxyAdapter(logger* log,
                                  const LocalproxyConfig &localproxy_config);
                /**
                 * An async public method to establish the TCP tunnel
                 *
                 * @param on_tcp_tunnel The callback that will be invoked once the tcp tunnel is established
                 * @param tcp_socket The TCP socket over which the TCP tunnel will be established
                 * @param web_proxy_endpoint The IP of the Web proxy
                 */
                void async_connect(BoostCallbackFunc on_tcp_tunnel,
                                   const shared_ptr<WebSocketStream> &wss,
                                   const tcp::endpoint &web_proxy_endpoint);
            };
        }
    }
}

enum class WebProxyAdapterErrc
{
    Success = 0,
    TcpConnectError = 1,
    HttpWriteRequestError = 2,
    ServerError = 3,
    ClientError = 4,
    RedirectionError = 5,
    OtherHttpError = 6,
    SslHandshakeError = 7,
};

namespace boost
{
    namespace system
    {
        // Tell the C++ 11 STL metaprogramming that enum WebProxyAdapterErrc
        // is registered with the standard error code system
        template <> struct is_error_code_enum<WebProxyAdapterErrc> : std::true_type
        {
        };
    }
}

// Define a custom error code category derived from boost::system::error_category
class WebProxyAdapterErrc_category : public boost::system::error_category
{
public:
    // Return a short descriptive name for the category
    virtual const char *name() const noexcept override final { return "WebProxyAdapterError"; }
    // Return what each enum means in text
    virtual std::string message(int c) const override final
    {
        switch(static_cast<WebProxyAdapterErrc>(c))
        {
            case WebProxyAdapterErrc::Success:
                return "TCP Tunnel established successfully";
            case WebProxyAdapterErrc::ServerError:
                return "The Web proxy server responded with 5xx to the HTTP CONNECT request";
            case WebProxyAdapterErrc::ClientError:
                return "The Web proxy server responded with 4xx to the HTTP CONNECT request";
            case WebProxyAdapterErrc::RedirectionError:
                return "The Web proxy server responded with 3xx to the HTTP CONNECT request";
            case WebProxyAdapterErrc::TcpConnectError:
                return "Failed to establish the TCP connection to the Web proxy";
            case WebProxyAdapterErrc::OtherHttpError:
                return "The Web proxy didn't respond with 200 response code.";
            case WebProxyAdapterErrc::HttpWriteRequestError:
                return "Failed to send to the CONNECT request to the Web proxy";
            case WebProxyAdapterErrc::SslHandshakeError:
                return "Failed to perform the SSL handshake with the Web proxy";
            default:
                return "unknown";
        }
    }
};

// Declare a global function returning a static instance of the WebProxyAdapter Error category
extern inline const WebProxyAdapterErrc_category &WebProxyAdapterErrc_category()
{
    static class WebProxyAdapterErrc_category c;
    return c;
}


// Overload the global make_error_code() free function with our
// custom enum. It will be found via ADL by the compiler if needed.
inline boost::system::error_code make_error_code(WebProxyAdapterErrc e)
{
    return {static_cast<int>(e), WebProxyAdapterErrc_category()};
}
