// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "WebProxyAdapter.h"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <boost/log/sources/severity_feature.hpp>
#include <boost/log/sources/severity_logger.hpp>

namespace base64 = boost::beast::detail::base64;
using boost::log::trivial::trace;
using boost::log::trivial::debug;
using boost::log::trivial::info;
using boost::log::trivial::warning;
using boost::log::trivial::error;
using boost::log::trivial::fatal;

namespace aws {
    namespace iot {
        namespace securedtunneling {

            constexpr int BUFFER_SIZE_IN_BYTES = 10*1000; // 10 KB
            constexpr int HTTP_VERSION = 11; // HTTP/1.1
            WebProxyAdapter::WebProxyAdapter(logger* log,
                                                 const LocalproxyConfig &localproxy_config):
                    log(log), localproxy_config(localproxy_config) { }

            void WebProxyAdapter::async_connect(BoostCallbackFunc on_tcp_tunnel_callback,
                                                  const shared_ptr<WebSocketStream> &wss,
                                                  const tcp::endpoint &web_proxy_endpoint) {
                on_tcp_tunnel = std::make_unique<BoostCallbackFunc>(std::move(on_tcp_tunnel_callback));
                websocket_stream = wss.get();
                BOOST_LOG_SEV(*log, trace) << "Establishing TCP connection with the Web Proxy";
                websocket_stream->get_tcp_socket().async_connect(web_proxy_endpoint, [this](error_code const &ec) {
                    if (ec) {
                        BOOST_LOG_SEV(*log, error) << (boost::format("Could not connect to Web Proxy: %1%") % ec.message()).str();
                        (*on_tcp_tunnel)(WebProxyAdapterErrc::TcpConnectError);
                    } else {
                        BOOST_LOG_SEV(*log, debug) << "Connected successfully with Web Proxy";
                        websocket_stream->lowest_layer().set_option(tcp::no_delay(true));
                        if (localproxy_config.is_web_proxy_using_tls) {
                            async_ssl_handshake();
                        } else {
                            on_tcp_connect();
                        }
                    }
                });
            }

            void WebProxyAdapter::async_ssl_handshake() {
                if (!localproxy_config.no_ssl_host_verify) {
                    websocket_stream->get_web_proxy_ssl_stream()->set_verify_mode(ssl::verify_peer | ssl::verify_fail_if_no_peer_cert);
                    websocket_stream->get_web_proxy_ssl_stream()->set_verify_callback(boost::asio::ssl::rfc2818_verification(localproxy_config.web_proxy_host));
                }
                websocket_stream->get_web_proxy_ssl_stream()->async_handshake(ssl::stream_base::client, [this](error_code const &ec) {
                    if (ec) {
                        BOOST_LOG_SEV(*log, error) << (boost::format("Could not perform SSL handshake with Web Proxy: %1%") % ec.message()).str();
                        (*on_tcp_tunnel)(WebProxyAdapterErrc::SslHandshakeError);
                    } else {
                        BOOST_LOG_SEV(*log, debug) << "Performed SSL handshake with Web proxy successfully";
                        on_tcp_connect();
                    }
                });
            }

            void WebProxyAdapter::on_tcp_connect() {
                BOOST_LOG_SEV(*log, trace) << "Preparing HTTP CONNECT request";
                request.version(HTTP_VERSION);
                request.method(http::verb::connect);
                const std::string host =  localproxy_config.proxy_host +
                                     ":" + std::to_string(localproxy_config.proxy_port);
                request.target(host);
                if (!localproxy_config.web_proxy_auth.empty()) {
                    BOOST_LOG_SEV(*log, trace) << "Web proxy AuthN found, adding them to the request";
                    request.set(http::field::host, host);
                    std::string credentials;
                    credentials.resize(base64::encoded_size(localproxy_config.web_proxy_auth.size()));
                    credentials.resize(base64::encode(&credentials[0],
                                                      localproxy_config.web_proxy_auth.data(),
                                                      localproxy_config.web_proxy_auth.size()));
                    request.set(http::field::proxy_authorization, "basic " + credentials);
                }
                BOOST_LOG_SEV(*log, trace) << "Sending HTTP CONNECT";
                auto on_async_write = [this](error_code const &ec,
                                                               std::size_t bytes_transferred) {
                    boost::ignore_unused(bytes_transferred);
                    if (ec) {
                        BOOST_LOG_SEV(*log, error) << (boost::format(
                                    "Could not send HTTP CONNECT request to the Web proxy: %1%") % ec.message()).str();
                        (*on_tcp_tunnel)(WebProxyAdapterErrc::HttpWriteRequestError);
                    } else {
                        BOOST_LOG_SEV(*log, debug) << "Successfully sent HTTP CONNECT to the Web proxy";
                        on_http_connect_write();
                    }
                };
                if (localproxy_config.is_web_proxy_using_tls) {
                    http::async_write(*websocket_stream->get_web_proxy_ssl_stream(), request, on_async_write);
                } else {
                    http::async_write(websocket_stream->get_tcp_socket(), request, on_async_write);
                }
            }

            void WebProxyAdapter::on_http_connect_write() {
                BOOST_LOG_SEV(*log, trace) << "Waiting for HTTP CONNECT response from the Web proxy";
                char *response_buffer = new char[BUFFER_SIZE_IN_BYTES];
                read_buffer = boost::asio::buffer(response_buffer, BUFFER_SIZE_IN_BYTES);
                auto on_read = [this, response_buffer](error_code const &ec,
                                                       std::size_t bytes_transferred){
                    if (ec) {
                        BOOST_LOG_SEV(*log, error) << (boost::format(
                                    "Could not read HTTP CONNECT response from the Web proxy: %1%") % ec.message()).str();
                        (*on_tcp_tunnel)(WebProxyAdapterErrc::ServerError);
                    }
                    BOOST_LOG_SEV(*log, trace) << "Parsing the HTTPS response from the Web proxy";
                    boost::ignore_unused(bytes_transferred);
                    error_code parser_ec{};
                    http::response_parser<http::string_body> parser{response};
                    parser.put(boost::asio::buffer(read_buffer),parser_ec);
                    response = parser.release();
                    const http::status_class status_class = http::to_status_class(response.result());
                    if (status_class != http::status_class::successful) {
                        BOOST_LOG_SEV(*log, error) << boost::format(
                                    "HTTP CONNECT request failed with response code: %1%(%2%)") % response.result_int() %
                                                            response.result();
                    }
                    BOOST_LOG_SEV(*log, debug) << "Full response from the Web proxy:\n"
                                                     << boost::beast::buffers_to_string(read_buffer);
                    switch (status_class) {
                        case http::status_class::successful:
                            if (response.result() == http::status::ok) {
                                BOOST_LOG_SEV(*log, info) << "TCP tunnel established successfully";
                            } else {
                                BOOST_LOG_SEV(*log, warning)
                                    << "TCP tunnel established but with unexpected response code from the Web proxy";
                            }
                            (*on_tcp_tunnel)(WebProxyAdapterErrc::Success);
                            break;
                        case http::status_class::redirection:
                            BOOST_LOG_SEV(*log, error) << "Make sure you're using the correct Web proxy address";
                            (*on_tcp_tunnel)(WebProxyAdapterErrc::RedirectionError);
                            break;
                        case http::status_class::client_error:
                            BOOST_LOG_SEV(*log, error) << "Make sure the Web proxy is configured properly";
                            (*on_tcp_tunnel)(WebProxyAdapterErrc::ClientError);
                            break;
                        case http::status_class::server_error:
                            BOOST_LOG_SEV(*log, error) << "Web proxy error, make sure to check your server's logs";
                            (*on_tcp_tunnel)(WebProxyAdapterErrc::ServerError);
                            break;
                        default:
                            BOOST_LOG_SEV(*log, error) << "Unexpected response code";
                            (*on_tcp_tunnel)(WebProxyAdapterErrc::OtherHttpError);
                            break;
                    }
                    delete[] response_buffer;
                };
                // Initially I tried to use boost::beast::http::async_read, but for some reason the beast implementation
                // of that method disrupted the TCP connection causing "stream truncated" error during the SSL handshake
                // with the proxy server. So I had to read from the TCP socket directly and parse the response. This could
                // be something to test when we upgrade to a newer version of boost to see if boost::beast::http::async_read
                // is fixed in it or not.
                if (localproxy_config.is_web_proxy_using_tls) {
                    websocket_stream->get_web_proxy_ssl_stream()->async_read_some(read_buffer, on_read);
                } else {
                    websocket_stream->get_tcp_socket().async_receive(read_buffer, on_read);
                }
            }
        }
    }
}
