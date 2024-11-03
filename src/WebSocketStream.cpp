#include "WebSocketStream.h"

#include <boost/log/sources/severity_feature.hpp>
#include <boost/log/sources/severity_logger.hpp>

using boost::log::trivial::trace;
using boost::log::trivial::debug;
using boost::log::trivial::info;
using boost::log::trivial::warning;
using boost::log::trivial::error;
using boost::log::trivial::fatal;

#ifdef _AWSIOT_TUNNELING_NO_SSL
#define WEB_PROXY_WITH_TLS_TYPE websocket_stream_single_ssl_type
char const* const WEB_PROXY_WITH_TLS_TYPE_NAME = "websocket_stream_single_ssl_type";
#define WEB_PROXY_NO_TLS_TYPE websocket_stream_type
char const* const WEB_PROXY_NO_TLS_TYPE_NAME = "websocket_stream_type";
#else
#define WEB_PROXY_WITH_TLS_TYPE websocket_stream_double_ssl_type
char const* const WEB_PROXY_WITH_TLS_TYPE_NAME = "websocket_stream_double_ssl_type";
#define WEB_PROXY_NO_TLS_TYPE websocket_stream_single_ssl_type
char const* const WEB_PROXY_NO_TLS_TYPE_NAME = "websocket_stream_single_ssl_type";
#endif

namespace aws {
    namespace iot {
        namespace securedtunneling {
            bool WebSocketStream::is_open() {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling is_open with type: "
                        << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->is_open();
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling is_open with type: "
                                                  << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->is_open();
                }
            }

            void WebSocketStream::async_ping(const websocket::ping_data& payload, const BoostCallbackFunc& handler) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_ping with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->async_ping(payload, handler);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_ping with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->async_ping(payload, handler);
                }
            }

            void WebSocketStream::async_pong(const websocket::ping_data& payload, const BoostCallbackFunc& handler) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_pong with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->async_pong(payload, handler);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_pong with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->async_pong(payload, handler);
                }
            }

            void WebSocketStream::control_callback(const function<void(websocket::frame_type, boost::beast::string_view)>& cb) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling control_callback with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->control_callback(cb);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling control_callback with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->control_callback(cb);
                }
            }

            void WebSocketStream::binary(const bool& value) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling binary with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->binary(value);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling binary with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->binary(value);
                }
            }

            void WebSocketStream::auto_fragment(const bool& value) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling auto_fragment with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->auto_fragment(value);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling auto_fragment with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->auto_fragment(value);
                }
            }

            void WebSocketStream::async_handshake_ex(websocket::response_type& res_type, const std::string &host,
                                                     const std::string &target,
                                                     const function<void(websocket::request_type &)> &decorator,
                                                     const BoostCallbackFunc& handler) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_handshake with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->set_option(websocket::stream_base::decorator(decorator));
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->async_handshake(
                            res_type, host, target, handler
                    );
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_handshake with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->set_option(websocket::stream_base::decorator(decorator));
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->async_handshake(
                            res_type, host, target, handler
                    );
                }
            }

            void WebSocketStream::async_read_some(boost::beast::multi_buffer &buffer, const size_t &size,
                                                  const function<void(boost::system::error_code, std::size_t)> &handler) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_read_some with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->async_read_some(
                            buffer, size, handler
                    );
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_read_some with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->async_read_some(
                            buffer, size, handler
                    );
                }
            }

            void WebSocketStream::async_write(const boost::asio::const_buffer &buffer,
                                              const function<void(boost::system::error_code, std::size_t)> &handler) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_write with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->async_write(buffer, handler);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_write with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->async_write(buffer, handler);
                }
            }

#ifndef _AWSIOT_TUNNELING_NO_SSL
            void WebSocketStream::set_ssl_verify_mode(const ssl::verify_mode &v) {
                if (localproxyConfig.is_web_proxy_using_tls) {

                    BOOST_LOG_SEV(*log, trace) << "Calling set_verify_mode with type: double_ssl_stream";
                    return double_ssl_stream->set_verify_mode(v);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling set_verify_mode with type: single_ssl_stream";
                    return single_ssl_stream->set_verify_mode(v);
                }
            }

            void WebSocketStream::set_verify_callback(const ssl::rfc2818_verification &callback) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling set_verify_callback with type: double_ssl_stream";
                    return double_ssl_stream->set_verify_callback(callback);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling set_verify_callback with type: single_ssl_stream";
                    return single_ssl_stream->set_verify_callback(callback);
                }
            }

            void WebSocketStream::async_ssl_handshake(const ssl::stream_base::handshake_type &type, const std::string &host,
                                                      const BoostCallbackFunc &handler) {
                auto retry_count = std::make_shared<int>(0);
                auto retry_limit = 3;
                auto retry_delay = std::chrono::seconds(1);

                auto perform_handshake = [this, type, host, handler, retry_count, retry_limit, retry_delay]() {
                    if (localproxyConfig.is_web_proxy_using_tls) {
                        BOOST_LOG_SEV(*log, trace) << "Calling next_layer().async_handshake with type: "
                                                   << WEB_PROXY_WITH_TLS_TYPE_NAME;
                        // Set SNI Hostname (many hosts need this to handshake successfully)
                        if(!SSL_set_tlsext_host_name(boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->next_layer().native_handle(), host.c_str()))
                        {
                             BOOST_LOG_SEV(*log, trace) << "SSL next_layer() failed to set SNI";
                        }
                        else
                        {
                             BOOST_LOG_SEV(*log, trace) << "SSL next_layer() SNI is set : "
                                                        << host;
                        }
                        boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->next_layer().async_handshake(type, [this, handler, retry_count, retry_limit, retry_delay](const boost::system::error_code& ec) {
                            if (ec) {
                                BOOST_LOG_SEV(*log, error) << "SSL handshake failed: " << ec.message();
                                if (*retry_count < retry_limit) {
                                    (*retry_count)++;
                                    BOOST_LOG_SEV(*log, warning) << "Retrying SSL handshake (" << *retry_count << "/" << retry_limit << ")...";
                                    boost::asio::steady_timer timer(io_context, retry_delay);
                                    timer.async_wait([this, handler](const boost::system::error_code&) {
                                        perform_handshake();
                                    });
                                } else {
                                    BOOST_LOG_SEV(*log, error) << "SSL handshake failed after " << retry_limit << " attempts.";
                                    handler(ec);
                                }
                            } else {
                                handler(ec);
                            }
                        });
                    } else {
                        BOOST_LOG_SEV(*log, trace) << "Calling next_layer().async_handshake with type: "
                                                   << WEB_PROXY_NO_TLS_TYPE_NAME;
                        // Set SNI Hostname (many hosts need this to handshake successfully)
                        if(!SSL_set_tlsext_host_name(boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->next_layer().native_handle(), host.c_str()))
                        {
                            BOOST_LOG_SEV(*log, trace) << "SSL next_layer() failed to set SNI";
                        }
                        else
                        {
                            BOOST_LOG_SEV(*log, trace) << "SSL next_layer() SNI is set : "
                                                       << host;
                        }
                        boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->next_layer().async_handshake(type, [this, handler, retry_count, retry_limit, retry_delay](const boost::system::error_code& ec) {
                            if (ec) {
                                BOOST_LOG_SEV(*log, error) << "SSL handshake failed: " << ec.message();
                                if (*retry_count < retry_limit) {
                                    (*retry_count)++;
                                    BOOST_LOG_SEV(*log, warning) << "Retrying SSL handshake (" << *retry_count << "/" << retry_limit << ")...";
                                    boost::asio::steady_timer timer(io_context, retry_delay);
                                    timer.async_wait([this, handler](const boost::system::error_code&) {
                                        perform_handshake();
                                    });
                                } else {
                                    BOOST_LOG_SEV(*log, error) << "SSL handshake failed after " << retry_limit << " attempts.";
                                    handler(ec);
                                }
                            } else {
                                handler(ec);
                            }
                        });
                    }
                };

                perform_handshake();
            }
#endif

            websocket::close_reason const &WebSocketStream::reason() {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling reason with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->reason();
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling reason with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->reason();
                }
            }

            boost::asio::basic_socket<tcp> &WebSocketStream::lowest_layer() {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling lowest_layer with type: "
                                               << WEB_PROXY_WITH_TLS_TYPE_NAME;
                    return boost::beast::get_lowest_layer(*boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss));
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling lowest_layer with type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::beast::get_lowest_layer(*boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss));
                }
            }

            WebSocketStream::WebSocketStream(LocalproxyConfig config, logger *log,
                                             boost::asio::io_context &io_ctx)
                    : localproxyConfig(std::move(config)),
                      ssl_context(ssl::context::sslv23),
                      io_context(io_ctx),
                      socket {io_context},
                      log(log){
                boost::system::error_code ec;
                ssl_context.set_default_verify_paths(ec);
                if (ec) {
                    BOOST_LOG_SEV(*log, warning) << "Could not set system default OpenSSL verification path: " << ec.message();
                }
                if (localproxyConfig.additional_ssl_verify_path.has_value()) {
                    ssl_context.add_verify_path(localproxyConfig.additional_ssl_verify_path.get(), ec);
                    if (ec) {
                        BOOST_LOG_SEV(*log, fatal) << "Could not set additional OpenSSL verification path ("
                                                   << localproxyConfig.additional_ssl_verify_path.get() << "): " << ec.message();
                        throw std::runtime_error((boost::format("Could not set additional OpenSSL verification path(%1%) - %2%")
                                                  % localproxyConfig.additional_ssl_verify_path.get()
                                                  % ec.message()).str());
                    }
                }
                if (localproxyConfig.is_web_proxy_using_tls) {
                    single_ssl_stream = std::make_shared<single_ssl_stream_type>(socket, ssl_context);
#ifdef _AWSIOT_TUNNELING_NO_SSL
                    wss = std::make_unique<websocket_stream_single_ssl_type>(*single_ssl_stream);
#else
                    double_ssl_stream = std::make_shared<double_ssl_stream_type>(*single_ssl_stream, ssl_context);
                    wss = std::make_unique<websocket_stream_double_ssl_type>(*double_ssl_stream);
#endif
                } else {
#ifdef _AWSIOT_TUNNELING_NO_SSL
                    wss = std::make_unique<websocket_stream_type>(socket);
#else
                    single_ssl_stream = std::make_shared<single_ssl_stream_type>(socket, ssl_context);
                    wss = std::make_unique<websocket_stream_single_ssl_type>(*single_ssl_stream);
#endif
                }
            }

            void WebSocketStream::async_teardown(const boost::beast::role_type &role, const BoostCallbackFunc &handler) {
                if (localproxyConfig.is_web_proxy_using_tls) {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_teardown for type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
                    return boost::beast::async_teardown(
                            role,
                            boost::get<unique_ptr<WEB_PROXY_WITH_TLS_TYPE>>(wss)->next_layer(),
                            handler);
                } else {
                    BOOST_LOG_SEV(*log, trace) << "Calling async_teardown for type: "
                                               << WEB_PROXY_NO_TLS_TYPE_NAME;
#ifdef _AWSIOT_TUNNELING_NO_SSL
                    return boost::beast::websocket::async_teardown(
#else
                    return boost::beast::async_teardown(
#endif
                            role,
                            boost::get<unique_ptr<WEB_PROXY_NO_TLS_TYPE>>(wss)->next_layer(),
                            handler);
                }
            }

            tcp::socket &WebSocketStream::get_tcp_socket() {
                return socket;
            }

            shared_ptr<single_ssl_stream_type> WebSocketStream::get_web_proxy_ssl_stream() {
                return single_ssl_stream;
            }
        }
    }
}
