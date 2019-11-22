// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <functional>
#include <limits.h>
#include <set>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl/rfc2818_verification.hpp>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/flat_static_buffer.hpp>
#include <boost/endian/conversion.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/sources/severity_feature.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/optional.hpp>
#include <boost/version.hpp>

#include <openssl/opensslv.h>

#include "TcpAdapterProxy.h"
#include "ProxySettings.h"

namespace aws { namespace iot { namespace securedtunneling {
    using boost::asio::io_context;
    using boost::asio::ip::tcp;
    using boost::property_tree::ptree;

    using boost::log::trivial::trace;
    using boost::log::trivial::debug;
    using boost::log::trivial::info;
    using boost::log::trivial::warning;
    using boost::log::trivial::error;
    using boost::log::trivial::fatal;

    char const * const PROXY_MODE_QUERY_PARAM = "local-proxy-mode";
    char const * const ACCESS_TOKEN_HEADER = "access-token";
    char const * const SOURCE_PROXY_MODE = "source";
    char const * const DESTINATION_PROXY_MODE = "destination";
    std::uint16_t const DEFAULT_PROXY_SERVER_PORT = 443;

    std::set<std::uint32_t> MESSAGE_TYPES_REQUIRING_STREAM_ID {
        com::amazonaws::iot::securedtunneling::Message_Type_DATA,
        com::amazonaws::iot::securedtunneling::Message_Type_STREAM_RESET };

    namespace
    {
        char const * get_proxy_mode_string(proxy_mode const mode)
        {
            switch (mode)
            {
            case proxy_mode::SOURCE:
                return SOURCE_PROXY_MODE;
            case proxy_mode::DESTINATION:
                return DESTINATION_PROXY_MODE;
            case proxy_mode::UNKNOWN:
                break;
            }
            throw std::invalid_argument("Cannot convert unknown proxy mode enum value to string");
        }

        inline void invoke_and_clear_handler(std::function<void()> &handler)
        {
            if (handler)
            {
                //Because the handler might set it up a follow on for the same operatio
                //we need to hang onto it, clear it, then invoke it
                auto handler_invoke = handler;
                handler = nullptr;
                handler_invoke();
            }
        }

        inline std::tuple<std::size_t, std::size_t> get_access_token_range(std::string const &request)
        {
            std::size_t start = 0;
            std::size_t end = 0;

            start = request.find(ACCESS_TOKEN_HEADER);
            if (start == std::string::npos)
            {
                throw std::logic_error("Cannot find access token header to filter for logging");
            }
            start += std::char_traits<char>::length(ACCESS_TOKEN_HEADER) + 2;
            end = request.find("\n", start);
            end = end == std::string::npos ? request.length() - 1 : end;
            return std::make_tuple(start, end);
        }

        std::string get_token_filtered_request(boost::beast::websocket::request_type const &request)
        {
            std::ostringstream request_stream;
            request_stream << request;
            std::string unfiltered_request_string = request_stream.str(); 
            std::tuple<std::size_t, std::size_t> token_filter_range = get_access_token_range(unfiltered_request_string);
            return (boost::format("%1%***ACCESS_TOKEN_REMOVED***%2%") %
                unfiltered_request_string.substr(0, std::get<0>(token_filter_range)) %
                unfiltered_request_string.substr(std::get<1>(token_filter_range))).str();
        }

        void basic_retry_execute(logger &log, std::shared_ptr<basic_retry_config> retry, std::function<void()> failure)
        {
            if (retry->count == -1 || retry->count > 0)
            {
                if (retry->count > 0) --retry->count;
                retry->timer.expires_after(retry->delay);
                retry->timer.async_wait([&log, retry](boost::system::error_code const &ec)
                {
                    if (ec)
                    {   //log error, but still perform the operation
                        BOOST_LOG_SEV(log, error) << "Error waiting for retry timer: " << ec.message();
                    }
                    retry->operation();
                });
            }
            else
            {
                failure();
            }
        }

        void do_ping_data(tcp_adapter_context &tac, boost::beast::websocket::ping_data &pd)
        {
            std::ostringstream strm_ping_time;
            strm_ping_time << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            pd.assign(strm_ping_time.str());
        }
    }

    tcp_adapter_proxy::tcp_adapter_proxy(ptree const &settings, adapter_proxy_config const &config) :
        settings{ settings },
        adapter_config{ config },
        outgoing_message_buffer{ GET_SETTING(settings, MAX_DATA_FRAME_SIZE) },
        incoming_message_buffer{ GET_SETTING(settings, WEB_SOCKET_READ_BUFFER_SIZE) },
        message_parse_buffer{ GET_SETTING(settings, MESSAGE_MAX_SIZE) },
        tcp_write_buffer{ GET_SETTING(settings, TCP_WRITE_BUFFER_SIZE) },
        tcp_read_buffer{ GET_SETTING(settings, TCP_READ_BUFFER_SIZE) },
        web_socket_data_write_buffer{ GET_SETTING(settings, WEB_SOCKET_WRITE_BUFFER_SIZE) }
    { }

    tcp_adapter_proxy::~tcp_adapter_proxy()
    { }

    void tcp_adapter_proxy::run_proxy()
    {
        BOOST_LOG_SEV(log, info) << "Starting proxy in " << get_proxy_mode_string(adapter_config.mode) << " mode";
        while (true)
        {   //continuous retry until normal return from io_ctx.run()
            tcp_adapter_context tac{ adapter_config, settings };
            try
            {
                setup_web_socket(tac);
                tac.io_ctx.run();
                return;
            }
            catch (proxy_exception &e)
            {
                if (GET_SETTING(settings, WEB_SOCKET_DATA_ERROR_RETRY))
                {
                    BOOST_LOG_SEV(log, error) << "Error from io_ctx::run(): " << e.what();
                }
                else
                {
                    throw e;
                }
                BOOST_LOG_SEV(log, error) << "Failed web socket session ID: " << tac.wss_response["channel-id"].to_string();
            }
        }
    }

    void tcp_adapter_proxy::setup_tcp_socket(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Setting up tcp socket...";
        if (adapter_config.mode == proxy_mode::DESTINATION)
        {
            after_setup_tcp_socket = std::bind(&tcp_adapter_proxy::async_setup_bidirectional_data_transfers, this, std::ref(tac));
            on_recieve_stream_start = std::bind(&tcp_adapter_proxy::async_setup_dest_tcp_socket, this, std::ref(tac));
            tac.stream_id = -1;
            async_web_socket_read_until_stream_start(tac);
        }
        else
        {
            after_send_message = std::bind(&tcp_adapter_proxy::async_setup_bidirectional_data_transfers, this, std::ref(tac));
            after_setup_tcp_socket = std::bind(&tcp_adapter_proxy::async_send_stream_start, this, std::ref(tac));
            async_setup_source_tcp_socket(tac);
        }
    }

    void tcp_adapter_proxy::setup_web_socket(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Setting up web socket...";
        after_setup_web_socket = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac));
        async_setup_web_socket(tac);
    }

    void tcp_adapter_proxy::tcp_socket_reset(tcp_adapter_context &tac, std::function<void()> then_what)
    {
        if (!tac.tcp_socket.is_open())
        {
            BOOST_LOG_SEV(log, debug) << "Ignoring explicit reset because TCP socket is already closed";
            return;
        }
        BOOST_LOG_SEV(log, debug) << "Handling explicit reset by closing TCP";
        //shut down read end of tcp
        tac.tcp_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_receive);
        std::shared_ptr<bool> web_socket_write_buffer_drain_complete = std::make_shared<bool>(false);
        std::shared_ptr<bool> tcp_write_buffer_drain_complete = std::make_shared<bool>(false);

        //ignore next tcp read error if a read operation is happening when TCP gets closed
        on_tcp_error =
            [this](boost::system::error_code const &ec)
            {
                //We *may* want to confirm that the error code is actually operation canceled or aborted due to TCP close as
                //any unexpected errors in this situation perhaps signals something else. But we may want to ignore other errors
                //anyways given we know we are closing the tcp socket to create a new one anyways
                BOOST_LOG_SEV(this->log, trace) << "Received expected TCP socket error and ignoring it. TCP socket read loop has been canceled";
            };
        //ignore next incoming message
        on_data_message = std::bind(&tcp_adapter_proxy::ignore_message_and_stop, this, std::ref(tac), std::placeholders::_1);
        on_control_message = std::bind(&tcp_adapter_proxy::ignore_message_and_stop, this, std::ref(tac), std::placeholders::_1);
        on_web_socket_write_buffer_drain_complete = 
            [this, web_socket_write_buffer_drain_complete, tcp_write_buffer_drain_complete, then_what, &tac]()
            {
                BOOST_LOG_SEV(this->log, trace) << "Post-reset web socket drain complete";
                *web_socket_write_buffer_drain_complete = true;
                if (*tcp_write_buffer_drain_complete)
                {
                    BOOST_LOG_SEV(this->log, trace) << "Both socket drains complete.";
                    then_what();
                }
            };

        //after drain write to tcp
        on_tcp_write_buffer_drain_complete =
            [this, web_socket_write_buffer_drain_complete, tcp_write_buffer_drain_complete, then_what, &tac]()
            {
                BOOST_LOG_SEV(this->log, trace) << "Post-reset TCP drain complete. Closing TCP socket";
                BOOST_LOG_SEV(this->log, info) << "Disconnected from: " << tac.tcp_socket.remote_endpoint();
                tac.tcp_socket.close(); //now close it all
                *tcp_write_buffer_drain_complete = true;
                if (*web_socket_write_buffer_drain_complete)
                {
                    BOOST_LOG_SEV(this->log, trace) << "Both socket drains complete. Setting up TCP socket again";
                    then_what();
                }
            };
        async_setup_web_socket_write_buffer_drain(tac);
        async_tcp_write_buffer_drain(tac);
    }

    void tcp_adapter_proxy::web_socket_close_and_stop(tcp_adapter_context &tac)
    {
        if (tac.wss)
        {
            if (tac.wss->is_open())
            {
                //clean shutdown
                boost::beast::websocket::async_teardown(boost::beast::websocket::role_type::client, tac.wss->next_layer(), [&tac, this](boost::system::error_code const &ec)
                {
                    if (ec)
                    {
                        BOOST_LOG_SEV(this->log, error) << "Teardown of web socket connection not successful: " << ec.message();
                    }
                    //close tcp  if open either way
                    if (tac.wss->lowest_layer().is_open())
                    {
                        tac.wss->lowest_layer().close();
                    }
                    tac.io_ctx.stop();
                });
            }
            else if (tac.wss->lowest_layer().is_open())
            {
                tac.wss->lowest_layer().close();
                tac.io_ctx.stop();
            }
            else
            {
                tac.io_ctx.stop();
            }
        }
        tac.io_ctx.stop();
    }

    void tcp_adapter_proxy::tcp_socket_error(tcp_adapter_context &tac, boost::system::error_code const &ec)
    {
        BOOST_LOG_SEV(log, debug) << "Handling tcp socket error: " << ec.message();

        BOOST_LOG_SEV(this->log, info) << "Disconnected from: " << tac.tcp_socket.remote_endpoint();
        tac.tcp_socket.close(); //might be redundant
        tcp_write_buffer.consume(tcp_write_buffer.max_size());

        //stop web socket read loop for the time being
        on_data_message = std::bind(&tcp_adapter_proxy::ignore_message_and_stop, this, std::ref(tac), std::placeholders::_1);
        on_control_message = std::bind(&tcp_adapter_proxy::ignore_message_and_stop, this, std::ref(tac), std::placeholders::_1);

        on_web_socket_write_buffer_drain_complete = [&]()
        {
            after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac));
            async_send_stream_reset(tac, tac.stream_id);
        };
        async_setup_web_socket_write_buffer_drain(tac);
    }

    void tcp_adapter_proxy::async_send_message(tcp_adapter_context &tac, message const &message)
    {
        //calculate total frame size
        std::size_t const frame_size = static_cast<std::size_t>(message.ByteSizeLong()) +
            GET_SETTING(settings, DATA_LENGTH_SIZE);
        //get pointers to where data length and protobuf msg will be written to
        void *frame_data = outgoing_message_buffer.prepare(frame_size).data();
        void *frame_data_msg_offset = reinterpret_cast<void *>(reinterpret_cast<std::uint8_t *>(frame_data) 
            + GET_SETTING(settings, DATA_LENGTH_SIZE));
        //get the protobuf data length and wirte it to start the frame
        std::uint16_t data_length = static_cast<std::uint16_t>(message.ByteSizeLong());
        *reinterpret_cast<std::uint16_t *>(frame_data) = boost::endian::native_to_big(data_length);
        //write the protobuf msg into the buffer next
        message.SerializeToArray(frame_data_msg_offset, static_cast<int>(GET_SETTING(settings, MESSAGE_MAX_SIZE)));
        //commit the entire frame to the outgoing message buffer
        outgoing_message_buffer.commit(frame_size);

        tac.is_web_socket_writing = true;
        tac.wss->async_write(outgoing_message_buffer.data(), [&](boost::system::error_code const &ec, std::size_t const bytes_sent)
        {
            tac.is_web_socket_writing = false;
            //clear outgoing buffer entirely. we do not need to know how much of it was used
            this->outgoing_message_buffer.consume(this->outgoing_message_buffer.max_size());
            if (ec)
            {
                throw proxy_exception("Error sending web socket message", ec);
            }
            else
            {
                BOOST_LOG_SEV(log, trace) << "Sent " << bytes_sent << " bytes over websocket";
                invoke_and_clear_handler(after_send_message);
            }
        });
    }

    void tcp_adapter_proxy::async_send_stream_start(tcp_adapter_context &tac)
    {
        using namespace com::amazonaws::iot::securedtunneling;

        if (tac.stream_id == -1)
        {
            tac.stream_id = 1;
        }
        else
        {
            if (tac.stream_id == std::numeric_limits<decltype(tac.stream_id)>::max())
            {
                tac.stream_id = 0;
            }
            ++tac.stream_id;
        }
        BOOST_LOG_SEV(log, debug) << "Setting new stream ID to: " << tac.stream_id;
        outgoing_message.set_type(Message_Type_STREAM_START);
        outgoing_message.set_streamid(tac.stream_id);
        outgoing_message.set_ignorable(false);
        outgoing_message.clear_payload();

        async_send_message(tac, outgoing_message);
    }

    void tcp_adapter_proxy::async_send_stream_reset(tcp_adapter_context &tac, std::int32_t stream_id)
    {
        using namespace com::amazonaws::iot::securedtunneling;
        outgoing_message.set_type(Message_Type_STREAM_RESET);
        outgoing_message.set_streamid(stream_id);
        outgoing_message.set_ignorable(false);
        outgoing_message.clear_payload();

        async_send_message(tac, outgoing_message);
    }

    void tcp_adapter_proxy::async_setup_bidirectional_data_transfers(tcp_adapter_context &tac)
    {
        //this is a common 'successful' starting state for both source and destination mode, so it's
        //a good place to reset retry counts
        BOOST_LOG_SEV(log, trace) << "Setting up bi-directional data transfer with stream_id: " << tac.stream_id;
        clear_buffers();
        on_tcp_error = nullptr;
        on_control_message = std::bind(&tcp_adapter_proxy::handle_control_message_data_transfer, this, std::ref(tac), std::placeholders::_1);
        on_data_message = std::bind(&tcp_adapter_proxy::forward_data_message_to_tcp_write, this, std::ref(tac), std::placeholders::_1);
        this->async_web_socket_read_loop(tac);
        this->async_tcp_socket_read_loop(tac);
    }

    void tcp_adapter_proxy::async_web_socket_read_until_stream_start(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Waiting for stream start...";
        on_control_message = std::bind(&tcp_adapter_proxy::async_wait_for_stream_start, this, std::ref(tac), std::placeholders::_1);
        on_data_message = std::bind(&tcp_adapter_proxy::ignore_message, this, std::ref(tac), std::placeholders::_1);
        this->async_web_socket_read_loop(tac);
    }

    void tcp_adapter_proxy::handle_web_socket_control_message(tcp_adapter_context &tac, boost::beast::websocket::frame_type ws_message_type, boost::beast::string_view payload)
    {
#ifdef DEBUG
        BOOST_LOG_SEV(log, debug) << "Control message recieved enum(close=0, ping=1, pong=2): " << static_cast<std::uint32_t>(ws_message_type);
#endif
        //may be used in response
        boost::beast::websocket::ping_data pd{ payload };
        long long now_millis = 0;
        long long pong_millis = 0;
        switch (ws_message_type)
        {
        case boost::beast::websocket::frame_type::close:
            //behavior of TCP socket reset will drain both web socket and TCP buffers, then perform a follow on action
            //--in this case, actually close
            BOOST_LOG_SEV(log, info) << "Web socket close recieved. Code: " << tac.wss->reason().code << "; Reason: " << tac.wss->reason().reason;
            tcp_socket_reset(tac, std::bind(&tcp_adapter_proxy::web_socket_close_and_stop, this, std::ref(tac)));
            break;
        case boost::beast::websocket::frame_type::ping:
#ifdef DEBUG
            BOOST_LOG_SEV(log, debug) << "Websocket ping recieved: " << pd;
#endif
            tac.wss->async_pong(pd, [&](boost::system::error_code const &ec)
            {
                if (ec)
                {
                    BOOST_LOG_SEV(log, warning) << "Pong reply failed to send to server " << ec.message();
                }
                //pong reply succeeded
            });
            break;
        case boost::beast::websocket::frame_type::pong:
            now_millis = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            pong_millis = boost::lexical_cast<decltype(now_millis)>(pd.data(), pd.length());
            BOOST_LOG_SEV(log, trace) << "Pong reply latency: " << (now_millis - pong_millis) << " ms";
            break;
        default:
            BOOST_LOG_SEV(log, warning) << "Received unknown control frame type(close=0, ping, pong): " << static_cast<std::uint32_t>(ws_message_type);
        }
    }

    void tcp_adapter_proxy::async_ping_handler_loop(tcp_adapter_context &tac,
        std::shared_ptr<boost::beast::websocket::ping_data> ping_data,
        std::shared_ptr<std::chrono::milliseconds> ping_period,
        std::shared_ptr<boost::asio::steady_timer> ping_timer,
        boost::system::error_code const &ping_ec)
    {
        if (ping_ec)
        {   //consider this an ignorable error
            BOOST_LOG_SEV(log, error) << "Failed to send websocket ping: " << ping_ec.message();
        }
#ifdef DEBUG
        else
        {
            BOOST_LOG_SEV(log, trace) << "Successfully sent websocket ping";
        }
#endif // DEBUG
        ping_timer->expires_after(*ping_period);
        ping_timer->async_wait([this, &tac, ping_data, ping_period, ping_timer](boost::system::error_code const &wait_ec)
        {
            if (wait_ec)
            {
                BOOST_LOG_SEV(this->log, error) << "Failed on wait timer for web socket ping: " << wait_ec.message();
            }
            do_ping_data(tac, *ping_data);
            BOOST_LOG_SEV(log, trace) << "Sent ping data: " << ping_data->data();
            tac.wss->async_ping(*ping_data, std::bind(&tcp_adapter_proxy::async_ping_handler_loop, this, std::ref(tac), ping_data, ping_period, ping_timer, std::placeholders::_1));
        });
    }

    //setup async web socket, and as soon as connection is up, setup async ping schedule
    void tcp_adapter_proxy::async_setup_web_socket(tcp_adapter_context &tac)
    {
        std::shared_ptr<basic_retry_config> retry_config =
            std::make_shared<basic_retry_config>(tac.io_ctx,
                GET_SETTING(settings, WEB_SOCKET_CONNECT_RETRY_COUNT),
                GET_SETTING(settings, WEB_SOCKET_CONNECT_RETRY_DELAY_MS),
                std::bind(&tcp_adapter_proxy::async_setup_web_socket, this, std::ref(tac)));

        if (tac.wss && tac.wss->is_open())
        {
            BOOST_LOG_SEV(log, info) << "Web socket stream already open. Continuing to use existing connection";
            if (after_setup_web_socket)
            {
                invoke_and_clear_handler(after_setup_web_socket);
            }
            return;
        }
        if (tac.wss && tac.wss->lowest_layer().is_open())
        {   //if prior tcp connection exists, close that as well (retry everything)
            tac.wss->lowest_layer().close();
        }
#ifdef _AWSIOT_TUNNELING_NO_SSL
        tac.wss = std::make_shared<web_socket_stream>(tac.io_ctx);
#else
        boost::system::error_code ec;
        tac.ssl_ctx.set_default_verify_paths(ec);
        if (ec)
        {
            BOOST_LOG_SEV(log, warning) << "Could not set system default OpenSSL verification path: " << ec.message();
        }
        if (tac.adapter_config.additional_ssl_verify_path.has_value())
        {
            tac.ssl_ctx.add_verify_path(tac.adapter_config.additional_ssl_verify_path.get(), ec);
            if (ec)
            {
                BOOST_LOG_SEV(log, fatal) << "Could not set additional OpenSSL verification path ("
                    << tac.adapter_config.additional_ssl_verify_path.get() << "): " << ec.message();
                throw std::runtime_error((boost::format("Could not set additional OpenSSL verification path(%1%) - %2%")
                        % tac.adapter_config.additional_ssl_verify_path.get()
                        % ec.message()).str());
            }
        }
        tac.wss = std::make_shared<web_socket_stream>(tac.io_ctx, tac.ssl_ctx);
#endif
        tac.wss->control_callback(std::bind(&tcp_adapter_proxy::handle_web_socket_control_message, this, std::ref(tac), std::placeholders::_1, std::placeholders::_2));
        
        static std::string user_agent_string = (boost::format("localproxy %1% %2%-bit/boost-%3%.%4%.%5%/openssl-%6%.%7%.%8%/protobuf-%9%")
            % BOOST_PLATFORM % (sizeof(void*)*8)
            % (BOOST_VERSION / 100000) % ((BOOST_VERSION / 100) % 1000) % (BOOST_VERSION % 100)
            % (OPENSSL_VERSION_NUMBER >> 28) % ((OPENSSL_VERSION_NUMBER >> 20) & 0xF) % ((OPENSSL_VERSION_NUMBER >> 12) & 0xF)
            % google::protobuf::internal::VersionString(GOOGLE_PROTOBUF_VERSION) ).str();
        
        //the actual work of this function starts here
        BOOST_LOG_SEV(log, info) << "Attempting to establish web socket connection with endpoint wss://" << tac.adapter_config.proxy_host << ":" << tac.adapter_config.proxy_port;
        //start first async handler which chains into adding the rest
        BOOST_LOG_SEV(log, trace) << "Resolving proxy host: " << tac.adapter_config.proxy_host;
        tac.resolver.async_resolve(tac.adapter_config.proxy_host, boost::lexical_cast<std::string>(tac.adapter_config.proxy_port), [=, &tac](boost::system::error_code const &ec, tcp::resolver::results_type results)
        {
            if (ec)
            {
                BOOST_LOG_SEV(log, error) << (boost::format("Could not resolve DNS hostname of proxy host: %1% - %2%") % tac.adapter_config.proxy_host % ec.message()).str();
                basic_retry_execute(log, retry_config, [&]() { std::bind(&tcp_adapter_proxy::web_socket_close_and_stop, this, std::ref(tac)); });
            }
            else
            {
                BOOST_LOG_SEV(log, debug) << "Resolved proxy server IP: " << results->endpoint().address();
                //next connect tcp
                tac.wss->lowest_layer().async_connect(*results.begin(), [=, &tac](boost::system::error_code const &ec)
                {
                    if (ec)
                    {
                        BOOST_LOG_SEV(log, error) << (boost::format("Could not connect to proxy server: %1%") % ec.message()).str();
                        basic_retry_execute(log, retry_config, [&]() { std::bind(&tcp_adapter_proxy::web_socket_close_and_stop, this, std::ref(tac)); });
                    }
                    else
                    {
                        BOOST_LOG_SEV(log, debug) << "Connected successfully with proxy server";
                        boost::asio::socket_base::receive_buffer_size const recv_buffer_size(static_cast<int>(GET_SETTING(settings, WEB_SOCKET_MAX_FRAME_SIZE)));
                        boost::asio::socket_base::send_buffer_size const send_buffer_size_option(static_cast<int>(GET_SETTING(settings, WEB_SOCKET_MAX_FRAME_SIZE)));
                        tac.wss->lowest_layer().set_option(recv_buffer_size);
                        tac.wss->lowest_layer().set_option(send_buffer_size_option);

#ifndef _AWSIOT_TUNNELING_NO_SSL
                        //conditional operation based on
                        BOOST_LOG_SEV(log, trace) << "Performing SSL handshake with proxy server";
                        if (!adapter_config.no_ssl_host_verify)
                        {
                            tac.wss->next_layer().set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
                            tac.wss->next_layer().set_verify_callback(boost::asio::ssl::rfc2818_verification(tac.adapter_config.proxy_host));
                        }
                        else
                        {
                            BOOST_LOG_SEV(log, debug) << "SSL host verification is off";
                        }
                        //next ssl handshake
                        tac.wss->next_layer().async_handshake(boost::asio::ssl::stream_base::client, [=, &tac](boost::system::error_code const &ec)
                        {
                            if (ec)
                            {
                                BOOST_LOG_SEV(log, error) << (boost::format("Could not perform SSL handshake with proxy server: %1%") % ec.message()).str();
                                basic_retry_execute(log, retry_config, [&]() { std::bind(&tcp_adapter_proxy::web_socket_close_and_stop, this, std::ref(tac)); });
                            }
                            else
                            {
                                BOOST_LOG_SEV(log, debug) << "Successfully completed SSL handshake with proxy server";
#endif
                                BOOST_LOG_SEV(log, trace) << "Performing websocket handshake with proxy server";
                                //next do web socket upgrade - add two custom headers

                                tac.wss->async_handshake_ex(tac.wss_response, tac.adapter_config.proxy_host.c_str(),
                                    (boost::format("/tunnel?%1%=%2%")%PROXY_MODE_QUERY_PARAM % get_proxy_mode_string(tac.adapter_config.mode)).str(),
                                    [&](boost::beast::websocket::request_type &request)
                                    {
                                        request.set(boost::beast::http::field::sec_websocket_protocol, GET_SETTING(settings, WEB_SOCKET_SUBPROTOCOL));
                                        request.set(ACCESS_TOKEN_HEADER, tac.adapter_config.access_token.c_str());
                                        request.set(boost::beast::http::field::user_agent, user_agent_string);
                                        BOOST_LOG_SEV(log, trace) << "Web socket ugprade request(*not entirely final):\n" << get_token_filtered_request(request);
                                    },
                                    [=, &tac](boost::system::error_code const &ec)
                                    {
                                        BOOST_LOG_SEV(log, trace) << "Web socket upgrade response:\n" << tac.wss_response;
                                        if (ec)
                                        {
                                            BOOST_LOG_SEV(log, error) << (boost::format("Proxy server rejected web socket upgrade request: (HTTP/%4%.%5% %1% %2%) \"%3%\"")
                                                % tac.wss_response.result_int() % tac.wss_response.reason() % boost::trim_copy(tac.wss_response.body())
                                                % (tac.wss_response.version() / 10) % (tac.wss_response.version() % 10)).str();    //form HTTP version
                                            if (tac.wss_response.result_int() >= 500 && tac.wss_response.result_int() < 600)
                                            {   //retry these, otherwise fail and close
                                                basic_retry_execute(log, retry_config, [&]() { std::bind(&tcp_adapter_proxy::web_socket_close_and_stop, this, std::ref(tac)); });
                                            }
                                            else
                                            {
                                                web_socket_close_and_stop(tac);
                                            }
                                        }
                                        else
                                        {   //put web socket in binary mode
                                            tac.wss->binary(true);
                                            tac.wss->auto_fragment(true);
                                            //output this first because it'll be necessary to have this if any further errors need support/debugging
                                            BOOST_LOG_SEV(log, info) << "Web socket session ID: " << tac.wss_response["channel-id"].to_string();
                                            if (!tac.wss_response.count(boost::beast::http::field::sec_websocket_protocol))
                                            {
                                                throw proxy_exception("No websocket subprotocol returned from proxy server!");
                                            }
                                            BOOST_LOG_SEV(log, debug) << "Web socket subprotocol selected: " << tac.wss_response[boost::beast::http::field::sec_websocket_protocol].to_string();
                                            BOOST_LOG_SEV(log, info) << "Successfully established websocket connection with proxy server: wss://" << tac.adapter_config.proxy_host << ":" << tac.adapter_config.proxy_port;

                                            std::shared_ptr<boost::beast::websocket::ping_data> ping_data = std::make_shared<boost::beast::websocket::ping_data>();
                                            do_ping_data(tac, *ping_data);
                                            std::shared_ptr<std::chrono::milliseconds> ping_period =
                                                std::make_shared<std::chrono::milliseconds>(GET_SETTING(settings, WEB_SOCKET_PING_PERIOD_MS));
                                            std::shared_ptr<boost::asio::steady_timer> ping_timer = std::make_shared<boost::asio::steady_timer>(tac.io_ctx);

                                            BOOST_LOG_SEV(log, debug) << "Seting up web socket pings for every " << ping_period->count() << " milliseconds";

                                            tac.wss->async_ping(*ping_data, std::bind(&tcp_adapter_proxy::async_ping_handler_loop, this, std::ref(tac), ping_data, ping_period, ping_timer, std::placeholders::_1));

                                            //run whatever we are configured to do after setting up ping
                                            if (after_setup_web_socket)
                                            {
                                                after_setup_web_socket();
                                            }
                                        }
                                    }
                                );
#ifndef _AWSIOT_TUNNELING_NO_SSL
                            }
                        });
#endif
                    }
                });
            }
        });
    }

    void tcp_adapter_proxy::async_tcp_socket_read_loop(tcp_adapter_context & tac)
    {
        if (tac.is_tcp_socket_reading)
        {
#ifdef DEBUG
            BOOST_LOG_SEV(log, debug) << "Not starting TCP read loop";
#endif
        }
        else if (wss_has_enough_write_buffer_space(tac))
        {
            //max bytes to read not to execeed either the read buffer capacity, or the available space in the web socket write buffer
            std::size_t max_bytes_to_read = std::min(web_socket_data_write_buffer.max_size() - web_socket_data_write_buffer.size(), tcp_read_buffer.max_size());
            tac.is_tcp_socket_reading = true;
            tac.tcp_socket.async_read_some(tcp_read_buffer.prepare(max_bytes_to_read),
                [&](boost::system::error_code const &ec, std::size_t const bytes_read)
                {
                    tac.is_tcp_socket_reading = false;
                    if (ec)
                    {
                        if (on_tcp_error)
                        {
                            on_tcp_error(ec);
                            on_tcp_error = nullptr;
                        }
                        else
                        {
                            tcp_socket_error(tac, ec);
                        }
                    }
                    else
                    {
                        tcp_read_buffer.commit(bytes_read); //move bytes written from output to input sequence
#ifdef DEBUG
                        BOOST_LOG_SEV(log, trace) << "TCP socket read " << bytes_read << " bytes";
#endif
                        //copy over to web socket write buffer
                        std::size_t bytes_copied = boost::asio::buffer_copy(web_socket_data_write_buffer.prepare(bytes_read), tcp_read_buffer.data(), bytes_read);
                        tcp_read_buffer.consume(bytes_read);    //now remove bytes from input sequence
                        web_socket_data_write_buffer.commit(bytes_copied);

                        if (wss_has_enough_write_buffer_space(tac))
                        {
                            async_tcp_socket_read_loop(tac);
                        }
                        else
                        {
                            BOOST_LOG_SEV(log, debug) << "No more space in web socket write buffer or tcp socket is closed. Stopping tcp read loop";
                        }
                        if (web_socket_data_write_buffer.size() > 0) {
                                async_setup_web_socket_write_buffer_drain(tac);
                            }
                        }
                    });
            }
            else
            {
    #ifdef DEBUG
                BOOST_LOG_SEV(log, debug) << "TCP socket read loop started while web socket write buffer is already full";
    #endif
            }
        }

        bool tcp_adapter_proxy::ignore_message(tcp_adapter_context &tac, message const &message)
        {
    #ifdef DEBUG
            BOOST_LOG_SEV(log, trace) << "Ignoring data message";
    #endif
            return true;
        }

        bool tcp_adapter_proxy::ignore_message_and_stop(tcp_adapter_context &tac, message const &message)
        {
    #ifdef DEBUG
            BOOST_LOG_SEV(log, trace) << "Ignoring data message and stopping web socket read loop";
    #endif
            return false;
        }

        bool tcp_adapter_proxy::async_wait_for_stream_start(tcp_adapter_context &tac, message const &message)
        {
            using namespace com::amazonaws::iot::securedtunneling;

            switch (message.type())
            {
            case Message_Type_SESSION_RESET:
    #ifdef DEBUG
                BOOST_LOG_SEV(log, trace) << "Session reset recieved";
    #endif
                return true;
            case Message_Type_STREAM_RESET:
                //while waiting for stream start (destination mode implied), no TCP socket is present so these
                //messages are no-op
    #ifdef DEBUG
                BOOST_LOG_SEV(log, trace) << "Stream reset recieved";
    #endif
                return true;
            case Message_Type_STREAM_START:
    #ifdef DEBUG
                BOOST_LOG_SEV(log, debug) << "Stream start recieved";
    #endif
                tac.stream_id = static_cast<std::int32_t>(message.streamid());
                if (!tac.stream_id)
                {
                    throw proxy_exception("No stream ID set for stream start message!");
                }
                //now that we have stream start, do what's next
                invoke_and_clear_handler(on_recieve_stream_start);
                return false;
            case Message_Type_DATA:    //handling the following cases alleviates clang compiler warnings
                throw std::logic_error("Data message recieved in control message handler");
            case Message_Type_UNKNOWN:
            case Message_Type_Message_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
            case Message_Type_Message_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
                //setup #define DEBUG to also be matched with link to protobuf, and without it link to protobuf-lite
                //throw proxy_exception((boost::format("Unexpected message type recieved during control message handling during data transfer: %1%") % External_MessageType_Name(message.messagetype())).str());
                throw proxy_exception((boost::format("Unexpected message type recieved while waiting for stream start: %1%") % message.type()).str());
            default:
                if (message.ignorable()) {  //other message types are safe to ignore
                    return true;
                }
                throw std::logic_error((boost::format("Unrecognized message type recieved while waiting for stream start: %1%") % message.type()).str());
            }
        }

        bool tcp_adapter_proxy::handle_control_message_data_transfer(tcp_adapter_context &tac, message const &message)
        {
            using namespace com::amazonaws::iot::securedtunneling;
            BOOST_LOG_SEV(log, trace) << "Handling control message...";

            switch (message.type())
            {
            case Message_Type_SESSION_RESET:
    #ifdef DEBUG
                BOOST_LOG_SEV(log, trace) << "Session reset recieved";
    #endif
                //validation has already been done on stream_id before calling this, so we can just listen
                tcp_socket_reset(tac, std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac)));
                return true;   //indicates we should stop reading from the web socket after processing this message
            case Message_Type_STREAM_RESET:
    #ifdef DEBUG
                BOOST_LOG_SEV(log, trace) << "Stream reset recieved";
    #endif
                //validation has already been done on stream_id before calling this, so we can just listen
                tcp_socket_reset(tac, std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac)));
                return true;   //indicates we should stop reading from the web socket after processing this message
            case Message_Type_STREAM_START: //could verify that this is a destination mode local proxy. Source mode shouldn't be recieving stream start
                BOOST_LOG_SEV(log, warning) << "Stream start recieved during data transfer";
                tcp_socket_reset(tac, std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac)));
                tac.stream_id = static_cast<std::int32_t>(message.streamid());
                if (!tac.stream_id)
                {
                    throw proxy_exception("No stream ID set for stream start message!");
                }
                return true;
            case Message_Type_DATA:   //handling the following cases alleviates clang compiler warnings
                throw std::logic_error("Data message recieved in control message handler");
            case Message_Type_UNKNOWN:
            case Message_Type_Message_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
            case Message_Type_Message_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
                //message-lite in C++ (gcc) generates a far far smaller executable. Likely a gcc issue since msvc generates reasonably sized executable either way
                //throw proxy_exception((boost::format("Unexpected message type recieved during control message handling during data transfer: %1%") % External_MessageType_Name(message.messagetype())).str());
                throw proxy_exception((boost::format("Unexpected message type recieved during control message handling during data transfer: %1%") % message.type()).str());
            default:
                if (message.ignorable()) {  //this flag lets us know we can drop it
                    return true;
                }
                throw std::logic_error((boost::format("Unrecognized message type recieved during control message handling during data transfer: %1%") % message.type()).str());
            }
        }

        //forwards data messages to tcp write buffer in tcp_adapter_context
        bool tcp_adapter_proxy::forward_data_message_to_tcp_write(tcp_adapter_context &tac, message const &message)
        {
            //capture write buffer size (we care if it is empty, that means we will need to trigger a drain)
            size_t write_buffer_size_before = tcp_write_buffer.size();
            //then copy it to the tcp write buffer
            //memcpy(tac.tcp_write_buffer.prepare(message.data().size()), message.data().c_str(), message.data().size());
            boost::asio::buffer_copy(tcp_write_buffer.prepare(message.payload().size()), boost::asio::buffer(message.payload()));
            tcp_write_buffer.commit(message.payload().size());

            //if the write buffer input size before we wrote the bytes we just did was 0
            //then we need to trigger a drain on it.
            if (write_buffer_size_before == 0)
            {
                async_tcp_write_buffer_drain(tac);
            }

            if (tcp_has_enough_write_buffer_space(tac))
            {
                return true;
            }
            else //tcp write buffer is full, instruct caller to not perform subsequent read
            {
                //seeing this output message means we are reading data in from web socket faster than
                //we are outputting and draining to TCP writes
                BOOST_LOG_SEV(log, debug) << "TCP write buffer full. Stopping web socket read loop";
                return false;
            }
        }

        void tcp_adapter_proxy::on_web_socket_read(tcp_adapter_context &tac, boost::system::error_code const &ec, size_t bytes_read)
        {
            tac.is_web_socket_reading = false;
            bool continue_reading = false;
            if (ec)
            {
                throw proxy_exception("Websocket read error", ec);
            }
    #ifdef DEBUG
            BOOST_LOG_SEV(log, trace) << "Websocket read " << bytes_read << " bytes";
    #endif

            //process buffers contents (work through completed messages)
            continue_reading = process_incoming_websocket_buffer(tac, incoming_message_buffer);

            if (continue_reading)
            {   //go through the entry function to prevent two async reads
                //this will be attempted in reset/read error scenarios
                async_web_socket_read_loop(tac);
            }
            else
            {
                BOOST_LOG_SEV(log, debug) << "Web socket read loop stopped";
            }
        }

        bool tcp_adapter_proxy::process_incoming_websocket_buffer(tcp_adapter_context &tac, boost::beast::multi_buffer &message_buffer)
        {
            using namespace com::amazonaws::iot::securedtunneling;
            bool continue_reading = true;

            size_t const data_length_size = GET_SETTING(settings, DATA_LENGTH_SIZE);
            boost::beast::flat_buffer data_length_buffer{ data_length_size };
            //is there enough data to even specify a data length?
            while (message_buffer.size() >= data_length_size && continue_reading)
            {
                boost::asio::buffer_copy(data_length_buffer.prepare(data_length_size), message_buffer.data(), data_length_size);
                uint16_t data_length = boost::endian::big_to_native(*reinterpret_cast<std::uint16_t const *>(data_length_buffer.data().data()));
                //is the entire message in the buffer yet?
                if (message_buffer.size() >= (data_length + data_length_size))
                {
                    //consume the length since we've already read it
                    message_buffer.consume(data_length_size);
                    //parse the amount of data specified into a protobuf message
                    bool parsed_successfully = parse_protobuf_and_consume_input(message_buffer, static_cast<size_t>(data_length), incoming_message)
                                                && incoming_message.IsInitialized();
                    if (!parsed_successfully)
                    {
                        //doesn't output actual errors unless debug protobuf library is linked to
                        throw proxy_exception((boost::format("Could not parse web socket binary frame into message: %1%") % incoming_message.InitializationErrorString()).str());
                    }
    #ifdef DEBUG
                    //BOOST_LOG_SEV(log, trace) << "Message recieved:\n" << message.DebugString(); //re-add when linked to protobuf instead of protobuf-lite
                    BOOST_LOG_SEV(log, trace) << "Message parsed successfully";
    #endif
                    if (!is_valid_stream_id(tac, incoming_message))
                    {
                        //drop the message, continue processing web socket messages
                        continue_reading = true;
    #ifdef DEBUG
                        BOOST_LOG_SEV(log, trace) << "Stale message recieved. Dropping";
    #endif
                    }
                    else
                    {
                        //use tac.is_web_socket_reading to hold directive flag on whether
                        //or not we will schedule a follow on async_read after processing
                        //order matters, we intentionally want to process control messages
                        //every time
                        if (incoming_message.type() != Message_Type_DATA)
                        {   //control message recieved
                            continue_reading = on_control_message(incoming_message);
                        }
                        else if (incoming_message.type() == Message_Type_DATA)
                        {
                            continue_reading = on_data_message(incoming_message);
                        }
                    }
                }
                else    //not enough room to read the entire msg, skip
                {
                    BOOST_LOG_SEV(log, trace) << "Not enough data to process complete message. Moving on to next web socket read";
                    break;
                }
            }

            return continue_reading;
        }

        bool tcp_adapter_proxy::parse_protobuf_and_consume_input(boost::beast::multi_buffer &message_buffer, size_t data_length, message &msg)
        {
            //copy into a continguous buffer for simplified protobuf parsing
            message_parse_buffer.consume(message_parse_buffer.size());
            msg.Clear();
            boost::asio::buffer_copy(message_parse_buffer.prepare(data_length), message_buffer.data(), data_length);
            message_buffer.consume(data_length);
            return msg.ParseFromArray(message_parse_buffer.data().data(), static_cast<int>(data_length));
        }

        //setup async web socket repeat loop
        void tcp_adapter_proxy::async_web_socket_read_loop(tcp_adapter_context &tac)
        {
            if (!on_control_message || !on_data_message)
            {
                throw std::logic_error("Cannot run web socket read loop without handlers in place for control messages and data messages");
            }
            if (!tcp_has_enough_write_buffer_space(tac))
            {
    #ifdef DEBUG
                BOOST_LOG_SEV(log, trace) << "Scheduled async web socket read into tcp write buffer and it does not have enough space!";
    #endif
            }
            else if (tac.is_web_socket_reading)
            {   //already reading, don't schedule again
    #ifdef DEBUG
                BOOST_LOG_SEV(log, debug) << "Starting web socket read loop while web socket is already reading. Ignoring...";
    #endif
            }
            else
            {
                tac.is_web_socket_reading = true;
                tac.wss->async_read_some(incoming_message_buffer, incoming_message_buffer.max_size() - incoming_message_buffer.size(),
                                        std::bind(&tcp_adapter_proxy::on_web_socket_read, this, std::ref(tac), std::placeholders::_1, std::placeholders::_2));
            }
        }

        void tcp_adapter_proxy::async_tcp_write_buffer_drain(tcp_adapter_context &tac)
        {
            static std::function<void(boost::system::error_code const &, size_t)> write_done;
            write_done = [&](boost::system::error_code const &ec, size_t bytes_written)
            {
                tac.is_tcp_socket_writing = false;
                if (ec)
                {
                    if (on_tcp_error)
                    {
                        on_tcp_error(ec);
                        on_tcp_error = nullptr;
                    }
                    else
                    {
                        tcp_socket_error(tac, ec);
                    }
                }
                else
                {
                    BOOST_LOG_SEV(log, trace) << "Wrote " << bytes_written << " bytes to tcp socket";
                    bool had_space_before = tcp_has_enough_write_buffer_space(tac);
                    tcp_write_buffer.consume(bytes_written);    //consume from buffer
                    bool has_space_after = tcp_has_enough_write_buffer_space(tac);
                    if (!had_space_before && has_space_after)
                    {   //this means web socket reads can be scheduled again
    #ifdef DEBUG
                        BOOST_LOG_SEV(log, debug) << "Just cleared enough buffer space in tcp write buffer. Re-starting async web socket read loop";
    #endif
                        async_web_socket_read_loop(tac);
                    }
                    //this is needed for write and write_some(), as even a full write may be completed
                    //after web socket reads put more data into the buffer
                    if (tcp_write_buffer.size() > 0)
                    {
                        tac.is_tcp_socket_writing = true;
                        tac.tcp_socket.async_write_some(tcp_write_buffer.data(), write_done);
                    }
                    else
                    {
                        if (on_tcp_write_buffer_drain_complete)
                        {
                            invoke_and_clear_handler(on_tcp_write_buffer_drain_complete);
                        }
    #ifdef DEBUG
                        BOOST_LOG_SEV(log, trace) << "TCP write buffer drain complete";
    #endif
                    }
                }
            };
            if (tac.is_tcp_socket_writing)
            {
                BOOST_LOG_SEV(log, debug) << "TCP write buffer drain cannot be started while already writing";
            }
            else if (tcp_write_buffer.size() == 0)
            {
                invoke_and_clear_handler(on_tcp_write_buffer_drain_complete);
            }
            else
            {
                tac.is_tcp_socket_writing = true;
                tac.tcp_socket.async_write_some(tcp_write_buffer.data(), write_done);
            }
        }

    void tcp_adapter_proxy::async_setup_web_socket_write_buffer_drain(tcp_adapter_context &tac)
    {
        using namespace com::amazonaws::iot::securedtunneling;

        if (tac.is_web_socket_writing)
        {
            //already writing, do nothing
        }
        else if (web_socket_data_write_buffer.size() > 0)
        {   //not writing, and buffer isn't empty so schedule one
            bool had_buffer_write_space = wss_has_enough_write_buffer_space(tac);

            outgoing_message.set_type(Message_Type_DATA);
            outgoing_message.set_streamid(tac.stream_id);
            //we can't put more than 
            size_t const send_size = std::min<std::size_t>(GET_SETTING(settings, MESSAGE_MAX_PAYLOAD_SIZE),
                web_socket_data_write_buffer.size());
            boost::asio::buffer_copy(outgoing_message_buffer.prepare(send_size), web_socket_data_write_buffer.data(), send_size);
            outgoing_message_buffer.commit(send_size);
            web_socket_data_write_buffer.consume(send_size);
            outgoing_message.set_payload(outgoing_message_buffer.data().data(), send_size);
            outgoing_message_buffer.consume(outgoing_message_buffer.max_size());

            //after message is sent, continue with the loop
            after_send_message = std::bind(&tcp_adapter_proxy::async_setup_web_socket_write_buffer_drain, this, std::ref(tac));
            async_send_message(tac, outgoing_message);

            //if this write cleared up enough space
            if (!had_buffer_write_space && wss_has_enough_write_buffer_space(tac))
            {
                async_tcp_socket_read_loop(tac);
            }
        }
        else
        {   //not writing, no buffer contents, skip straight to being done draining
            invoke_and_clear_handler(on_web_socket_write_buffer_drain_complete);
        }
    }


    void tcp_adapter_proxy::async_setup_source_tcp_socket(tcp_adapter_context &tac)
    {
        std::shared_ptr<basic_retry_config> retry_config =
                std::make_shared<basic_retry_config>(tac.io_ctx,
                    GET_SETTING(settings, TCP_CONNECTION_RETRY_COUNT),
                    GET_SETTING(settings, TCP_CONNECTION_RETRY_DELAY_MS),
                    nullptr);
        retry_config->operation = std::bind(&tcp_adapter_proxy::async_setup_source_tcp_socket_retry, this, std::ref(tac), retry_config);
        async_setup_source_tcp_socket_retry(tac, retry_config);
    }

    void tcp_adapter_proxy::async_setup_source_tcp_socket_retry(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config)
    {
        tcp_socket_ensure_closed(tac);
        //ensure acceptor is available for re-use
        tac.acceptor.close();

        static boost::asio::socket_base::reuse_address reuse_addr_option(true);

        tac.bind_address_actual = tac.adapter_config.bind_address.get_value_or(GET_SETTING(settings, DEFAULT_BIND_ADDRESS));
        BOOST_LOG_SEV(log, debug) << "Resolving bind address host: " << tac.bind_address_actual;
        tac.resolver.async_resolve(tac.bind_address_actual, boost::lexical_cast<std::string>(tac.adapter_config.data_port),
            boost::asio::ip::resolver_base::passive, 
            [=, &tac](boost::system::error_code const &ec, tcp::resolver::results_type results)
            {
                if (ec)
                {
                    BOOST_LOG_SEV(log, error) << (boost::format("Could not resolve bind address: %1% -- %2%") % tac.bind_address_actual % ec.message()).str();
                    basic_retry_execute(log, retry_config,
                        [&tac, &ec]() { throw proxy_exception((boost::format("Failed to resolve bind address for: %1%") % tac.bind_address_actual).str(), ec); });
                }
                else
                {
                    BOOST_LOG_SEV(log, debug) << "Resolved bind IP: " << results->endpoint().address().to_string();
                    boost::system::error_code bind_ec;
                    tac.acceptor.open(results->endpoint().protocol());  //this style of opening allows for IPv6 to be picked dynamically
                    if (tac.adapter_config.data_port)
                    {   //if data port is 0 (means pick an empheral port), then don't set this option
                        tac.acceptor.set_option(reuse_addr_option);
                    }
                    tac.acceptor.bind(results->endpoint(), bind_ec);
                    if (bind_ec)
                    {
                        BOOST_LOG_SEV(log, error) << (boost::format("Could not bind to address: %1% -- %2%") % results->endpoint().address().to_string() % bind_ec.message()).str();
                        basic_retry_execute(log, retry_config,
                            [&tac, &ec]() { throw proxy_exception((boost::format("Failed to bind to address %1%:%2%") % tac.bind_address_actual % tac.adapter_config.data_port).str(), ec); });
                    }
                    else
                    {
                        tac.local_port = static_cast<std::uint16_t>(tac.acceptor.local_endpoint().port());
                        BOOST_LOG_SEV(log, info) << "Listening for new connection on port " << tac.local_port;
                        boost::system::error_code listen_ec;
                        tac.acceptor.listen(0, listen_ec);
                        if (listen_ec)
                        {
                            BOOST_LOG_SEV(log, error) << (boost::format("Could not listen on bind address: %1% -- %2%")
                                % results->endpoint().address().to_string() % listen_ec.message()).str();
                            basic_retry_execute(log, retry_config,
                                [&tac, &ec]() { throw proxy_exception((boost::format("Failed to listen on bind address %1%:%2%") % tac.bind_address_actual % tac.adapter_config.data_port).str(), ec); });
                        }
                        else
                        {
                            if (tac.adapter_config.data_port == 0 && tac.adapter_config.on_listen_port_assigned)
                            {
                                tac.adapter_config.on_listen_port_assigned(tac.local_port);
                            }

                            tac.acceptor.async_accept(
                                [=, &tac](boost::system::error_code const &ec, boost::asio::ip::tcp::socket new_socket)
                            {
                                if (ec)
                                {
                                    BOOST_LOG_SEV(log, error) << (boost::format("Could not listen/accept incoming connection on %1%:%2% -- %3%")
                                        % tac.bind_address_actual % tac.local_port % ec.message()).str();
                                    basic_retry_execute(log, retry_config,
                                        [&tac, &ec]() { throw std::runtime_error((boost::format("Failed to accept new connection -- %2%") % tac.adapter_config.data_port % ec.message()).str()); });
                                }
                                else
                                {
                                    tac.tcp_socket = std::move(new_socket);
                                    BOOST_LOG_SEV(log, info) << "Accepted tcp connection on port " << tac.local_port << " from " << tac.tcp_socket.remote_endpoint();
                                    invoke_and_clear_handler(after_setup_tcp_socket);
                                }
                            });
                        }
                    }
                }
            });
    }

    void tcp_adapter_proxy::async_resolve_destination_for_connect(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config, boost::system::error_code const &ec, tcp::resolver::results_type results)
    {
        if (ec)
        {
            BOOST_LOG_SEV(log, error) << (boost::format("Could not resolve ip/host {%1}: %2%") % tac.adapter_config.data_host % ec.message()).str();
            basic_retry_execute(log, retry_config,
                [this, &tac, &ec]()
                {
                    this->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac));
                    async_send_stream_reset(tac, tac.stream_id);
                });
        }
        else {
            BOOST_LOG_SEV(log, debug) << "Resolved destination host to IP: " << results->endpoint().address().to_string();
            BOOST_LOG_SEV(log, trace) << "Connecting to " << results->endpoint().address().to_string();
            //connect async
            tac.tcp_socket.async_connect(*results.begin(),
                [=, &tac](boost::system::error_code const &ec)
                {
                    if (ec)
                    {
                        BOOST_LOG_SEV(log, error) << (boost::format("Could not connect to destination %1%:%2% -- %3%") % tac.adapter_config.data_host % tac.adapter_config.data_port % ec.message()).str();
                        basic_retry_execute(log, retry_config,
                            [this, &tac, &ec]()
                            {
                                this->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac));
                                async_send_stream_reset(tac, tac.stream_id);
                            });
                    }
                    else
                    {
                        BOOST_LOG_SEV(log, info) << "Connected to " << tac.adapter_config.data_host << ":" << tac.adapter_config.data_port;
                        invoke_and_clear_handler(after_setup_tcp_socket);
                    }
                }
            );
        }
    }

    void tcp_adapter_proxy::async_setup_dest_tcp_socket(tcp_adapter_context &tac)
    {
        std::shared_ptr<basic_retry_config> retry_config = 
            std::make_shared<basic_retry_config>(tac.io_ctx,
                GET_SETTING(settings, TCP_CONNECTION_RETRY_COUNT),
                GET_SETTING(settings, TCP_CONNECTION_RETRY_DELAY_MS),
                nullptr);
        retry_config->operation = std::bind(&tcp_adapter_proxy::async_setup_dest_tcp_socket_retry, this, std::ref(tac), retry_config);
        async_setup_dest_tcp_socket_retry(tac, retry_config);
    }

    void tcp_adapter_proxy::async_setup_dest_tcp_socket_retry(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config)
    {
        tcp_socket_ensure_closed(tac); 

        //the actual work of this function starts here
        BOOST_LOG_SEV(log, info) << "Attempting to establish tcp socket connection to: " << tac.adapter_config.data_host << ":" << tac.adapter_config.data_port;

        //the actual work of this function starts here
        if (tac.adapter_config.bind_address.has_value())
        {
            //start first async handler which chains into adding the rest
            BOOST_LOG_SEV(log, debug) << "Resolving local address host: " << tac.adapter_config.bind_address.get();
            tac.resolver.async_resolve(tac.adapter_config.bind_address.get(), boost::lexical_cast<std::string>(tac.adapter_config.data_port),
                boost::asio::ip::resolver_base::passive,
                [=, &tac](boost::system::error_code const &ec, tcp::resolver::results_type results)
                {
                    if (ec)
                    {
                        BOOST_LOG_SEV(log, error) << (boost::format("Could not resolve bind address: %1% -- %2%") % tac.adapter_config.bind_address.get() % ec.message()).str();
                        basic_retry_execute(log, retry_config,
                            [this, &tac, &ec]()
                            {
                                this->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac));
                                async_send_stream_reset(tac, tac.stream_id);
                            });
                    }
                    else
                    {
                        BOOST_LOG_SEV(log, debug) << "Resolved bind IP: " << results->endpoint().address().to_string();
                        boost::system::error_code bind_ec;
                        tac.tcp_socket.bind(results->endpoint(), bind_ec);
                        if (bind_ec)
                        {
                            BOOST_LOG_SEV(log, error) << (boost::format("Could not bind to address: %1% -- %2%") % results->endpoint().address().to_string() % bind_ec.message()).str();
                            basic_retry_execute(log, retry_config,
                                [this, &tac, &ec]()
                                {
                                    this->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac));
                                    async_send_stream_reset(tac, tac.stream_id);
                                });
                        }
                        else
                        {
                            tac.local_port = static_cast<std::uint16_t>(tac.tcp_socket.local_endpoint().port());
                            BOOST_LOG_SEV(log, trace) << "Resolving destination host: " << tac.adapter_config.data_host;
                            tac.resolver.async_resolve(tac.adapter_config.data_host, boost::lexical_cast<std::string>(tac.adapter_config.data_port),
                                std::bind(&tcp_adapter_proxy::async_resolve_destination_for_connect, this, std::ref(tac), retry_config, std::placeholders::_1, std::placeholders::_2));
                        }
                    }
                });
        }
        else
        {
            //start first async handler which chains into adding the rest
            BOOST_LOG_SEV(log, trace) << "Resolving destination host: " << tac.adapter_config.data_host;
            tac.resolver.async_resolve(tac.adapter_config.data_host, boost::lexical_cast<std::string>(tac.adapter_config.data_port),
                std::bind(&tcp_adapter_proxy::async_resolve_destination_for_connect, this, std::ref(tac), retry_config, std::placeholders::_1, std::placeholders::_2));
        }
    }

    void tcp_adapter_proxy::tcp_socket_ensure_closed(tcp_adapter_context &tac)
    {
        boost::system::error_code ec;
        if (tac.tcp_socket.is_open())
        {
            BOOST_LOG_SEV(log, debug) << "Previously open connection detected. Closing...";
            auto remote_endpoint = tac.tcp_socket.remote_endpoint(ec);
            if (!ec)
            {
                BOOST_LOG_SEV(this->log, info) << "Disconnected from: " << remote_endpoint;
            }
            tac.tcp_socket.close();
        }
    }

    void tcp_adapter_proxy::clear_buffers()
    {
        BOOST_LOG_SEV(log, trace) << "Clearing all data buffers";
        outgoing_message_buffer.consume(outgoing_message_buffer.max_size());
        incoming_message_buffer.consume(incoming_message_buffer.max_size());
        message_parse_buffer.consume(message_parse_buffer.max_size());
        tcp_write_buffer.consume(tcp_write_buffer.max_size());
        tcp_read_buffer.consume(tcp_read_buffer.max_size());
        web_socket_data_write_buffer.consume(web_socket_data_write_buffer.max_size());
    }

    bool tcp_adapter_proxy::is_valid_stream_id(tcp_adapter_context const& tac, message const &message)
    {
        if (MESSAGE_TYPES_REQUIRING_STREAM_ID.find(message.type()) != MESSAGE_TYPES_REQUIRING_STREAM_ID.end())
        {
            if (message.streamid() == 0)
            {
                BOOST_LOG_SEV(log, warning) << "Message recieved with streamid not set";
                return false;   //stream id of 0 means unset, so we don't accept it
            }
            return tac.stream_id == message.streamid();
        }
        return true;
    }

    bool tcp_adapter_proxy::tcp_has_enough_write_buffer_space(tcp_adapter_context const &tac)
    {   //tcp write buffer needs at least enough space to hold a max data size web socket message
        //because we can't limit how much data we might recieve next frame
        return (tcp_write_buffer.max_size() - tcp_write_buffer.size()) >= GET_SETTING(settings, MESSAGE_MAX_PAYLOAD_SIZE);
    }

    bool tcp_adapter_proxy::wss_has_enough_write_buffer_space(tcp_adapter_context const &tac)
    {   //web socket write buffer only needs non-zero space because we can make TCP read
        //calls that limit the data recieved
        return (web_socket_data_write_buffer.max_size() - web_socket_data_write_buffer.size()) > 0;
    }
}}}
