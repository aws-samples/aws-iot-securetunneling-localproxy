// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <functional>
#include <set>

#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl/rfc2818_verification.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/core/flat_buffer.hpp>
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
#include "config/ConfigFile.h"
#include "WebProxyAdapter.h"

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

    using std::uint16_t;
    using std::string;
    using std::tuple;

    char const * const PROXY_MODE_QUERY_PARAM = "local-proxy-mode";
    char const * const ACCESS_TOKEN_HEADER = "access-token";
    char const * const SOURCE_PROXY_MODE = "source";
    char const * const DESTINATION_PROXY_MODE = "destination";
    char const * const LOCALHOST_IP = "127.0.0.1";
    std::string const SOURCE_LOCAL_PROXY_PORT_BIND_EXCEPTION = "Source local proxy fails to bind address";
    std::uint16_t const DEFAULT_PROXY_SERVER_PORT = 443;
    std::uint16_t const DEFAULT_WEB_PROXY_SERVER_PORT = 3128;

    std::set<std::uint32_t> MESSAGE_TYPES_VALIDATING_STREAM_ID {
        com::amazonaws::iot::securedtunneling::Message_Type_DATA,
        com::amazonaws::iot::securedtunneling::Message_Type_STREAM_RESET};


    std::string get_region_endpoint(std::string const &region, boost::property_tree::ptree const &settings)
    {
        boost::optional<std::string> endpoint_override = settings.get_optional<std::string>(
            (boost::format("%1%.%2%") % settings::KEY_PROXY_ENDPOINT_REGION_MAP % region).str());
        if(endpoint_override)
        {
            return endpoint_override.get();
        }
        return (boost::format(GET_SETTING(settings, PROXY_ENDPOINT_HOST_FORMAT)) % region).str();
    }

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
                    {
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

    tcp_adapter_proxy::tcp_adapter_proxy(ptree const &settings, LocalproxyConfig const &config) :
            settings{ settings },
            localproxy_config{config },
            web_proxy_adapter{&log, config },
            incoming_message_buffer{ GET_SETTING(settings, WEB_SOCKET_READ_BUFFER_SIZE) },
            message_parse_buffer{ GET_SETTING(settings, MESSAGE_MAX_SIZE) }
    { }

    tcp_adapter_proxy::~tcp_adapter_proxy()
    { }

    int tcp_adapter_proxy::run_proxy()
    {
        BOOST_LOG_SEV(log, info) << "Starting proxy in " << get_proxy_mode_string(localproxy_config.mode) << " mode";
        while (true)
        {
            tcp_adapter_context tac{localproxy_config, settings };
            try
            {
                setup_web_socket(tac);
                tac.io_ctx.run();
                return EXIT_SUCCESS;
            }
            catch (proxy_exception &e)
            {
                if (e.what() == SOURCE_LOCAL_PROXY_PORT_BIND_EXCEPTION)
                {
                    return EXIT_FAILURE;
                }
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

    void tcp_adapter_proxy::initialize_tcp_clients(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Initializing tcp clients ...";
        for (auto m: tac.adapter_config.serviceId_to_endpoint_map)
        {
            string service_id = m.first;
            // create new tcp clients if needed
            if (tac.serviceId_to_tcp_client_map.find(service_id) == tac.serviceId_to_tcp_client_map.end())
            {
                tac.serviceId_to_tcp_client_map[service_id] = tcp_client::create(tac.io_ctx,
                        GET_SETTING(settings, TCP_WRITE_BUFFER_SIZE),
                        GET_SETTING(settings, TCP_READ_BUFFER_SIZE),
                        GET_SETTING(settings, WEB_SOCKET_WRITE_BUFFER_SIZE));
            }
        }
    }

    void tcp_adapter_proxy::initialize_tcp_servers(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Initializing tcp servers ...";
        for (auto m: tac.adapter_config.serviceId_to_endpoint_map)
        {
            string service_id = m.first;
            // create new tcp servers if needed
            if (tac.serviceId_to_tcp_server_map.find(service_id) == tac.serviceId_to_tcp_server_map.end())
            {
                tac.serviceId_to_tcp_server_map[service_id] = tcp_server::create(tac.io_ctx,
                        GET_SETTING(settings, TCP_WRITE_BUFFER_SIZE),
                        GET_SETTING(settings, TCP_READ_BUFFER_SIZE),
                        GET_SETTING(settings, WEB_SOCKET_WRITE_BUFFER_SIZE));
            }
        }
    }

    void tcp_adapter_proxy::setup_tcp_sockets(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Setting up tcp sockets ";
        clear_ws_buffers(tac);
        if (localproxy_config.mode == proxy_mode::DESTINATION)
        {
            initialize_tcp_clients(tac);
            async_setup_destination_tcp_sockets(tac);
        }
        else
        {
            initialize_tcp_servers(tac);
            async_setup_source_tcp_sockets(tac);
        }
    }

    void tcp_adapter_proxy::setup_tcp_socket(tcp_adapter_context &tac, std::string const & service_id)
    {
        BOOST_LOG_SEV(log, trace) << "Setting up tcp socket for service id: " << service_id;
        tcp_connection::pointer connection = get_tcp_connection(tac, service_id);
        if (localproxy_config.mode == proxy_mode::DESTINATION)
        {
            tcp_client::pointer client = tac.serviceId_to_tcp_client_map[service_id];
            client->on_receive_stream_start = std::bind(&tcp_adapter_proxy::async_setup_dest_tcp_socket, this, std::ref(tac), service_id);
            client->after_setup_tcp_socket = std::bind(&tcp_adapter_proxy::async_setup_bidirectional_data_transfers, this, std::ref(tac), service_id);
            async_web_socket_read_until_stream_start(tac, service_id);
        }
        else
        {
            tcp_server::pointer server = tac.serviceId_to_tcp_server_map[service_id];
            server->connection_->after_send_message = std::bind(&tcp_adapter_proxy::async_setup_bidirectional_data_transfers, this, std::ref(tac), service_id);
            server->after_setup_tcp_socket = std::bind(&tcp_adapter_proxy::async_send_stream_start, this, std::ref(tac), service_id);
            std::shared_ptr<basic_retry_config> retry_config =
                    std::make_shared<basic_retry_config>(tac.io_ctx,
                                                         GET_SETTING(settings, TCP_CONNECTION_RETRY_COUNT),
                                                         GET_SETTING(settings, TCP_CONNECTION_RETRY_DELAY_MS),
                                                         nullptr);
            retry_config->operation = std::bind(&tcp_adapter_proxy::async_setup_source_tcp_socket_retry, this, std::ref(tac), retry_config, service_id);
            async_setup_source_tcp_socket_retry(tac, retry_config, service_id);
        }
    }

    void tcp_adapter_proxy::setup_web_socket(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Setting up web socket...";
        after_setup_web_socket = std::bind(&tcp_adapter_proxy::async_wait_for_service_ids, this, std::ref(tac));
        async_setup_web_socket(tac);
    }

   void tcp_adapter_proxy::tcp_socket_reset_all(tcp_adapter_context &tac, std::function<void()> post_reset_operation)
   {
        for (auto m: tac.adapter_config.serviceId_to_endpoint_map)
        {
            string service_id = m.first;
            tcp_adapter_proxy::tcp_socket_reset(tac, service_id, post_reset_operation);
        }
   }

   tcp_connection::pointer tcp_adapter_proxy::get_tcp_connection(tcp_adapter_context &tac, string service_id)
   {
       tcp_connection::pointer connection_ptr;
       if (tac.adapter_config.mode == proxy_mode::SOURCE)
       {
           if (tac.serviceId_to_tcp_server_map.find(service_id) == tac.serviceId_to_tcp_server_map.end())
           {
               BOOST_LOG_SEV(log, debug) << "No serviceId_to_tcp_server mapping for service_id: " << service_id;
               return connection_ptr;
           }
           connection_ptr = tac.serviceId_to_tcp_server_map[service_id]->connection_;
       }
       else if (tac.adapter_config.mode == proxy_mode::DESTINATION)
       {
           if (tac.serviceId_to_tcp_client_map.find(service_id) == tac.serviceId_to_tcp_client_map.end())
           {
               BOOST_LOG_SEV(log, debug) << "No serviceId_to_tcp_client mapping for service_id: " << service_id;

               return connection_ptr;
           }
           connection_ptr = tac.serviceId_to_tcp_client_map[service_id]->connection_;
       }
       else
       {
           throw proxy_exception((boost::format("Unknown mode: %1%") % tac.adapter_config.mode).str());
       }
       return connection_ptr;
   }

    void tcp_adapter_proxy::tcp_socket_reset(tcp_adapter_context &tac, string service_id, std::function<void()> post_reset_operation)
    {
        tcp_connection::pointer connection = get_tcp_connection(tac, service_id);
        if (!connection->socket_.is_open())
        {
            BOOST_LOG_SEV(log, debug) << "Ignoring explicit reset because TCP socket is already closed";
            return;
        }
        BOOST_LOG_SEV(log, debug) << "Handling explicit reset by closing TCP for service id: " << service_id;

        connection->socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_receive);
        std::shared_ptr<bool> web_socket_write_buffer_drain_complete = std::make_shared<bool>(false);
        std::shared_ptr<bool> tcp_write_buffer_drain_complete = std::make_shared<bool>(false);

        //ignore next tcp read error if a read operation is happening when TCP gets closed
        connection->on_tcp_error =
            [=](boost::system::error_code const &ec)
            {
                //We *may* want to confirm that the error code is actually operation canceled or aborted due to TCP close as
                //any unexpected errors in this situation perhaps signals something else. But also we may want to ignore all errors
                //anyways given we know we are closing the tcp socket to create a new one anyways
                BOOST_LOG_SEV(this->log, trace) << "Received expected TCP socket error and ignoring it. TCP socket read loop has been canceled for service id: " << service_id;
            };
        connection->on_data_message = std::bind(&tcp_adapter_proxy::ignore_message_and_stop, this, std::ref(tac), std::placeholders::_1);
        connection->on_control_message = std::bind(&tcp_adapter_proxy::ignore_message_and_stop, this, std::ref(tac), std::placeholders::_1);
        connection->on_web_socket_write_buffer_drain_complete =
            [=]()
            {
                BOOST_LOG_SEV(this->log, trace) << "Post-reset web socket drain complete";
                *web_socket_write_buffer_drain_complete = true;
                if (*tcp_write_buffer_drain_complete)
                {
                    BOOST_LOG_SEV(this->log, trace) << "Both socket drains complete.";
                    post_reset_operation();
                }
            };

        connection->on_tcp_write_buffer_drain_complete =
            [=, &tac]()
            {
                tcp_connection::pointer connection_to_reset = get_tcp_connection(tac, service_id);
                BOOST_LOG_SEV(this->log, trace) << "Post-reset TCP drain complete. Closing TCP socket for service id " << service_id;
                BOOST_LOG_SEV(this->log, info) << "Disconnected from: " << connection_to_reset->socket().remote_endpoint();
                connection_to_reset->socket_.close();
                *tcp_write_buffer_drain_complete = true;
                if (*web_socket_write_buffer_drain_complete)
                {
                    BOOST_LOG_SEV(this->log, trace) << "Both socket drains complete. Setting up TCP socket again";
                    post_reset_operation();
                }
            };
        async_setup_web_socket_write_buffer_drain(tac, service_id);
        async_tcp_write_buffer_drain(tac, service_id);
    }

    void tcp_adapter_proxy::web_socket_close_and_stop(tcp_adapter_context &tac)
    {
        if (tac.wss)
        {
            if (tac.wss->is_open())
            {
                tac.wss->async_teardown(boost::beast::role_type::client, [&tac, this](boost::system::error_code const &ec)
                {
                    if (ec)
                    {
                        BOOST_LOG_SEV(this->log, error) << "Teardown of web socket connection not successful: " << ec.message();
                    }
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

    void tcp_adapter_proxy::tcp_socket_error(tcp_adapter_context &tac, boost::system::error_code const &ec, string const & service_id)
    {
        BOOST_LOG_SEV(log, debug) << "Handling tcp socket error for service id: " << service_id << " . error message:" << ec.message();
        tcp_connection::pointer connection = get_tcp_connection(tac, service_id);
        BOOST_LOG_SEV(this->log, info) << "Disconnected from: " << connection->socket().remote_endpoint();
        connection->socket_.close();
        connection->tcp_write_buffer_.consume(connection->tcp_write_buffer_.max_size());

        connection->on_data_message = std::bind(&tcp_adapter_proxy::ignore_message_and_stop, this, std::ref(tac), std::placeholders::_1);
        connection->on_control_message = std::bind(&tcp_adapter_proxy::ignore_message_and_stop, this, std::ref(tac), std::placeholders::_1);

        connection->on_web_socket_write_buffer_drain_complete = [&, service_id]()
        {
            tcp_connection::pointer socket_connection = get_tcp_connection(tac, service_id);
            socket_connection->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac), service_id);
            async_send_stream_reset(tac, service_id);
        };
        async_setup_web_socket_write_buffer_drain(tac, service_id);
    }

    void tcp_adapter_proxy::async_send_message(tcp_adapter_context &tac, message const &message)
    {
        boost::beast::flat_buffer     outgoing_message_buffer;
        std::size_t const frame_size = static_cast<std::size_t>(message.ByteSizeLong()) +
            GET_SETTING(settings, DATA_LENGTH_SIZE);
        void *frame_data = outgoing_message_buffer.prepare(frame_size).data();
        void *frame_data_msg_offset = reinterpret_cast<void *>(reinterpret_cast<std::uint8_t *>(frame_data) 
            + GET_SETTING(settings, DATA_LENGTH_SIZE));
        std::uint16_t data_length = static_cast<std::uint16_t>(message.ByteSizeLong());
        *reinterpret_cast<std::uint16_t *>(frame_data) = boost::endian::native_to_big(data_length);
        message.SerializeToArray(frame_data_msg_offset, static_cast<int>(GET_SETTING(settings, MESSAGE_MAX_SIZE)));
        outgoing_message_buffer.commit(frame_size);
        string service_id = message.serviceid();
        async_send_message_to_web_socket(tac, std::make_shared<boost::beast::flat_buffer>(outgoing_message_buffer), service_id);
    }

    void tcp_adapter_proxy::async_send_stream_start(tcp_adapter_context &tac, string const & service_id)
    {
        using namespace com::amazonaws::iot::securedtunneling;
        if (!tac.is_service_ids_received)
        {
            std::shared_ptr<basic_retry_config> retry_config =
                    std::make_shared<basic_retry_config>(tac.io_ctx,
                                                         GET_SETTING(settings, TCP_CONNECTION_RETRY_COUNT),
                                                         GET_SETTING(settings, TCP_CONNECTION_RETRY_DELAY_MS),
                                                         std::bind(&tcp_adapter_proxy::async_send_stream_start, this, std::ref(tac), service_id));
            BOOST_LOG_SEV(log, error) << "No service ids received. Will retry.";
            basic_retry_execute(log, retry_config, []() { throw std::runtime_error("Fail all the retries to get service ids before stream start. Exit."); });
            return;
        }
        std::string src_listening_port = boost::lexical_cast<std::string>(tac.serviceId_to_tcp_server_map[service_id]->acceptor().local_endpoint().port());
        if (tac.adapter_config.serviceId_to_endpoint_map.find(service_id) == tac.adapter_config.serviceId_to_endpoint_map.end() ||
        tac.adapter_config.serviceId_to_endpoint_map.at(service_id) != src_listening_port)
        {
            throw std::runtime_error((boost::format("Receive incoming connection from non-configured port: %1%") % src_listening_port).str());
        }

        /**
         * Initialize stream id to 1. If a mapping exist for a certain service id, it will be overwrite to the value
         * from the serviceId_to_streamId_map.
         */
        std::int32_t new_stream_id = 1;

        if(tac.serviceId_to_streamId_map.find(service_id) != tac.serviceId_to_streamId_map.end())
        {
            std::int32_t old_stream_id = tac.serviceId_to_streamId_map[service_id];
            // Reset old stream id to 0 if it already reaches the max value of current type
            if (old_stream_id == std::numeric_limits<decltype(old_stream_id)>::max())
            {
                old_stream_id = 0;
            }
            new_stream_id = old_stream_id + 1;
        }

        // Update streamId <-> serviceId mapping for future book keeping
        tac.serviceId_to_streamId_map[service_id] = new_stream_id;

        BOOST_LOG_SEV(log, debug) << "Setting new stream ID to: " << new_stream_id << ", service id: " << service_id;

        outgoing_message.set_type(Message_Type_STREAM_START);
        outgoing_message.set_serviceid(service_id);
        outgoing_message.set_streamid(new_stream_id);
        outgoing_message.set_ignorable(false);
        outgoing_message.clear_payload();
        async_send_message(tac, outgoing_message);
    }

    void tcp_adapter_proxy::async_send_stream_reset(tcp_adapter_context &tac, std::string const & service_id)
    {
        using namespace com::amazonaws::iot::securedtunneling;
        BOOST_LOG_SEV(log, trace) << "Reset stream for service id: " << service_id;
        if (tac.serviceId_to_streamId_map.find(service_id) == tac.serviceId_to_streamId_map.end())
        {
            BOOST_LOG_SEV(log, warning) << "No stream id mapping found for service id " << service_id << " . Skip stream reset.";
            return;
        }
        // NOTE: serviceIds -> streamId mapping will be updated when send/receive stream start, no action needed now.
        std::int32_t stream_id = tac.serviceId_to_streamId_map[service_id];
        outgoing_message.set_type(Message_Type_STREAM_RESET);
        outgoing_message.set_serviceid(service_id);
        outgoing_message.set_streamid(stream_id);
        outgoing_message.set_ignorable(false);
        outgoing_message.clear_payload();
        async_send_message(tac, outgoing_message);
    }

    void tcp_adapter_proxy::async_setup_bidirectional_data_transfers(tcp_adapter_context &tac, string const & service_id)
    {
        BOOST_LOG_SEV(log, trace) << "Setting up bi-directional data transfer for service id: " << service_id;
        // clear tcp_buffers for this stream
        tcp_connection::pointer connection = get_tcp_connection(tac, service_id);
        if (!connection)
        {
            BOOST_LOG_SEV(log, trace) << "Null connection pointers, skip";
            return;
        }
        clear_tcp_connection_buffers(connection);
        connection->on_control_message = std::bind(&tcp_adapter_proxy::handle_control_message_data_transfer, this, std::ref(tac), std::placeholders::_1);
        connection->on_data_message = std::bind(&tcp_adapter_proxy::forward_data_message_to_tcp_write, this, std::ref(tac), std::placeholders::_1);
        this->async_web_socket_read_loop(tac);
        this->async_tcp_socket_read_loop(tac, service_id);
    }

    void tcp_adapter_proxy::async_web_socket_read_until_stream_start(tcp_adapter_context &tac, string const & service_id)
    {
        BOOST_LOG_SEV(log, trace) << "Waiting for stream start...";
        tcp_client::pointer client = tac.serviceId_to_tcp_client_map[service_id];
        client->connection_->on_control_message = std::bind(&tcp_adapter_proxy::async_wait_for_stream_start, this, std::ref(tac), std::placeholders::_1);
        client->connection_->on_data_message = std::bind(&tcp_adapter_proxy::ignore_message, this, std::ref(tac), std::placeholders::_1);
        this->async_web_socket_read_loop(tac);
    }

    void tcp_adapter_proxy::handle_web_socket_control_message(tcp_adapter_context &tac, boost::beast::websocket::frame_type ws_message_type, boost::beast::string_view payload)
    {
#ifdef DEBUG
        BOOST_LOG_SEV(log, debug) << "Control message recieved enum(close=0, ping=1, pong=2): " << static_cast<std::uint32_t>(ws_message_type);
#endif
        boost::beast::websocket::ping_data pd{ payload };
        long long now_millis = 0;
        long long pong_millis = 0;
        switch (ws_message_type)
        {
            BOOST_LOG_SEV(log, trace) << "handle_web_socket_control_message, message type: " << static_cast<std::uint32_t>(ws_message_type);
        case boost::beast::websocket::frame_type::close:
            BOOST_LOG_SEV(log, info) << "Web socket close received. Code: " << tac.wss->reason().code << "; Reason: " << tac.wss->reason().reason;
            tcp_socket_reset_all(tac, std::bind(&tcp_adapter_proxy::web_socket_close_and_stop, this, std::ref(tac)));
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
        {
            BOOST_LOG_SEV(log, error) << "Failed to send websocket ping: " << ping_ec.message();
        }
#ifdef DEBUG
        else
        {
            BOOST_LOG_SEV(log, trace) << "Successfully sent websocket ping";
        }
#endif
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
                after_setup_web_socket();
            }
            return;
        }
        if (tac.wss && tac.wss->lowest_layer().is_open())
        {
            tac.wss->lowest_layer().close();
        }
        tac.wss = std::make_shared<WebSocketStream>(tac.adapter_config, &log, tac.io_ctx);
        tac.wss->control_callback(std::bind(&tcp_adapter_proxy::handle_web_socket_control_message, this, std::ref(tac), std::placeholders::_1, std::placeholders::_2));
        
        static std::string user_agent_string = (boost::format("localproxy %1% %2%-bit/boost-%3%.%4%.%5%/openssl-%6%.%7%.%8%/protobuf-%9%")
            % BOOST_PLATFORM % (sizeof(void*)*8)
            % (BOOST_VERSION / 100000) % ((BOOST_VERSION / 100) % 1000) % (BOOST_VERSION % 100)
            % (OPENSSL_VERSION_NUMBER >> 28) % ((OPENSSL_VERSION_NUMBER >> 20) & 0xF) % ((OPENSSL_VERSION_NUMBER >> 12) & 0xF)
            % google::protobuf::internal::VersionString(GOOGLE_PROTOBUF_VERSION) ).str();
        
        //the actual work of this function starts here
        BOOST_LOG_SEV(log, info) << "Attempting to establish web socket connection with endpoint wss://" << tac.adapter_config.proxy_host << ":" << tac.adapter_config.proxy_port;

        auto on_websocket_handshake = [=, &tac](boost::system::error_code const &ec)
        {
            BOOST_LOG_SEV(log, trace) << "Web socket upgrade response:\n" << tac.wss_response;
            if (ec)
            {
                BOOST_LOG_SEV(log, error) << (boost::format("Proxy server rejected web socket upgrade request: (HTTP/%4%.%5% %1% %2%) \"%3%\"")
                                              % tac.wss_response.result_int() % tac.wss_response.reason() % boost::trim_copy(tac.wss_response.body())
                                              % (tac.wss_response.version() / 10) % (tac.wss_response.version() % 10)).str();    //form HTTP version
                auto is_server_error = [](const int http_response_code) { return http_response_code >= 500 && http_response_code < 600;};
                if (is_server_error(tac.wss_response.result_int()))
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

                if (after_setup_web_socket)
                {
                    after_setup_web_socket();
                }
            }
        };
        auto on_tcp_connect = [=, &tac](boost::system::error_code const &ec)
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
                BOOST_LOG_SEV(log, trace) << "Performing SSL handshake with proxy server";
                if (!localproxy_config.no_ssl_host_verify)
                {
                    tac.wss->set_ssl_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);
                    tac.wss->set_verify_callback(boost::asio::ssl::rfc2818_verification(tac.adapter_config.proxy_host));
                }
                else
                {
                    BOOST_LOG_SEV(log, debug) << "SSL host verification is off";
                }
                //next ssl handshake
                tac.wss->async_ssl_handshake(boost::asio::ssl::stream_base::client, [=, &tac](boost::system::error_code const &ec)
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
                                                    on_websocket_handshake
                        );
#ifndef _AWSIOT_TUNNELING_NO_SSL
                    }
                });
#endif
            }
        };
        auto on_proxy_server_dns_resolve = [=, &tac](boost::system::error_code const &ec, tcp::resolver::results_type results)
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
                tac.wss->lowest_layer().async_connect(*results.begin(), on_tcp_connect);
            }
        };
        auto on_web_proxy_dns_resolve = [=, &tac](boost::system::error_code const &ec, tcp::resolver::results_type results)
        {
            if (ec)
            {
                BOOST_LOG_SEV(log, error) << (boost::format("Could not resolve DNS hostname of Web proxy: %1% - %2%") % tac.adapter_config.web_proxy_host % ec.message()).str();
                basic_retry_execute(log, retry_config, [&]() { std::bind(&tcp_adapter_proxy::web_socket_close_and_stop, this, std::ref(tac)); });
            } else {
                BOOST_LOG_SEV(log, debug) << "Resolved Web proxy IP: " << results->endpoint().address();
                web_proxy_adapter.async_connect(on_tcp_connect, tac.wss, results->endpoint());
            }
        };


        //start first async handler which chains into adding the rest
        if (tac.adapter_config.web_proxy_host.empty()) {
            BOOST_LOG_SEV(log, trace) << "Resolving proxy server host: " << tac.adapter_config.proxy_host;
            tac.wss_resolver.async_resolve(tac.adapter_config.proxy_host, boost::lexical_cast<std::string>(tac.adapter_config.proxy_port), on_proxy_server_dns_resolve);
        } else {
            BOOST_LOG_SEV(log, trace) << "Resolving Web proxy host: " << tac.adapter_config.web_proxy_host;
            tac.wss_resolver.async_resolve(tac.adapter_config.web_proxy_host, boost::lexical_cast<std::string>(tac.adapter_config.web_proxy_port), on_web_proxy_dns_resolve);
        }
    }

    void tcp_adapter_proxy::async_tcp_socket_read_loop(tcp_adapter_context & tac, string const & service_id)
    {
        BOOST_LOG_SEV(log, trace) << "Begin tcp socket read loop for service id : " << service_id;
        tcp_connection::pointer connection = get_tcp_connection(tac, service_id);
        if (!connection->socket().is_open())
        {
            BOOST_LOG_SEV(log, trace) << "socket for service id : " << service_id << " is not open yet, skip reading";
            return;
        }
        if (connection->is_tcp_socket_reading_)
        {
#ifdef DEBUG
            BOOST_LOG_SEV(log, debug) << "Not starting TCP read loop";
#endif
        }
        else if (wss_has_enough_write_buffer_space(connection->web_socket_data_write_buffer_))
        {
            //max bytes to read not to exceed either the read buffer capacity, or the available space in the web socket write buffer
            std::size_t max_bytes_to_read = std::min(connection->web_socket_data_write_buffer_.max_size() - connection->web_socket_data_write_buffer_.size(), connection->tcp_read_buffer_.max_size());
            connection->is_tcp_socket_reading_ = true;
            connection->socket_.async_read_some(connection->tcp_read_buffer_.prepare(max_bytes_to_read),
                [&, service_id](boost::system::error_code const &ec, std::size_t const bytes_read)
                {
                    BOOST_LOG_SEV(log, trace) << "Reading from tcp socket for service id " << service_id;
                    tcp_connection::pointer socket_read_connection = get_tcp_connection(tac, service_id);
                    socket_read_connection->is_tcp_socket_reading_ = false;
                    if (ec)
                    {
                        if (socket_read_connection->on_tcp_error)
                        {
                            socket_read_connection->on_tcp_error(ec);
                            socket_read_connection->on_tcp_error = nullptr;
                        }
                        else
                        {
                            tcp_socket_error(tac, ec, service_id);
                        }
                    }
                    else
                    {
                        socket_read_connection->tcp_read_buffer_.commit(bytes_read);
#ifdef DEBUG
                        BOOST_LOG_SEV(log, trace) << "TCP socket read " << bytes_read << " bytes";
#endif
                        BOOST_LOG_SEV(log, trace) << "TCP socket read " << bytes_read << " bytes";
                        std::size_t bytes_copied = boost::asio::buffer_copy(socket_read_connection->web_socket_data_write_buffer_.prepare(bytes_read), socket_read_connection->tcp_read_buffer_.data(), bytes_read);
                        socket_read_connection->tcp_read_buffer_.consume(bytes_read);
                        socket_read_connection->web_socket_data_write_buffer_.commit(bytes_copied);

                        if (wss_has_enough_write_buffer_space(socket_read_connection->web_socket_data_write_buffer_))
                        {
                            async_tcp_socket_read_loop(tac, service_id);
                        }
                        else
                        {
                            BOOST_LOG_SEV(log, debug) << "No more space in web socket write buffer or tcp socket is closed. Stopping tcp read loop";
                        }
                        if (socket_read_connection->web_socket_data_write_buffer_.size() > 0) {
                                async_setup_web_socket_write_buffer_drain(tac, service_id);
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

        bool tcp_adapter_proxy::async_wait_for_service_ids(tcp_adapter_context &tac)
        {
            using namespace com::amazonaws::iot::securedtunneling;
            BOOST_LOG_SEV(log, trace) << "Waiting for service ids...";
            on_web_socket_control_message = std::bind(&tcp_adapter_proxy::handle_control_message_service_ids, this, std::ref(tac), std::placeholders::_1);
            on_web_socket_data_message = std::bind(&tcp_adapter_proxy::ignore_message, this, std::ref(tac), std::placeholders::_1);
            after_get_service_ids = std::bind(&tcp_adapter_proxy::setup_tcp_sockets, this, std::ref(tac));
            this->async_web_socket_read_loop_for_service_ids(tac);
            return true;
        }

        bool tcp_adapter_proxy::async_wait_for_stream_start(tcp_adapter_context &tac, message const &message)
        {
            using namespace com::amazonaws::iot::securedtunneling;
            BOOST_LOG_SEV(log, trace) << "Wait for control message stream start, receive message type:" << message.type();
            std::int32_t stream_id = static_cast<std::int32_t>(message.streamid());
            string service_id = message.serviceid();
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
                stream_id = static_cast<std::int32_t>(message.streamid());
                if (!stream_id)
                {
                    throw proxy_exception("No stream ID set for stream start message!");
                }
                BOOST_LOG_SEV(log, debug) << "Received service id :" << service_id << " ,stream id: " << message.streamid();
                // v1 message format does not need to validate service id. Set to the one service id stored in memory.
                if (tac.adapter_config.is_v1_message_format)
                {
                    service_id = tac.adapter_config.serviceId_to_endpoint_map.cbegin()->first;
                }
                else if (tac.adapter_config.serviceId_to_endpoint_map.find(service_id) == tac.adapter_config.serviceId_to_endpoint_map.end())
                {
                    throw proxy_exception((boost::format("Invalid service id received for stream start: %1%") % service_id).str());
                }

                tac.serviceId_to_streamId_map[service_id] = stream_id;
                tac.serviceId_to_tcp_client_map[service_id]->on_receive_stream_start();
                return false;
            case Message_Type_DATA:    //handling the following cases alleviates clang compiler warnings
                throw std::logic_error("Data message recieved in control message handler");
            case Message_Type_SERVICE_IDS:
                // service ids should already be received at this point, no actions to process again.
                return true;
            case Message_Type_UNKNOWN:
            case Message_Type_Message_Type_INT_MIN_SENTINEL_DO_NOT_USE_:
            case Message_Type_Message_Type_INT_MAX_SENTINEL_DO_NOT_USE_:
                //Can only use the following when linked to full ProtocolBuffers library rather than LITE
                //throw proxy_exception((boost::format("Unexpected message type recieved during control message handling during data transfer: %1%") % External_MessageType_Name(message.messagetype())).str());
                throw proxy_exception((boost::format("Unexpected message type recieved while waiting for stream start: %1%") % message.type()).str());
            default:
                if (message.ignorable()) {
                    return true;
                }
                throw std::logic_error((boost::format("Unrecognized message type received while waiting for stream start: %1%") % message.type()).str());
            }
        }

        /**
         * Upon receiving service ids, validate service ids provided through the configurations through CLI (-s, -d)
         * @return if configurations are valid
         */
        bool tcp_adapter_proxy::validate_service_ids_from_configuration(tcp_adapter_context &tac, std::unordered_set <std::string> service_id_list)
        {
            BOOST_LOG_SEV(log, trace) << "Validating service ids configuration";
            /**
             * Configurations are not provided when local proxy starts, no need to check further.
             * v1 local proxy format does not need to do this validation since service id won't be used.
             */
            if (fall_back_to_v1_message_format(tac.adapter_config.serviceId_to_endpoint_map)) return true;

            if (tac.adapter_config.serviceId_to_endpoint_map.empty()) return true;

            if (tac.adapter_config.serviceId_to_endpoint_map.size() != service_id_list.size())
            {
                BOOST_LOG_SEV(log, debug) << "Number of the service ids provided through CLI (-s or -d) does not match with open tunnel call. Please provide the same sets of service ids.";
                return false;
            }
            for (auto s: service_id_list)
            {
                if (tac.adapter_config.serviceId_to_endpoint_map.find(s) == tac.adapter_config.serviceId_to_endpoint_map.end())
                {
                    BOOST_LOG_SEV(log, debug) << "Service ids provided through open tunnel call " << s << " cannot be found in the CLI parameters (-s or -d).Please provide the same sets of service ids.";
                    return false;
                }
            }
            return true;
        }

        /**
         * Extracts service ids from the control message type Message_Type_SERVICE_IDS
         */
        bool tcp_adapter_proxy::handle_control_message_service_ids(tcp_adapter_context &tac, message const & message)
        {
            using namespace com::amazonaws::iot::securedtunneling;
            using namespace aws::iot::securedtunneling::config_file;
            tac.is_service_ids_received = true;
            std::unordered_set <std::string> service_id_list;
            std::unordered_set<string> found_service_ids;
            std::unordered_set <std::string> unfound_service_ids;
            // Cannot start the stream before receiving service ids.
            if (message.type() == Message_Type_STREAM_START)
            {
                throw proxy_exception("Receive stream start before receiving service ids. Cannot forward data.");
            }
            else if (message.type() != Message_Type_SERVICE_IDS)
            {
                BOOST_LOG_SEV(log, debug) << "Expect:Message_Type_SERVICE_IDS. Ignore message type: " << message.type();
                return false;
            }
            BOOST_LOG_SEV(log, debug) << "Extracting service Ids from control message " << message.type();
            for (int i = 0; i < message.availableserviceids_size(); i++)
            {
                std::string id = message.availableserviceids(i);
                if (service_id_list.find(id) != service_id_list.end())
                {
                    BOOST_LOG_SEV(log, warning) << "Duplicate service Id received, ignore: "<< id;
                    continue;
                }
                service_id_list.insert(id);
            }
            BOOST_LOG_SEV(log, trace) << "Service id received: ";
            for (auto s: service_id_list)
            {
                BOOST_LOG_SEV(log, trace) << s;
            }
            if (!tcp_adapter_proxy::validate_service_ids_from_configuration(tac, service_id_list))
            {
                throw std::runtime_error("Wrong configurations detected in local proxy. Please starts local proxy with right sets of service ids.");
            }

            /**
             * Set flag to mark local proxy will communicate using local proxy v1 message format.
             * local proxy v1 message format: 1 service id. It can be a empty string when open tunnel with no service in destination config.
             */
            if (service_id_list.size() == 1)
            {
                tac.adapter_config.is_v1_message_format = true;
            }
            /**
             * Build serviceId <-> endpoint mapping if not done yet.
             * Case1: Configuration is provided through configuration files. Upon receiving service ids, search through
             * the configuration directory and find the service ids provided in those files.
             * Case 2: Configuration is NOT provided from both files or CLI. Local proxy need to randomly pick up ports
             * to use if running in source mode.
             * Case 3: If not enough service ids are found through configuration files, local proxy helps to pick random
             * available ports, if starts in source mode.
             * If serviceId <-> endpoint mapping already exists, validate the mapping provided through CLI.
             */

            if (tac.adapter_config.serviceId_to_endpoint_map.empty())
             {
                 BOOST_LOG_SEV(log, trace) << "Build serviceId <-> endpoint mapping upon receiving service ids";

                 // Scan configuration files to find port mappings
                 if (!tac.adapter_config.config_files.empty())
                 {
                     BOOST_LOG_SEV(log, info) << "Scan configuration files to find the service ids";
                     read_service_ids_from_config_files(tac.adapter_config.config_files, service_id_list, tac.adapter_config.serviceId_to_endpoint_map);

                     std::transform(tac.adapter_config.serviceId_to_endpoint_map.cbegin(), tac.adapter_config.serviceId_to_endpoint_map.cend(),
                                    std::inserter(found_service_ids, found_service_ids.begin()),
                                    [](const std::pair<std::string, std::string>& key_value)
                                    { return key_value.first; });

                     std::set_difference(service_id_list.begin(), service_id_list.end(), found_service_ids.begin(), found_service_ids.end(),
                                         std::inserter(unfound_service_ids, unfound_service_ids.end()));

                     if (!unfound_service_ids.empty())
                     {
                         BOOST_LOG_SEV(log, trace) << "Receive number of service ids: " << service_id_list.size() <<
                         " .But only found " << tac.adapter_config.serviceId_to_endpoint_map.size() << " in configuration files";
                         if (tac.adapter_config.mode != proxy_mode::SOURCE)
                         {
                             throw std::runtime_error("Not enough the service ids are found in the configuration files. Fail to start.");
                         }

                         BOOST_LOG_SEV(log, trace) << "Not all the service ids are found in the configuration files. Local proxy will help to pick up " << unfound_service_ids.size() << " ports.";
                         // initialize the port to be 0 in the service id <-> endpoint mapping, so that local proxy will help picking available ports when establish tcp connection with client's APP
                         for (auto service_id :unfound_service_ids)
                         {
                             tac.adapter_config.serviceId_to_endpoint_map[service_id] = "0";
                         }
                         tac.adapter_config.on_listen_port_assigned = std::bind(&tcp_adapter_proxy::handle_listen_port_assigned, this, std::placeholders::_1, std::placeholders::_2, std::ref(tac));
                     }
                 }
                 // If configuration files not provided, initialize the port to be 0 if in source mode.
                 else
                 {
                     if (tac.adapter_config.mode != proxy_mode::SOURCE)
                     {
                         throw std::runtime_error("No port mapping exists. Fail to start local proxy in destination mode.");
                     }
                     for (auto service_id:service_id_list)
                     {
                         tac.adapter_config.serviceId_to_endpoint_map[service_id] = "0";
                     }
                     tac.adapter_config.on_listen_port_assigned = std::bind(&tcp_adapter_proxy::handle_listen_port_assigned, this, std::placeholders::_1, std::placeholders::_2, std::ref(tac));
                 }

                 // Update in-memory mapping
                 BOOST_LOG_SEV(log, info) << "Use port mapping:";
                 BOOST_LOG_SEV(log, info) << "---------------------------------";
                 for (auto m: tac.adapter_config.serviceId_to_endpoint_map)
                 {
                     BOOST_LOG_SEV(log, info) << m.first << " = " << m.second;
                 }
                 BOOST_LOG_SEV(log, info) << "---------------------------------";
             }
             else if (tcp_adapter_proxy::fall_back_to_v1_message_format(tac.adapter_config.serviceId_to_endpoint_map) && service_id_list.size() == 1)
             {
                 // v1 format service id is an empty string in the map
                 std::string endpoint = tac.adapter_config.serviceId_to_endpoint_map[""];
                 std::string service_id = *service_id_list.begin();

                 // Remove empty string map and put new mapping
                 tac.adapter_config.serviceId_to_endpoint_map.erase("");
                 tac.adapter_config.serviceId_to_endpoint_map[service_id] = endpoint;
                 BOOST_LOG_SEV(log, info) << "Updated port mapping for v1 format: ";
                 for (auto m : tac.adapter_config.serviceId_to_endpoint_map)
                 {
                     BOOST_LOG_SEV(log, info) << m.first << " = " << m.second;
                 }
             }
             if (after_get_service_ids)
             {
                 after_get_service_ids();
             }
             return true;
        }

        bool tcp_adapter_proxy::handle_control_message_data_transfer(tcp_adapter_context &tac, message const &message)
        {
            using namespace com::amazonaws::iot::securedtunneling;
            BOOST_LOG_SEV(log, trace) << "Handling control message...";
            std::int32_t stream_id = static_cast<std::int32_t>(message.streamid());
            string service_id = message.serviceid();
            // v1 message format does not need to validate service id. Set to the one service id stored in memory.
            if (tac.adapter_config.is_v1_message_format)
            {
                service_id = tac.adapter_config.serviceId_to_endpoint_map.cbegin()->first;
            }
            switch (message.type())
            {
            case Message_Type_SESSION_RESET:
    #ifdef DEBUG
                BOOST_LOG_SEV(log, trace) << "Session reset recieved";
    #endif
                //validation has already been done on stream_id before calling this, so we can just listen
                tcp_socket_reset_all(tac, std::bind(&tcp_adapter_proxy::setup_tcp_sockets, this, std::ref(tac)));
                return true;   //indicates we should stop reading from the web socket after processing this message
            case Message_Type_STREAM_RESET:
    #ifdef DEBUG
                BOOST_LOG_SEV(log, trace) << "Stream reset recieved";
    #endif
                //validation has already been done on stream_id before calling this, so we can just listen
                tcp_socket_reset(tac, service_id, std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac), service_id));
                return true;   //indicates we should stop reading from the web socket after processing this message
            case Message_Type_STREAM_START: //could verify that this is a destination mode local proxy. Source mode shouldn't receive stream start
                if (!stream_id)
                {
                    throw proxy_exception("No stream ID set for stream start message!");
                }
                if (tac.serviceId_to_streamId_map.find(service_id) == tac.serviceId_to_streamId_map.end())
                {
                    BOOST_LOG_SEV(log, warning) << "Starting new stream for service id: " << service_id;
                    tac.serviceId_to_streamId_map[service_id] = stream_id;
                    tac.serviceId_to_tcp_client_map[service_id]->on_receive_stream_start();
                }
                else if (tac.serviceId_to_streamId_map.at(service_id) != message.streamid())
                {
                    BOOST_LOG_SEV(log, warning) << "Stream start received during data transfer for service id :" << service_id << "with new stream id: " << message.streamid();
                    BOOST_LOG_SEV(log, warning) << "Reset this stream";
                    tcp_socket_reset(tac, service_id, std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac), service_id));
                }
                return true;
            case Message_Type_SERVICE_IDS:
                // service ids should be received and validate before any stream can start. Ignore this control message if receive after stream already start.
                BOOST_LOG_SEV(log, info) << "Receive service Ids during data transfer. ignore";
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
                if (message.ignorable()) {
                    return true;
                }
                throw std::logic_error((boost::format("Unrecognized message type recieved during control message handling during data transfer: %1%") % message.type()).str());
            }
        }

        bool tcp_adapter_proxy::forward_data_message_to_tcp_write(tcp_adapter_context &tac, message const &message)
        {
            // Get the endpoint information based on the service id mapping
            // Validate if this mapping exists, if not, discard the message
            string service_id = message.serviceid();
            /**
             * v1 message format does not need to have service id field, so we don't need to do validation on this field.
             * Fill the service id with the current one used in the local proxy mapping.
             */
            if(tac.adapter_config.is_v1_message_format)
            {
                service_id = tac.adapter_config.serviceId_to_endpoint_map.cbegin()->first;
            }
            else if (tac.serviceId_to_streamId_map.find(service_id) == tac.serviceId_to_streamId_map.end())
            {
                BOOST_LOG_SEV(log, error) << "Received non exist service Id, ignore";
                return false;
            }
            tcp_connection::pointer connection = get_tcp_connection(tac, service_id);;
            //capture write buffer size (we care if it is empty, that means we will need to trigger a drain)
            size_t write_buffer_size_before = connection->tcp_write_buffer_.size();
            boost::asio::buffer_copy(connection->tcp_write_buffer_.prepare(message.payload().size()), boost::asio::buffer(message.payload()));
            connection->tcp_write_buffer_.commit(message.payload().size());

            if (write_buffer_size_before == 0)
            {
                async_tcp_write_buffer_drain(tac, service_id);
            }

            if (tcp_has_enough_write_buffer_space(connection))
            {
                return true;
            }
            else //tcp write buffer is full, instruct caller to not perform subsequent read
            {
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

            continue_reading = process_incoming_websocket_buffer(tac, incoming_message_buffer);

            if (continue_reading)
            {
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
            //is there enough data to read to know data length?
            while (message_buffer.size() >= data_length_size && continue_reading)
            {
                boost::asio::buffer_copy(data_length_buffer.prepare(data_length_size), message_buffer.data(), data_length_size);
                uint16_t data_length = boost::endian::big_to_native(*reinterpret_cast<std::uint16_t const *>(data_length_buffer.data().data()));
                //is the entire message in the buffer yet?
                if (message_buffer.size() >= (data_length + data_length_size))
                {
                    //consume the length since we've already read it
                    message_buffer.consume(data_length_size);
                    bool parsed_successfully = parse_protobuf_and_consume_input(message_buffer, static_cast<size_t>(data_length), incoming_message)
                                                && incoming_message.IsInitialized();
                    if (!parsed_successfully)
                    {
                        //doesn't output actual error string unless debug protobuf library is linked to
                        throw proxy_exception((boost::format("Could not parse web socket binary frame into message: %1%") % incoming_message.InitializationErrorString()).str());
                    }
    #ifdef DEBUG
                    //BOOST_LOG_SEV(log, trace) << "Message recieved:\n" << message.DebugString(); //re-add when linked to protobuf instead of protobuf-lite
                    BOOST_LOG_SEV(log, trace) << "Message parsed successfully , type :" << incoming_message.type();
    #endif
                    if (!is_valid_stream_id(tac, incoming_message))
                    {
                        continue_reading = true;
    #ifdef DEBUG
                        BOOST_LOG_SEV(log, trace) << "Stale message recieved. Dropping";
    #endif
                    }
                    else
                    {
                        string service_id = incoming_message.serviceid();
                        // v1 message format does not need to validate service id. Set to the one service id stored in memory.
                        if (tac.adapter_config.is_v1_message_format)
                        {
                            service_id = tac.adapter_config.serviceId_to_endpoint_map.cbegin()->first;
                        }
                        tcp_connection::pointer connection = get_tcp_connection(tac, service_id);
                        // if per connection handler is available, trigger them.
                        if (incoming_message.type() != Message_Type_DATA)
                        {
                            if (connection != nullptr && connection->on_control_message != nullptr)
                            {
                                continue_reading = connection->on_control_message(incoming_message);
                            }
                            else
                            {
                                continue_reading = on_web_socket_control_message(incoming_message);
                            }
                        }
                        else if (incoming_message.type() == Message_Type_DATA)
                        {
                            if (connection != nullptr && connection->on_data_message != nullptr)
                            {
                                continue_reading = connection->on_data_message(incoming_message);
                            }
                            else
                            {
                                continue_reading = on_web_socket_data_message(incoming_message);
                            }

                        }
                    }
                }
                else    //not enough room to read the entire msg out of our buffer so skip
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

        void tcp_adapter_proxy::async_web_socket_read_loop(tcp_adapter_context &tac)
        {
            if (!on_web_socket_control_message || !on_web_socket_data_message)
            {
                throw std::logic_error("Cannot run web socket read loop without handlers in place for control messages and data messages");
            }
            if (!tcp_has_enough_write_buffer_space(tac))
            {
                BOOST_LOG_SEV(log, trace) << "Scheduled async web socket read into tcp write buffer and it does not have enough space!";
    #ifdef DEBUG
                BOOST_LOG_SEV(log, trace) << "Scheduled async web socket read into tcp write buffer and it does not have enough space!";
    #endif
            }

            else if (tac.is_web_socket_reading)
            {
                BOOST_LOG_SEV(log, debug) << "Starting web socket read loop while web socket is already reading. Ignoring...";
    #ifdef DEBUG
                BOOST_LOG_SEV(log, debug) << "Starting web socket read loop while web socket is already reading. Ignoring...";
    #endif
            }
            else
            {
                BOOST_LOG_SEV(log, debug) << "Starting web socket read loop continue reading...";
                tac.is_web_socket_reading = true;
                tac.wss->async_read_some(incoming_message_buffer, incoming_message_buffer.max_size() - incoming_message_buffer.size(),
                                        std::bind(&tcp_adapter_proxy::on_web_socket_read, this, std::ref(tac), std::placeholders::_1, std::placeholders::_2));
            }
        }

        /**
         * NOTE: No tcp read or write buffer needs to be initialized before we receive service ids.
         * This is because before getting the service ids, we don't know which applications to connect/listen to. No
         * tcp connections need to be established at this point.
         * @param tac
         */
        void tcp_adapter_proxy::async_web_socket_read_loop_for_service_ids(tcp_adapter_context &tac)
        {
            BOOST_LOG_SEV(log, trace) << "async_web_socket_read_loop_for_service_ids";

            if (!on_web_socket_control_message || !on_web_socket_data_message)
            {
                throw std::logic_error("Cannot run web socket read loop without handlers in place for control messages and data messages");
            }
            if (tac.is_web_socket_reading)
            {
#ifdef DEBUG
                BOOST_LOG_SEV(log, debug) << "Starting web socket read loop while web socket is already reading. Ignoring...";
#endif
            }
            else
            {
                tac.is_web_socket_reading = true;
                BOOST_LOG_SEV(log, debug) << "Scheduled next read:";
                tac.wss->async_read_some(incoming_message_buffer, incoming_message_buffer.max_size() - incoming_message_buffer.size(),
                                         std::bind(&tcp_adapter_proxy::on_web_socket_read, this, std::ref(tac), std::placeholders::_1, std::placeholders::_2));
            }
        }

        void tcp_adapter_proxy::async_tcp_write_buffer_drain(tcp_adapter_context &tac, string service_id)
        {
            tcp_connection::pointer connection = get_tcp_connection(tac, service_id);
            if (!connection->socket_.is_open())
            {
                throw proxy_exception((boost::format("TCP socket is not open service id: %1%") % service_id).str());
            }
            static std::function<void(boost::system::error_code const &, size_t)> write_done;
            write_done = [&, service_id](boost::system::error_code const &ec, size_t bytes_written)
            {
                BOOST_LOG_SEV(log, trace) << "write done service id " << service_id;
                tcp_connection::pointer socket_write_connection = get_tcp_connection(tac, service_id);
                socket_write_connection->is_tcp_socket_writing_ = false;
                if (ec)
                {
                    if (socket_write_connection->on_tcp_error)
                    {
                        socket_write_connection->on_tcp_error(ec);
                        socket_write_connection->on_tcp_error = nullptr;
                    }
                    else
                    {
                        tcp_socket_error(tac, ec, service_id);
                    }
                }
                else
                {
                    BOOST_LOG_SEV(log, trace) << "Wrote " << bytes_written << " bytes to tcp socket";
                    bool had_space_before = tcp_has_enough_write_buffer_space(socket_write_connection);
                    socket_write_connection->tcp_write_buffer_.consume(bytes_written);
                    bool has_space_after = tcp_has_enough_write_buffer_space(socket_write_connection);
                    if (!had_space_before && has_space_after)
                    {
    #ifdef DEBUG
                        BOOST_LOG_SEV(log, debug) << "Just cleared enough buffer space in tcp write buffer. Re-starting async web socket read loop";
    #endif
                        async_web_socket_read_loop(tac);
                    }
                    if (socket_write_connection->tcp_write_buffer_.size() > 0)
                    {
                        socket_write_connection->is_tcp_socket_writing_ = true;
                        BOOST_LOG_SEV(log, debug) << "Write to tcp socket";
                        socket_write_connection->socket_.async_write_some(socket_write_connection->tcp_write_buffer_.data(), write_done);
                    }
                    else
                    {
                        if (socket_write_connection->on_tcp_write_buffer_drain_complete)
                        {
                            invoke_and_clear_handler(socket_write_connection->on_tcp_write_buffer_drain_complete);
                        }
                        BOOST_LOG_SEV(log, trace) << "TCP write buffer drain complete";
    #ifdef DEBUG
                        BOOST_LOG_SEV(log, trace) << "TCP write buffer drain complete";
    #endif
                    }
                    BOOST_LOG_SEV(log, trace) << "Done writing for: " << service_id;
                }
            };
            if (connection->is_tcp_socket_writing_)
            {
                BOOST_LOG_SEV(log, debug) << "TCP write buffer drain cannot be started while already writing";
            }
            else if (connection->tcp_write_buffer_.size() == 0)
            {
                invoke_and_clear_handler(connection->on_tcp_write_buffer_drain_complete);
            }
            else
            {
                connection->is_tcp_socket_writing_ = true;
                connection->socket_.async_write_some(connection->tcp_write_buffer_.data(), write_done);
            }
        }

    void tcp_adapter_proxy::async_setup_web_socket_write_buffer_drain(tcp_adapter_context &tac, std::string const & service_id)
    {
        BOOST_LOG_SEV(log, trace) << "Web socket write buffer drain for service id: " << service_id;
        boost::beast::flat_buffer                   outgoing_message_buffer;
        tcp_connection::pointer connection = get_tcp_connection(tac, service_id);
        using namespace com::amazonaws::iot::securedtunneling;
        if (connection->web_socket_data_write_buffer_.size() > 0)
        {
            // Get end point from the tcp socket

            outgoing_message.set_type(Message_Type_DATA);
            if (tac.adapter_config.serviceId_to_endpoint_map.find(service_id) == tac.adapter_config.serviceId_to_endpoint_map.end())
            {
                throw proxy_exception((boost::format("Could not forward traffic from invalid service id: %1%") % service_id).str());
            }
            else if (tac.serviceId_to_streamId_map.find(service_id) == tac.serviceId_to_streamId_map.end())
            {
                throw proxy_exception((boost::format("No streamId exists for the service Id %1%") % service_id).str());
            }
            BOOST_LOG_SEV(log, debug) << "Prepare to send data message: service id: " << service_id << " stream id: " << tac.serviceId_to_streamId_map[service_id];
            // Construct outgoing message
            outgoing_message.set_serviceid(service_id);
            outgoing_message.set_streamid(tac.serviceId_to_streamId_map[service_id]);
            size_t const send_size = std::min<std::size_t>(GET_SETTING(settings, MESSAGE_MAX_PAYLOAD_SIZE),
                                                           connection->web_socket_data_write_buffer_.size());
            boost::asio::buffer_copy(outgoing_message_buffer.prepare(send_size), connection->web_socket_data_write_buffer_.data(), send_size);
            outgoing_message_buffer.commit(send_size);
            outgoing_message.set_payload(outgoing_message_buffer.data().data(), send_size);

            // Clean up web_socket_data_write_buffer
            connection->web_socket_data_write_buffer_.consume(send_size);
            outgoing_message_buffer.consume(outgoing_message_buffer.max_size());

            //after message is sent, continue with the loop
            connection->after_send_message = std::bind(&tcp_adapter_proxy::async_setup_web_socket_write_buffer_drain, this, std::ref(tac), service_id);
            async_send_message(tac, outgoing_message);

            //if this write cleared up enough space
            if (wss_has_enough_write_buffer_space(connection->web_socket_data_write_buffer_))
            {
                BOOST_LOG_SEV(log, debug) << "Write buffer has enough space, continue tcp read loop for " << service_id ;
                async_tcp_socket_read_loop(tac, service_id);
            }
            else
            {
                BOOST_LOG_SEV(log, debug) << " write DOES NOT cleared up enough space, no tcp read loop" << service_id ;
            }
        }
        else
        {   //not writing, no buffer contents, skip straight to being done draining
            invoke_and_clear_handler(connection->on_web_socket_write_buffer_drain_complete);
        }
    }

    void tcp_adapter_proxy::async_setup_source_tcp_sockets(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Setting up source tcp sockets";
        for (auto m: tac.adapter_config.serviceId_to_endpoint_map)
        {
            string service_id = m.first;
            setup_tcp_socket(tac, service_id);
        }
    }

    void tcp_adapter_proxy::tcp_adapter_proxy::async_setup_destination_tcp_sockets(tcp_adapter_context &tac)
    {
        for (auto m: tac.adapter_config.serviceId_to_endpoint_map)
        {
            string service_id = m.first;
            setup_tcp_socket(tac, service_id);
        }
    }

    void tcp_adapter_proxy::async_send_message_to_web_socket(tcp_adapter_context &tac, std::shared_ptr<boost::beast::flat_buffer> const& data_to_send, std::string const & service_id)
    {
        BOOST_LOG_SEV(log, trace) << "Sending messages over web socket for service id: " << service_id;
        BOOST_LOG_SEV(log, trace) << "Current queue size: " << tac.web_socket_outgoing_message_queue.size();
        // Always add to queue and invoke the send message complete
        if (data_to_send != nullptr)
        {
            BOOST_LOG_SEV(log, trace) << "Put data " << data_to_send->size() << " bytes into the web_socket_outgoing_message_queue for service id: " << service_id;
            tcp_connection::pointer socket_connection = get_tcp_connection(tac, service_id);
            data_message temp = std::make_pair(data_to_send, socket_connection->after_send_message);
            tac.web_socket_outgoing_message_queue.push(temp);
            // Are we already writing?
            if(tac.web_socket_outgoing_message_queue.size() > 1)
                return;
        }

        // We are not currently writing, so send this immediately
        data_message message_to_send = tac.web_socket_outgoing_message_queue.front();
        tac.wss->async_write(message_to_send.first->data(), [=, &tac](boost::system::error_code const &ec, std::size_t const bytes_sent)
        {
            if (ec)
            {
                throw proxy_exception("Error sending web socket message", ec);
            }
            BOOST_LOG_SEV(log, trace) << "Sent " << bytes_sent << " bytes over websocket for service id: " << service_id;
            std::function<void()> capture_after_send_message = message_to_send.second;
            tac.web_socket_outgoing_message_queue.pop();

            if(capture_after_send_message)
            {
                capture_after_send_message();
            }
            if(tac.web_socket_outgoing_message_queue.empty())
            {
                BOOST_LOG_SEV(log, trace) << "web_socket_outgoing_message_queue is empty, no more messages to send.";
                return;
            }
            async_send_message_to_web_socket(tac, nullptr, service_id);
        });
    }

    void tcp_adapter_proxy::async_setup_source_tcp_socket_retry(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config, string service_id)
    {
        tcp_server::pointer server = tac.serviceId_to_tcp_server_map[service_id];
        tcp_socket_ensure_closed(server->connection_->socket());
        server->acceptor_.close();

        static boost::asio::socket_base::reuse_address reuse_addr_option(true);

        tac.bind_address_actual = tac.adapter_config.bind_address.get_value_or(GET_SETTING(settings, DEFAULT_BIND_ADDRESS));
        BOOST_LOG_SEV(log, debug) << "Resolving bind address host: " << tac.bind_address_actual;

        std::string endpoint =  tac.adapter_config.serviceId_to_endpoint_map[service_id];
        tuple<string, string> endpoint_to_connect = get_host_and_port(endpoint, tac.bind_address_actual);
        std::string src_port = std::get<1>(endpoint_to_connect);
        std::uint16_t port_to_connect = boost::lexical_cast<std::uint16_t>(src_port);
        BOOST_LOG_SEV(log, debug) << "Port to connect " << port_to_connect;
        server->resolver_.async_resolve(tac.bind_address_actual, src_port,
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
                    server->acceptor_.open(results->endpoint().protocol());
                    if (port_to_connect)
                    {   //if data port is 0 (means pick an empheral port), then don't set this option
                        server->acceptor_.set_option(reuse_addr_option);
                    }
                    server->acceptor_.bind(results->endpoint(), bind_ec);
                    if (bind_ec)
                    {
                        BOOST_LOG_SEV(log, error) << (boost::format("Could not bind to address: %1%:%2% -- %3%") % results->endpoint().address().to_string() % results->endpoint().port() % bind_ec.message()).str();
                        basic_retry_execute(log, retry_config,
                            []() { throw proxy_exception(SOURCE_LOCAL_PROXY_PORT_BIND_EXCEPTION); });
                    }
                    else
                    {
                        std::uint16_t local_port = static_cast<std::uint16_t>(server->acceptor_.local_endpoint().port());
                        BOOST_LOG_SEV(log, info) << "Listening for new connection on port " << local_port;
                        boost::system::error_code listen_ec;
                        server->acceptor_.listen(0, listen_ec);
                        if (listen_ec)
                        {
                            BOOST_LOG_SEV(log, error) << (boost::format("Could not listen on bind address: %1%:%2% -- %3%")
                                % results->endpoint().address().to_string() % local_port % listen_ec.message()).str();
                            basic_retry_execute(log, retry_config,
                                []() { throw proxy_exception(SOURCE_LOCAL_PROXY_PORT_BIND_EXCEPTION); });
                        }
                        else
                        {
                            if (port_to_connect == 0 && tac.adapter_config.on_listen_port_assigned)
                            {
                                tac.adapter_config.on_listen_port_assigned(local_port, service_id);
                            }
                            server->acceptor_.async_accept(
                                    [=, &tac](boost::system::error_code const &ec, boost::asio::ip::tcp::socket new_socket)
                            {

                                if (ec)
                                {
                                    BOOST_LOG_SEV(log, error) << (boost::format("Could not listen/accept incoming connection on %1%:%2% -- %3%")
                                        % tac.bind_address_actual % local_port % ec.message()).str();
                                    basic_retry_execute(log, retry_config,
                                        [=, &ec]() { throw std::runtime_error((boost::format("Failed to accept new connection on %1% -- %2%") % local_port % ec.message()).str()); });
                                }
                                else
                                {
                                    BOOST_LOG_SEV(log, debug) << "socket port " << new_socket.local_endpoint().port();
                                    string endpoint = boost::lexical_cast<std::string>(new_socket.local_endpoint().port());
                                    BOOST_LOG_SEV(log, debug) << "endpoint mapping:";
                                    for (auto m: tac.adapter_config.serviceId_to_endpoint_map)
                                    {
                                        BOOST_LOG_SEV(log, debug) << m.first << " = " << m.second;
                                    }
                                    tcp_server::pointer server = tac.serviceId_to_tcp_server_map[service_id];
                                    server->connection_->socket() = std::move(new_socket);
                                    BOOST_LOG_SEV(log, info) << "Accepted tcp connection on port " << server->connection_->socket().local_endpoint().port() << " from " << server->connection_->socket().remote_endpoint();
                                    invoke_and_clear_handler(server->after_setup_tcp_socket);
                                }
                            });
                        }
                    }
                }
            });
    }

    void tcp_adapter_proxy::async_resolve_destination_for_connect(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config, string const & service_id, boost::system::error_code const &ec, tcp::resolver::results_type results)
    {
        BOOST_LOG_SEV(log, trace) << "Resolve destination to connect for service id: " << service_id;
        if (ec)
        {
            string endpoint = tac.adapter_config.serviceId_to_endpoint_map[service_id];
            BOOST_LOG_SEV(log, error) << (boost::format("Could not resolve endpoint %1%. Error message: %2%") % endpoint % ec.message()).str();
            basic_retry_execute(log, retry_config,
                [this, &tac, service_id]()
                {
                    tcp_connection::pointer socket_connection = get_tcp_connection(tac, service_id);
                    socket_connection->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac), service_id);
                    async_send_stream_reset(tac, service_id);
                });
        }
        else {
            tcp_client::pointer client = tac.serviceId_to_tcp_client_map[service_id];
            std::string dst_host = results->endpoint().address().to_string();
            unsigned short dst_port = results->endpoint().port();
            BOOST_LOG_SEV(log, debug) << "Resolved destination host to IP: " << dst_host << " , connecting ...";
            client->connection_->socket().async_connect(*results.begin(),
                [=, &tac](boost::system::error_code const &ec)
                {
                    if (ec)
                    {
                        BOOST_LOG_SEV(log, error) << (boost::format("Could not connect to destination %1%:%2% -- %3%") % dst_host % dst_host % ec.message()).str();
                        basic_retry_execute(log, retry_config,
                            [this, &tac, service_id]()
                            {
                                tcp_connection::pointer socket_connection = get_tcp_connection(tac, service_id);
                                socket_connection->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac), service_id);
                                async_send_stream_reset(tac, service_id);
                            });
                    }
                    else
                    {
                        BOOST_LOG_SEV(log, info) << "Connected to " << dst_host << ", port: " << dst_port;
                        tcp_client::pointer client = tac.serviceId_to_tcp_client_map[service_id];
                        invoke_and_clear_handler(client->after_setup_tcp_socket);
                    }
                }
            );
        }
    }

    void tcp_adapter_proxy::async_setup_dest_tcp_socket(tcp_adapter_context &tac, string const & service_id)
    {
        BOOST_LOG_SEV(log, trace) << "Setup destination tcp socket for service id" << service_id;
        std::shared_ptr<basic_retry_config> retry_config = 
            std::make_shared<basic_retry_config>(tac.io_ctx,
                GET_SETTING(settings, TCP_CONNECTION_RETRY_COUNT),
                GET_SETTING(settings, TCP_CONNECTION_RETRY_DELAY_MS),
                nullptr);
        retry_config->operation = std::bind(&tcp_adapter_proxy::async_setup_dest_tcp_socket_retry, this, std::ref(tac), retry_config, service_id);
        async_setup_dest_tcp_socket_retry(tac, retry_config, service_id);
    }

    void tcp_adapter_proxy::async_setup_dest_tcp_socket_retry(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config, string const & service_id)
    {
        tcp_client::pointer client = tac.serviceId_to_tcp_client_map[service_id];
        tcp_socket_ensure_closed(client->connection_->socket());
        if (tac.adapter_config.serviceId_to_endpoint_map.find((service_id)) == tac.adapter_config.serviceId_to_endpoint_map.end())
        {
            throw std::runtime_error((boost::format("Receive invalid service id %1%") % service_id).str());
        }
        std::string endpoint = tac.adapter_config.serviceId_to_endpoint_map[service_id];

        BOOST_LOG_SEV(log, info) << "Attempting to establish tcp socket connection to: " << endpoint;

        if (tac.adapter_config.bind_address.has_value())
        {
            BOOST_LOG_SEV(log, debug) << "Resolving local address host: " << tac.adapter_config.bind_address.get();
            client->resolver_.async_resolve(tac.adapter_config.bind_address.get(), boost::lexical_cast<std::string>("0"),
                boost::asio::ip::resolver_base::passive,
                [=, &tac](boost::system::error_code const &ec, tcp::resolver::results_type results)
                {
                    if (ec)
                    {
                        BOOST_LOG_SEV(log, error) << (boost::format("Could not resolve bind address: %1% -- %2%") % tac.adapter_config.bind_address.get() % ec.message()).str();
                        basic_retry_execute(log, retry_config,
                            [this, &tac, service_id]()
                            {
                                tcp_connection::pointer socket_connection = get_tcp_connection(tac, service_id);
                                socket_connection->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac), service_id);
                                async_send_stream_reset(tac, service_id);
                            });
                    }
                    else
                    {
                        BOOST_LOG_SEV(log, debug) << "Resolved bind IP: " << results->endpoint().address().to_string();
                        boost::system::error_code bind_ec;

                        client->connection_->socket().open(results->endpoint().protocol());
                        client->connection_->socket().bind({results->endpoint().address(), 0}, bind_ec);
                        if (bind_ec)
                        {
                            BOOST_LOG_SEV(log, error) << (boost::format("Could not bind to address: %1% -- %2%") % results->endpoint().address().to_string() % bind_ec.message()).str();
                            basic_retry_execute(log, retry_config,
                                [this, &tac, service_id]()
                                {
                                    tcp_connection::pointer socket_connection = get_tcp_connection(tac, service_id);
                                    socket_connection->after_send_message = std::bind(&tcp_adapter_proxy::setup_tcp_socket, this, std::ref(tac), service_id);
                                    async_send_stream_reset(tac, service_id);
                                });
                        }
                        else
                        {
                            tuple<string, string> endpoint_to_connect = tcp_adapter_proxy::get_host_and_port(endpoint, tac.adapter_config.bind_address.get());
                            std::string dst_host = std::get<0>(endpoint_to_connect);
                            std::string dst_port = std::get<1>(endpoint_to_connect);
                            client->resolver_.async_resolve(dst_host, dst_port,
                                std::bind(&tcp_adapter_proxy::async_resolve_destination_for_connect, this, std::ref(tac), retry_config, service_id, std::placeholders::_1, std::placeholders::_2));
                        }
                    }
                });
        }
        else
        {
            tuple<string, string> endpoint_to_connect = tcp_adapter_proxy::get_host_and_port(endpoint, LOCALHOST_IP);
            std::string dst_host = std::get<0>(endpoint_to_connect);
            std::string dst_port = std::get<1>(endpoint_to_connect);
            BOOST_LOG_SEV(log, trace) << "Resolving destination host: " << dst_host << " port: " << dst_port;
            client->resolver_.async_resolve(dst_host, dst_port,
                std::bind(&tcp_adapter_proxy::async_resolve_destination_for_connect, this, std::ref(tac), retry_config, service_id, std::placeholders::_1, std::placeholders::_2));
        }
    }

    void tcp_adapter_proxy::tcp_socket_ensure_closed(tcp::socket & tcp_socket)
    {
        boost::system::error_code ec;
        if (tcp_socket.is_open())
        {
            BOOST_LOG_SEV(log, debug) << "Previously open connection detected. Closing...";
            auto remote_endpoint = tcp_socket.remote_endpoint(ec);
            if (!ec)
            {
                BOOST_LOG_SEV(this->log, info) << "Disconnected from: " << remote_endpoint;
            }
            tcp_socket.close();
        }
    }

    void tcp_adapter_proxy::clear_ws_buffers(tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Clearing all ws data buffers";
        incoming_message_buffer.consume(incoming_message_buffer.max_size());
        message_parse_buffer.consume(message_parse_buffer.max_size());
        BOOST_LOG_SEV(log, trace) << "Finished Clearing all ws data buffers";
    }

    void tcp_adapter_proxy::clear_tcp_connection_buffers(tcp_connection::pointer connection)
    {
        BOOST_LOG_SEV(log, trace) << "Clearing tcp connection buffers";
        connection->tcp_read_buffer_.consume(connection->tcp_read_buffer_.max_size());
        connection->tcp_write_buffer_.consume(connection->tcp_write_buffer_.max_size());
        connection->web_socket_data_write_buffer_.consume(connection->web_socket_data_write_buffer_.max_size());
    }

    bool tcp_adapter_proxy::is_valid_stream_id(tcp_adapter_context const& tac, message const &message)
    {
        if (MESSAGE_TYPES_VALIDATING_STREAM_ID.find(message.type()) != MESSAGE_TYPES_VALIDATING_STREAM_ID.end())
        {
            string service_id = message.serviceid();
            // v1 message format does not need to validate service id. Set to the one service id stored in memory.
            if (tac.adapter_config.is_v1_message_format)
            {
                service_id = tac.adapter_config.serviceId_to_endpoint_map.cbegin()->first;
            }
            else if (tac.serviceId_to_streamId_map.find(service_id) == tac.serviceId_to_streamId_map.end())
            {
                BOOST_LOG_SEV(log, warning) << "No stream found for service id: " << service_id << ". Ignore stream id: " << message.streamid();
                return false;
            }
            int32_t stream_id = tac.serviceId_to_streamId_map.at(service_id);
            if (message.streamid() == 0)
            {
                BOOST_LOG_SEV(log, warning) << "Message recieved with streamid not set";
                return false;
            }
            return stream_id == message.streamid();
        }
        return true;
    }

    bool tcp_adapter_proxy::tcp_has_enough_write_buffer_space(tcp_connection::pointer connection)
    {   //tcp write buffer needs at least enough space to hold a max data size web socket message
        //because we can't limit how much data we might recieve next frame
        return (connection->tcp_write_buffer_.max_size() - connection->tcp_write_buffer_.size()) >= GET_SETTING(settings, MESSAGE_MAX_PAYLOAD_SIZE);
    }

    // Check if all tcp write buffers have space. If one of them does not have enough, return false
    bool tcp_adapter_proxy::tcp_has_enough_write_buffer_space(tcp_adapter_context const &tac)
    {
            bool has_enough_space = true;
            for (auto m : tac.serviceId_to_tcp_client_map)
            {
                string service_id = m.first;
                tcp_connection::pointer connection = m.second->connection_;
                if ( (connection->tcp_write_buffer_.max_size() - connection->tcp_write_buffer_.size()) < GET_SETTING(settings, MESSAGE_MAX_PAYLOAD_SIZE) )
                {
                    has_enough_space = false;
                    break;
                }
            }
        return has_enough_space;
    }

    bool tcp_adapter_proxy::wss_has_enough_write_buffer_space(boost::beast::multi_buffer const &buffer)
    {   //web socket write buffer only needs non-zero space because we can make TCP read
        //calls that limit the data recieved

        return (buffer.max_size() - buffer.size()) > 0;
    }

    /**
     * Given a string of endpoint, returns the boost tcp endpoint.
     */
    std::tuple<std::string, std::string> tcp_adapter_proxy::get_host_and_port( const std::string & endpoint, const std::string & default_host)
    {
        std::tuple<std::string, std::string> res;
        std::vector<std::string> split_res;
        std::string endpoint_to_process = endpoint;
        std::string port;
        std::string host;
        transform(endpoint_to_process.begin(), endpoint_to_process.end(), endpoint_to_process.begin(), ::tolower);
        boost::split(split_res, endpoint_to_process, boost::is_any_of(":"));

        if (split_res.empty()) {
            throw std::runtime_error("Must provide at least one port or host name/ip!");
        }
        else if (split_res.size() == 1)
        {
            boost::trim(split_res[0]);
            res = std::make_tuple(default_host, split_res[0]);
        }
        else if (split_res.size() == 2)
        {
            boost::trim(split_res[0]);
            boost::trim(split_res[1]);
            res = std::make_tuple(split_res[0], split_res[1]);
        }
        else
        {
            // If step in this case, it means host name has delimiter ":"
            uint16_t hostname_len = endpoint_to_process.size() - split_res[split_res.size()-1].size();
            host = endpoint_to_process.substr(0, hostname_len);
            boost::trim(split_res[split_res.size()-1]);
            BOOST_LOG_SEV(log, trace) << "host name: " << host;
            res = std::make_tuple(host, split_res[split_res.size()-1]);
        }
        return res;
    }

    void tcp_adapter_proxy::handle_listen_port_assigned(const std::uint16_t & port_assigned, const std::string & service_id, tcp_adapter_context &tac)
    {
        BOOST_LOG_SEV(log, trace) << "Handling source listening port assigned";
        // Update service_id <-> endpoint mapping
        tac.adapter_config.serviceId_to_endpoint_map[service_id] = boost::lexical_cast<std::string>(port_assigned);

        // Output new port mapping to user
        BOOST_LOG_TRIVIAL(info) << "Listen port assigned for service id " << service_id << ". New port mapping: ";
        BOOST_LOG_TRIVIAL(info) << service_id << " = " << port_assigned;
    }

    bool tcp_adapter_proxy::fall_back_to_v1_message_format(std::unordered_map<std::string, std::string> const & serviceId_to_endpoint_map)
    {
        if (serviceId_to_endpoint_map.size() == 1 && serviceId_to_endpoint_map.begin()->first.empty())
        {
            return true;
        }
        else
        {
            return false;
        }
    }
}}}
