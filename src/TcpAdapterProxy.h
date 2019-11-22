// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>
#include <functional>
#include <vector>
#include <memory>
#include <boost/log/trivial.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/optional.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl/rfc2818_verification.hpp>
#include <boost/format.hpp>
#include <boost/property_tree/ptree.hpp>
#include "ProxySettings.h"
#include "Message.pb.h"

namespace aws { namespace iot { namespace securedtunneling {
    enum proxy_mode {
        UNKNOWN = 0,
        SOURCE = 1,
        DESTINATION = 2
    };
    
    extern std::uint16_t const DEFAULT_PROXY_SERVER_PORT;

    struct adapter_proxy_config
    {
        std::string                             proxy_host { };
        std::uint16_t                           proxy_port{ 0 };
        std::string                             access_token { };
        proxy_mode                              mode{ proxy_mode::UNKNOWN };
        std::string                             data_host { };
        std::uint16_t                           data_port { 0 };
        boost::optional<std::string>            bind_address;
        boost::optional<std::string>            additional_ssl_verify_path;
        bool                                    no_ssl_host_verify;
        std::function<void(std::uint16_t)>      on_listen_port_assigned;
    };

    namespace
    {
        using boost::asio::io_context;
        using boost::asio::ip::tcp;
        using boost::property_tree::ptree;
        using std::shared_ptr;

#ifdef _AWSIOT_TUNNELING_NO_SSL
        using web_socket_stream = boost::beast::websocket::stream<boost::asio::ip::tcp::socket>;
#else
        using web_socket_stream = boost::beast::websocket::stream<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>;
#endif

        using message = com::amazonaws::iot::securedtunneling::Message;
        using logger = boost::log::sources::severity_logger<boost::log::trivial::severity_level>;

        class proxy_exception : public std::exception
        {
        public:
            explicit proxy_exception(std::string const & message) : message(message) {}
            proxy_exception(std::string const & message, boost::system::error_code const & ec)
                : message{ (boost::format("%1%; Underlying boost::system error: [%2%]") % message%ec.message()).str() }, boost_error_code(boost::make_optional(ec)) {}
            proxy_exception(boost::system::error_code const & ec)
                : message{ (boost::format("Boost::System error: [%1%]") % ec.message()).str() }, boost_error_code(boost::make_optional(ec)) {}
            virtual char const * what() const noexcept { return message.c_str(); }
            boost::optional<boost::system::error_code const> error_code() const { return boost_error_code; }

            proxy_exception(proxy_exception const &) = default;
            ~proxy_exception() = default;

        protected:
            std::string                                             message;
            boost::optional<boost::system::error_code const>        boost_error_code;   //boost system error code if the cause
        };

        //this structure is pretty much *the* program visibility of all
        //async function handlers so it's likely to get a bit disorganized
        struct tcp_adapter_context
        {
            tcp_adapter_context(adapter_proxy_config const & cfg, ptree const &settings) :
                io_ctx{ },
                ec{ },
                adapter_config{ cfg },
                acceptor{ io_ctx },
                resolver{ io_ctx },
                ssl_ctx{ boost::asio::ssl::context::sslv23 },
                wss{ nullptr },
                wss_response{ },
                tcp_socket{ io_ctx },
                stream_id{ -1 },
                local_port{ 0 },
                bind_address_actual{ },
                is_web_socket_writing{ false },
                is_web_socket_reading{ false },
                is_tcp_socket_writing{ false },
                is_tcp_socket_reading{ false }
            { }

            boost::asio::io_context                 io_ctx;
            boost::system::error_code               ec;
            adapter_proxy_config const &            adapter_config;

            tcp::acceptor                           acceptor;
            tcp::resolver                           resolver;
            boost::asio::ssl::context               ssl_ctx;

            shared_ptr<web_socket_stream>           wss;
            //response of current wss connection upgrade request
            //we need this somewhere because it can(should) contain
            //information identifying this websocket connection
            //instance that we can tag operations/logging with for better
            //debuggability.
            boost::beast::websocket::response_type  wss_response;

            tcp::socket                             tcp_socket;
            //represents the current stream ID to expect data from
            //care should be taken how(if) this is updated directly
            std::int32_t                            stream_id;
            std::uint16_t                           local_port;
            std::string                             bind_address_actual;
            //flag set to true while web socket data is being drained
            //necessary for better TCP socket recovery rather than destroying
            //what's in the buffer
            bool                                    is_web_socket_writing;
            //flag neccessary to know on TCP resets whether or not web socket
            //has a current read (usually should, but may not if 
            bool                                    is_web_socket_reading;
            //used to ensure command resets of TCP don't schedule multiple
            //drains on TCP
            bool                                    is_tcp_socket_writing;

            bool                                    is_tcp_socket_reading;
        };

        //simple re-usable structure for a basic retry strategy's state
        struct basic_retry_config
        {
            basic_retry_config(boost::asio::io_context &ctx, std::int32_t count, std::uint32_t delay_ms, std::function<void()> op) :
                timer{ ctx },
                count{ count },
                delay{ std::chrono::milliseconds(delay_ms) },
                operation{ op } {}
            boost::asio::steady_timer           timer;
            std::int32_t                        count;
            std::chrono::milliseconds const     delay;
            std::function<void()>               operation;
        };
    };

    class tcp_adapter_proxy
    {
    public:
        tcp_adapter_proxy() = delete;
        tcp_adapter_proxy(ptree const &settings, adapter_proxy_config const &config);

        ~tcp_adapter_proxy();
        tcp_adapter_proxy(tcp_adapter_proxy const &) = delete;
        tcp_adapter_proxy(tcp_adapter_proxy &&) = default;

        void run_proxy();

    private:
        void setup_tcp_socket(tcp_adapter_context &tac);
        //setup async io flow to connect tcp socket to the adapter config's data host/port
        void async_setup_dest_tcp_socket(tcp_adapter_context &tac);
        void async_setup_dest_tcp_socket_retry(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config);
        void async_setup_source_tcp_socket(tcp_adapter_context &tac);
        void async_setup_source_tcp_socket_retry(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config);
        std::function<void()> after_setup_tcp_socket = nullptr;

        void setup_web_socket(tcp_adapter_context &tac);

        //setup async web socket, and as soon as connection is up, setup async ping schedule
        void async_setup_web_socket(tcp_adapter_context &tac);
        std::function<void()> after_setup_web_socket = nullptr;

        //Call in order to close and reset the TCP connection. If error code is set
        //then the reset is intentionally reset via web socket, and retries
        //occur definitely (regardless of retry configuration)
        void tcp_socket_reset(tcp_adapter_context &tac, std::function<void()> then_what);

        void tcp_socket_error(tcp_adapter_context &tac, boost::system::error_code const &_ec);

        //sets up a web socket read loop that will read, and ignore most messages until a stream start
        //is read and then do something with it (likely, connect to configured endpoint)
        void async_web_socket_read_until_stream_start(tcp_adapter_context &tac);
        std::function<void()> on_recieve_stream_start = nullptr;


        void async_setup_bidirectional_data_transfers(tcp_adapter_context &tac);
        
        //setup async web socket repeat loop
        void async_web_socket_read_loop(tcp_adapter_context &tac);

        //handlers for messages during the web socket read loop return false
        //if the read loop should be stopped after processing the message.
        //This might happen due to tcp write buffer being full, or the processing
        //requires some destructive actions before contructing a new TCP connection
        //followed by data
        void on_web_socket_read(tcp_adapter_context &tac, boost::system::error_code const &ec, size_t bytes_read);

        std::function<bool(message const &)> on_control_message = nullptr;
        std::function<bool(message const &)> on_data_message = nullptr;
        bool ignore_message(tcp_adapter_context &tac, message const &message);
        bool ignore_message_and_stop(tcp_adapter_context &tac, message const &message);
        bool forward_data_message_to_tcp_write(tcp_adapter_context &tac, message const &message);
        bool handle_control_message_data_transfer(tcp_adapter_context &tac, message const &message);

        //invokes after_setup_web_socket_read_until_stream_start() after stream start is encountered
        bool async_wait_for_stream_start(tcp_adapter_context &tac, message const &message);

        void async_tcp_socket_read_loop(tcp_adapter_context &tac);
        //if the below handler is set and an error occurs, call it to handle the tcp error
        //rather than invoking the standard tcp error handling path
        std::function<void(boost::system::error_code const&)> on_tcp_error = nullptr;

        //below loop does continuous writes to TCP socket from the TCP adapter
        //context's tcp_write_buffer. After consuming chunks out of the buffer
        //the behavior will be to check 
        void async_tcp_write_buffer_drain(tcp_adapter_context &tac);
        std::function<void()> on_tcp_write_buffer_drain_complete = nullptr;
        
        void async_setup_web_socket_write_buffer_drain(tcp_adapter_context &tac);
        std::function<void()> on_web_socket_write_buffer_drain_complete;

        //returns a boolean that indicates if another web socket data read message can be put
        //onto the tcp write buffer. We have no way of knowing what the next message is and if
        //it will be too big to process, thus we don't do the read applying back pressure on
        //the socket. Implicitly, this means that an async_read is not happening on the web socket
        bool tcp_has_enough_write_buffer_space(tcp_adapter_context const &tac);

        //returns a boolean that indicates if another tcp socket read's data can be put on the
        //web socket write buffer. It's a bit different from tcp write buffer space requirements
        //because we can limit the amout of data we pull from a read, even a single byte means we
        //can perform the read.
        //Not setting up the read applies back pressure on the tcp socket
        bool wss_has_enough_write_buffer_space(tcp_adapter_context const &tac);

        void handle_web_socket_control_message(tcp_adapter_context &tac, boost::beast::websocket::frame_type kind, boost::beast::string_view payload);

        bool is_valid_stream_id(tcp_adapter_context const& tac, message const &message);

        //same handler used to send any message
        std::function<void()> after_send_message;
        void async_send_message(tcp_adapter_context &tac, message const &message);
        void async_send_stream_start(tcp_adapter_context &tac);
        void async_send_stream_reset(tcp_adapter_context &tac, std::int32_t stream_id);

        //handler for successfully sent ping will delay the next one
        void async_ping_handler_loop(tcp_adapter_context &tac,
            std::shared_ptr<boost::beast::websocket::ping_data> ping_data,
            std::shared_ptr<std::chrono::milliseconds> ping_period,
            std::shared_ptr<boost::asio::steady_timer> ping_timer,
            boost::system::error_code const &ec);

        void clear_buffers();

        void tcp_socket_ensure_closed(tcp_adapter_context &tac);

        //closes the websocket connection
        //1 - shutdown the receive side of TCP
        //2 - drain the web socket write buffer
        //3 - send a web socket close frame
        //4 - perform teardown procedure on websocket
        void web_socket_close_and_stop(tcp_adapter_context &tac);

        void async_resolve_destination_for_connect(tcp_adapter_context &tac, std::shared_ptr<basic_retry_config> retry_config, boost::system::error_code const &ec, tcp::resolver::results_type results);

        bool process_incoming_websocket_buffer(tcp_adapter_context &tac, boost::beast::multi_buffer &message_buffer);

        bool parse_protobuf_and_consume_input(boost::beast::multi_buffer &message_buffer, size_t data_length, message &msg);

    private:
        logger                                      log;
        ptree const &                               settings;
        adapter_proxy_config const &                adapter_config;
        //below messages are re-used by local functions/callbacks as necessary to put the data in the
        //right object (protobuf) then serialize to a Boost Asio buffer to actually send/recv
        message                                     outgoing_message;
        boost::beast::flat_buffer                   outgoing_message_buffer;
        message                                     incoming_message;
        boost::beast::multi_buffer                  incoming_message_buffer;
        boost::beast::flat_buffer                   message_parse_buffer;

        boost::beast::multi_buffer                  tcp_write_buffer;
        boost::beast::flat_buffer                   tcp_read_buffer;

        //Buffer sequence storing the raw bytes read from the tcp socket reads
        //to send over web socket. The bytes in this buffer represent the raw application
        //data not already packaged in protobuf messages. This allows us to
        //condense smaller TCP read chunks to bigger web socket writes. It also makes
        //it impossible to "inject" a non-data message in data sequence order
        boost::beast::multi_buffer                  web_socket_data_write_buffer;
    };
}}}
