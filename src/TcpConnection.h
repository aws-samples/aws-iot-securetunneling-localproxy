// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/beast/core/multi_buffer.hpp>
#include "Message.pb.h"

namespace aws { namespace iot { namespace securedtunneling { namespace connection {
    using message = com::amazonaws::iot::securedtunneling::Message;
    using boost::asio::ip::tcp;
    class tcp_connection
            : public boost::enable_shared_from_this<tcp_connection>
    {
    public:
        typedef boost::shared_ptr<tcp_connection> pointer;

        static pointer create(boost::asio::io_context& io_context, std::size_t const & write_buf_size, std::size_t const & read_buf_size, std::size_t ws_write_buf_size)
        {
            return pointer(new tcp_connection(io_context, write_buf_size, read_buf_size, ws_write_buf_size));
        }

       tcp::socket& socket()
        {
            return socket_;
        }

        tcp_connection(boost::asio::io_context & io_context, std::size_t write_buf_size, std::size_t read_buf_size, std::size_t ws_write_buf_size)
                : socket_(io_context)
                , tcp_write_buffer_(write_buf_size)
                , tcp_read_buffer_(read_buf_size)
                , web_socket_data_write_buffer_(ws_write_buf_size)
        {
        }

        tcp::socket                                             socket_;
        // A buffer holding data writes to customer's application
        boost::beast::multi_buffer                              tcp_write_buffer_;
        // A buffer holding data reads from customer's application
        boost::beast::flat_buffer                               tcp_read_buffer_;
        /**
         * A buffer holding data that will be sent to secure tunneling server through web socket connection.
         * This buffer will only hold data belongs to its own stream in a multiplexed tunnel.
         */
        boost::beast::flat_buffer                               outgoing_message_buffer_;
        //Buffer sequence storing the raw bytes read from the tcp socket reads
        //to send over web socket. The bytes in this buffer represent the raw application
        //data not already packaged in protobuf messages. This allows us to
        //condense smaller TCP read chunks to bigger web socket writes. It also makes
        //it impossible to "inject" a non-data message in data sequence order
        boost::beast::multi_buffer                              web_socket_data_write_buffer_;
        // Is this tcp socket currently writing
        bool                                                    is_tcp_socket_writing_{ false };
        // Is this tcp socket currently reading
        bool                                                    is_tcp_socket_reading_{ false };
        // function object defines what to do after send a message
        std::function<void()>                                   after_send_message;
        // function object defines what to do upon receiving control message
        std::function<bool(message const &)>                    on_control_message = nullptr;
        // function object defines what to do upon receiving data message
        std::function<bool(message const &)>                    on_data_message = nullptr;
        // function object defines what to do if there is a tcp error occurred
        std::function<void(boost::system::error_code const&)>   on_tcp_error = nullptr;
        // function object defines what to do when tcp_write_buffer_ drain has completed
        std::function<void()>                                   on_tcp_write_buffer_drain_complete = nullptr;
        // function object defines what to do when web_socket_data_write_buffer_ drain has completed
        std::function<void()>                                   on_web_socket_write_buffer_drain_complete = nullptr;
    };
}}}}