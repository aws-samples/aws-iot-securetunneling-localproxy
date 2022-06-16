// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <unordered_map>
#include "TcpConnection.h"

namespace aws { namespace iot { namespace securedtunneling { namespace connection {
    using boost::asio::ip::tcp;
    class tcp_server
    {
    public:
        typedef boost::shared_ptr<tcp_server> pointer;
        tcp_server(boost::asio::io_context & io_context, std::size_t write_buf_size, std::size_t read_buf_size, std::size_t ws_write_buf_size)
                : acceptor_(io_context)
                , resolver_(io_context)
        {
            highest_connection_id = 0;
        }

        static pointer create(boost::asio::io_context& io_context, std::size_t const & write_buf_size, std::size_t const & read_buf_size, std::size_t const & ws_write_buf_size)
        {
            return pointer(new tcp_server(io_context, write_buf_size, read_buf_size, ws_write_buf_size));
        }

        tcp::acceptor & acceptor()
        {
            return acceptor_;
        }

        tcp::acceptor                           acceptor_;
        tcp::resolver                           resolver_;

        // first connection ref used to setup tcp socket, has key value of "1" in the tcp connection map
        tcp_connection::pointer                 first_connection;
        std::unordered_map<uint32_t, tcp_connection::pointer> connectionId_to_tcp_connection_map;

        std::atomic_uint32_t highest_connection_id;

        // function object defines what to do after set up a tcp socket
        std::function<void()>                   after_setup_tcp_socket = nullptr;
    };
}}}}