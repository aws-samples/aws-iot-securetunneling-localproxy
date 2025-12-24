// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include "TcpConnection.h"
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <unordered_map>

namespace aws {
namespace iot {
    namespace securedtunneling {
        namespace connection {
            using boost::asio::ip::tcp;

            class tcp_server {
            public:
                typedef boost::shared_ptr<tcp_server> pointer;

                tcp_server(
                    boost::asio::io_context &io_context,
                    std::size_t write_buf_size,
                    std::size_t read_buf_size,
                    std::size_t ws_write_buf_size
                )
                    : acceptor_(io_context)
                    , resolver_(io_context) {
                    highest_connection_id = 0;
                }

                static pointer create(
                    boost::asio::io_context &io_context,
                    const std::size_t &write_buf_size,
                    const std::size_t &read_buf_size,
                    const std::size_t &ws_write_buf_size
                ) {
                    return pointer(new tcp_server(
                        io_context,
                        write_buf_size,
                        read_buf_size,
                        ws_write_buf_size
                    ));
                }

                tcp::acceptor &acceptor() {
                    return acceptor_;
                }

                tcp::acceptor acceptor_;
                tcp::resolver resolver_;

                std::unordered_map<uint32_t, tcp_connection::pointer>
                    connectionId_to_tcp_connection_map;

                std::atomic_uint32_t highest_connection_id;

                // function object defines what to do after set up a tcp socket
                std::function<void()> after_setup_tcp_socket = nullptr;
            };
        }
    }
}
}
