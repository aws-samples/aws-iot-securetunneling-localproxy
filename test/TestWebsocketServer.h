// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "Message.pb.h"
#include <boost/asio.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/property_tree/ptree.hpp>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>

namespace aws {
namespace iot {
    namespace securedtunneling {
        namespace test {

            using boost::asio::ip::tcp;
            using web_socket_stream
                = boost::beast::websocket::stream<boost::asio::ip::tcp::socket>;
            using message = com::amazonaws::iot::securedtunneling::Message;
            using boost::property_tree::ptree;

            class TestWebsocketServer {
            public:
                TestWebsocketServer(
                    const std::string &address, const ptree &adapter_settings
                );

                tcp::endpoint get_endpoint() {
                    return acceptor.local_endpoint();
                }

                void close_client(
                    const std::string &close_reason,
                    boost::beast::websocket::close_code code
                );

                void expect_next_message(
                    std::function<bool(const message &)> predicate
                );

                void run();

                void deliver_message(const message &message);

                const boost::beast::http::request<
                    boost::beast::http::string_body> &
                get_handshake_request() {
                    return handshake_request;
                }

                void wait_for_handshake();

            protected:
                void process_input_buffer(
                    web_socket_stream &ws,
                    boost::beast::multi_buffer &message_buffer
                );
                void send_message(
                    web_socket_stream &ws, const message &message
                );
                bool parse_protobuf_and_consume_input(
                    boost::beast::multi_buffer &message_buffer,
                    size_t data_length,
                    message &msg
                );

                void on_read_complete(
                    web_socket_stream &ws,
                    const boost::system::error_code &ec,
                    size_t bytes_read
                );
                void on_read_message(
                    web_socket_stream &ws, const message &message
                );
                void on_write_complete(
                    web_socket_stream &ws,
                    const boost::system::error_code &ec,
                    size_t bytes_written
                );

                const ptree &adapter_settings;
                boost::asio::io_context io_ctx;
                boost::system::error_code ec;
                tcp::acceptor acceptor;
                bool closed;
                std::string close_reason;
                boost::beast::websocket::close_code code;
                boost::optional<web_socket_stream &> ws_stream;

                message incoming_message;
                boost::beast::multi_buffer incoming_message_buffer;
                boost::beast::flat_buffer message_parse_buffer;
                boost::beast::http::request<boost::beast::http::string_body>
                    handshake_request;

                std::queue<std::function<bool(const message &)>>
                    expect_messages;

                std::mutex handshake_mutex;
                std::condition_variable handshake_cv;
                bool handshake_complete { false };
            };

        }
    }
}
}
