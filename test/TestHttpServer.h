// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

using tcp = boost::asio::ip::tcp;
using string = std::string;
using boost::system::error_code;
namespace http = boost::beast::http;

namespace aws {
    namespace iot {
        namespace securedtunneling {
            namespace test {
                const string username = "user";
                const string password = "password";

                class Session : public std::enable_shared_from_this<Session> {
                    // This is the C++14 equivalent of a generic lambda.
                    // The function object is used to send an HTTP message.
                    struct send_lambda {
                        Session& self_;
                        explicit send_lambda(Session& self);
                        template<bool isRequest, class Body, class Fields>
                        void operator()(http::message<isRequest, Body, Fields>&& msg) const;
                    };
                    tcp::socket socket_;
                    boost::beast::flat_buffer buffer_;
                    http::request<http::string_body> req_;
                    std::shared_ptr<void> res_;
                    send_lambda lambda_;

                public:
                    explicit Session(tcp::socket socket);
                    void run();
                    void do_read();
                    void on_read(error_code ec, std::size_t bytes_transferred);
                    void on_write(error_code ec, std::size_t bytes_transferred, bool close);
                    void do_close();
                };

                class Listener : public std::enable_shared_from_this<Listener> {
                public:
                    tcp::acceptor acceptor_;
                    tcp::socket socket_;
                    Listener(boost::asio::io_context& ioc, const tcp::endpoint& endpoint);
                    void run();
                    void do_accept();
                    void on_accept(error_code ec);
                };

                class TestHttpServer {
                public:
                    boost::asio::ip::address address;
                    unsigned short port;
                    boost::asio::io_context ioc{};
                    std::shared_ptr<Listener> listener;
                    TestHttpServer(const string& address, const unsigned short port);
                    int run();
                    int stop();
                };
            }
        }
    }
}
