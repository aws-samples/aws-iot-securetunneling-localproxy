// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "TestHttpServer.h"

#include <boost/config.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>


using boost::beast::string_view;
namespace base64 = boost::beast::detail::base64;

/**
 * This Async server implementation is based on the following boost example
 * https://www.boost.org/doc/libs/1_68_0/libs/beast/example/http/server/async/http_server_async.cpp
 */

/**
 * This function produces an HTTP response for the given request.
 */
template<class Body, class Allocator, class Send>
void handle_request(http::request<Body, http::basic_fields<Allocator>>&& req, Send&& send) {
    // Returns a 4xx response
    auto const client_error =
            [&req](string_view why, http::status status) {
                http::response<http::string_body> res{status, req.version()};
                res.set(http::field::content_type, "text/html");
                res.keep_alive(req.keep_alive());
                res.body() = why.to_string();
                res.prepare_payload();
                return res;
            };
    // Returns a 500 response
    auto const server_error =
            [&req](boost::beast::string_view what)
            {
                http::response<http::string_body> res{http::status::internal_server_error, req.version()};
                res.set(http::field::content_type, "text/html");
                res.keep_alive(req.keep_alive());
                res.prepare_payload();
                return res;
            };


    // Make sure we can handle the method
    if( req.method() != http::verb::connect)
        return send(client_error("Unknown HTTP-method", http::status::bad_request));

    // We will use the auth information to indicate to the server how respond so that we can test how
    // the HTTPS Proxy adapter will handle different scenarios
    std::string encoded_auth{req[http::field::proxy_authorization]};
    if (!encoded_auth.empty()) {
        std::string incoming_auth;
        incoming_auth.resize(base64::decoded_size(encoded_auth.size()));
        auto const result = base64::decode(&incoming_auth[0], encoded_auth.substr(6).data(), encoded_auth.length() - 6);
        incoming_auth.resize(result.first);
        string allowed_auth = aws::iot::securedtunneling::test::username + ":" + aws::iot::securedtunneling::test::password;
        if (!incoming_auth.empty() && incoming_auth == "500")
            return send(server_error("Server failure"));

        if (!incoming_auth.empty() && incoming_auth == "300")
            return send(client_error("REDIRECT", http::status::permanent_redirect));

        if (!incoming_auth.empty() && incoming_auth == "100")
            return send(client_error("UNKNOWN", http::status::processing));

        if (!incoming_auth.empty() && incoming_auth != allowed_auth)
            return send(client_error("ACCESS DENIED", http::status::forbidden));
    }

    // Respond to CONNECT request
    http::response<http::string_body> res{http::status::ok, 11};
    return send(std::move(res));
}

void fail(error_code ec, char const* what) {
    std::cerr << what << ": " << ec.message() << "\n";
}

namespace aws {
    namespace iot {
        namespace securedtunneling {
            namespace test {

                TestHttpServer::TestHttpServer(const string& address, const unsigned short port) :
                        port(port) {
                    this->address = boost::asio::ip::make_address(address);
                    this->listener = std::make_shared<Listener>(ioc, tcp::endpoint{this->address, port});
                    this->listener->run();
                }

                int TestHttpServer::run() {
                    ioc.run();
                    return EXIT_SUCCESS;
                }

                int TestHttpServer::stop() {
                    ioc.stop();
                    return EXIT_SUCCESS;
                }

                Session::send_lambda::send_lambda(Session &self) : self_(self) { }
                
                template<bool isRequest, class Body, class Fields>
                void Session::send_lambda::operator()(http::message<isRequest, Body, Fields> &&msg) const {
                    // The lifetime of the message has to extend for the duration of the async operation so
                    // we use a shared_ptr to manage it.
                    auto sp = std::make_shared<
                            http::message<isRequest, Body, Fields>>(std::move(msg));

                    // Store a type-erased version of the shared pointer in the class to keep it alive.
                    self_.res_ = sp;

                    // Write the response
                    http::async_write(self_.socket_, *sp, [self = self_.shared_from_this(), need_eof = sp->need_eof()]
                            (const error_code & ec, const std::size_t & bytes_transferred) {
                        self->on_write(ec, bytes_transferred, need_eof);
                    });
                }

                Session::Session(tcp::socket socket)
                : socket_(std::move(socket))
                , lambda_(*this) { }

                void Session::run() {
                    do_read();
                }

                void Session::do_read() {
                    // Make the request empty before reading, otherwise the operation behavior is undefined.
                    req_ = {};

                    // Read a request
                    http::async_read(socket_, buffer_, req_,[self = shared_from_this()]
                            (const error_code & ec, const std::size_t & bytes_transferred) {
                        self->on_read(ec, bytes_transferred);
                    });
                }

                void Session::on_read(error_code ec, std::size_t bytes_transferred) {
                    boost::ignore_unused(bytes_transferred);

                    // This means they closed the connection
                    if(ec == http::error::end_of_stream)
                        return do_close();

                    if(ec)
                        return fail(ec, "read");

                    // Send the response
                    handle_request(std::move(req_), lambda_);
                }

                void Session::on_write(error_code ec, std::size_t bytes_transferred, bool close) {
                    boost::ignore_unused(bytes_transferred);

                    if(ec)
                        return fail(ec, "write");

                    if(close) {
                        // This means we should close the connection, usually because
                        // the response indicated the "Connection: close" semantic.
                        return do_close();
                    }

                    // We're done with the response so delete it
                    res_ = nullptr;

                    // Read another request
                    do_read();
                }

                void Session::do_close() {
                    error_code ec;
                    socket_.shutdown(tcp::socket::shutdown_send, ec);
                }

                Listener::Listener(boost::asio::io_context& ioc, const tcp::endpoint& endpoint)
                        : acceptor_(ioc) , socket_(ioc) {
                    error_code ec;
                    acceptor_.open(endpoint.protocol(), ec);
                    if(ec) {
                        fail(ec, "open");
                        return;
                    }
                    acceptor_.set_option(boost::asio::socket_base::reuse_address(true), ec);
                    if(ec) {
                        fail(ec, "set_option");
                        return;
                    }
                    acceptor_.bind(endpoint, ec);
                    if(ec) {
                        fail(ec, "bind");
                        return;
                    }
                    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
                    if(ec) {
                        fail(ec, "listen");
                        return;
                    }
                }

                void Listener::run() {
                    if(! acceptor_.is_open())
                        return;
                    do_accept();
                }

                void Listener::do_accept() {
                    acceptor_.async_accept(socket_, [self = shared_from_this()](const error_code & ec) {
                        self->on_accept(ec);
                    });
                }

                void Listener::on_accept(error_code ec) {
                    if(ec) {
                        fail(ec, "accept");
                    }
                    else {
                        std::make_shared<Session>(std::move(socket_))->run();
                    }
                    do_accept();
                }
            }
        }
    }
}