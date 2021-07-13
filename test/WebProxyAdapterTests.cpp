// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0


#include "TestHttpServer.h"
#include "WebProxyAdapter.h"
#include "WebSocketStream.h"

#include <catch2/catch.hpp>
#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>
#include <boost/lexical_cast.hpp>
#include <iostream>
#include <thread>
#include <chrono>

using namespace std;

namespace aws {
    namespace iot {
        namespace securedtunneling {
            namespace test {
                constexpr char LOCALHOST[] = "127.0.0.1";
                constexpr int IO_PAUSE_MS = 1000;
                unsigned short get_available_port() {
                    boost::asio::io_context io_ctx { };
                    tcp::acceptor acceptor(io_ctx);
                    tcp::endpoint endPoint(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
                    acceptor.open(endPoint.protocol());
                    acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
                    acceptor.bind(endPoint);
                    acceptor.listen();
                    tcp::endpoint le = acceptor.local_endpoint();
                    acceptor.close();
                    return le.port();
                }
                LocalproxyConfig get_localproxy_config(const std::uint16_t& port, const string& auth = "") {
                    LocalproxyConfig config;
                    config.web_proxy_host = LOCALHOST;
                    config.web_proxy_port = port;
                    config.web_proxy_auth = auth;
                    return config;
                }

                struct TestContext {
                    TestHttpServer http_server;
                    tcp::endpoint local_address;
                    logger log;
                    LocalproxyConfig config;
                    boost::asio::io_context ioc{};
                    shared_ptr<WebSocketStream> wss;
                    WebProxyAdapter https_proxy_adapter;
                    boost::system::error_code ec;
                    unique_ptr<thread> http_server_thread;
                    unique_ptr<thread> https_proxy_adapter_thread;
                    TestContext(const string& auth = "")
                            : http_server(LOCALHOST, get_available_port()),
                              local_address(http_server.listener->acceptor_.local_endpoint()),
                              log{},
                              config(get_localproxy_config(local_address.port(), auth)),
                              ioc{},
                              wss{make_shared<WebSocketStream>(config, &log, ioc)},
                              https_proxy_adapter(&log, config),
                              ec{} {
                        cout << "Test HTTP server is listening on address: " << local_address.address()
                             << " and port: " << local_address.port() << endl;
                    }
                    void start() {
                        auto on_tcp_tunnel =
                                [this](const boost::system::error_code& ec_response) {
                                    ec = ec_response;
                                };
                        http_server_thread = make_unique<thread>([this]() { http_server.run(); });
                        https_proxy_adapter_thread = make_unique<thread>([this, on_tcp_tunnel]() {
                            https_proxy_adapter.async_connect(on_tcp_tunnel, wss, local_address);
                            ioc.run();
                        });
                    }
                    void stop() {
                        http_server.stop();
                        ioc.stop();
                        http_server_thread->join();
                        https_proxy_adapter_thread->join();
                    }

                };

                TEST_CASE( "Unit tests for WebProxyAdapter.h-happy-case") {
                    cout << "Test HTTPS proxy adapter base case with no credentials" << endl;
                    TestContext test_context{};
                    test_context.start();
                    this_thread::sleep_for(chrono::microseconds(IO_PAUSE_MS));
                    REQUIRE(test_context.ec.message() == WebProxyAdapterErrc_category().message((int) WebProxyAdapterErrc::Success));
                    REQUIRE(static_cast<WebProxyAdapterErrc>(test_context.ec.value()) == WebProxyAdapterErrc::Success);
                    test_context.stop();
                }

                TEST_CASE( "Unit tests for WebProxyAdapter.h-with credentials") {
                    cout << "Test HTTPS proxy adapter handling of valid credentials response" << endl;
                    TestContext test_context{username + ":" + password};
                    test_context.start();
                    this_thread::sleep_for(chrono::microseconds(IO_PAUSE_MS));
                    REQUIRE(test_context.ec.message() == WebProxyAdapterErrc_category().message((int) WebProxyAdapterErrc::Success));
                    REQUIRE(static_cast<WebProxyAdapterErrc>(test_context.ec.value()) == WebProxyAdapterErrc::Success);
                    test_context.stop();
                }

                TEST_CASE( "Unit tests for WebProxyAdapter.h-bad credentials credentials") {
                    cout << "Test HTTPS proxy adapter handling of bad credentials response" << endl;
                    TestContext test_context{username + "a:" + password};
                    test_context.start();
                    this_thread::sleep_for(chrono::microseconds(IO_PAUSE_MS));
                    REQUIRE(test_context.ec.message() == WebProxyAdapterErrc_category().message((int) WebProxyAdapterErrc::ClientError));
                    REQUIRE(static_cast<WebProxyAdapterErrc>(test_context.ec.value()) == WebProxyAdapterErrc::ClientError);
                    test_context.stop();
                }

                TEST_CASE( "Unit tests for WebProxyAdapter.h-500 error") {
                    cout << "Test HTTPS proxy adapter handling of 500 response" << endl;
                    TestContext test_context{"500"};
                    test_context.start();
                    this_thread::sleep_for(chrono::microseconds(IO_PAUSE_MS));
                    REQUIRE(test_context.ec.message() == WebProxyAdapterErrc_category().message((int) WebProxyAdapterErrc::ServerError));
                    REQUIRE(static_cast<WebProxyAdapterErrc>(test_context.ec.value()) == WebProxyAdapterErrc::ServerError);
                    test_context.stop();
                }

                TEST_CASE( "Unit tests for WebProxyAdapter.h-100 error") {
                    cout << "Test HTTPS proxy adapter handling of 100 response" << endl;
                    TestContext test_context{"100"};
                    test_context.start();
                    this_thread::sleep_for(chrono::microseconds(IO_PAUSE_MS));
                    REQUIRE(test_context.ec.message() == WebProxyAdapterErrc_category().message((int) WebProxyAdapterErrc::OtherHttpError));
                    REQUIRE(static_cast<WebProxyAdapterErrc>(test_context.ec.value()) == WebProxyAdapterErrc::OtherHttpError);
                    test_context.stop();
                }

                TEST_CASE( "Unit tests for WebProxyAdapter.h-300 error") {
                    cout << "Test HTTPS proxy adapter handling of 300 response" << endl;
                    TestContext test_context{"300"};
                    test_context.start();
                    this_thread::sleep_for(chrono::microseconds(IO_PAUSE_MS));
                    REQUIRE(test_context.ec.message() == WebProxyAdapterErrc_category().message((int) WebProxyAdapterErrc::RedirectionError));
                    REQUIRE(static_cast<WebProxyAdapterErrc>(test_context.ec.value()) == WebProxyAdapterErrc::RedirectionError);
                    test_context.stop();
                }
            }
        }
    }
}
