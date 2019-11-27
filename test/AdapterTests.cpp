// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <TcpAdapterProxy.h>
#include <ProxySettings.h>

#include <iostream>
#include <thread>
#include <chrono>
#include "Message.pb.h"

#include "TestWebsocketServer.h"

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/system/error_code.hpp>

using boost::property_tree::ptree;
using boost::system::errc::errc_t;
using aws::iot::securedtunneling::adapter_proxy_config;
using aws::iot::securedtunneling::tcp_adapter_proxy;
using aws::iot::securedtunneling::proxy_mode;

int const               IO_PAUSE_MS = 50;
size_t const            READ_BUFFER_SIZE = 63 * 1024;
char const * const      LOCALHOST = "127.0.0.1";
errc_t const            BOOST_EC_SOCKET_CLOSED = boost::system::errc::no_such_file_or_directory;

namespace aws { namespace iot { namespace securedtunneling { namespace test
{
    void apply_test_config(adapter_proxy_config &cfg, tcp::endpoint const& ws_endpoint) 
    {
        cfg.proxy_host = ws_endpoint.address().to_string();
        cfg.proxy_port = ws_endpoint.port();
        cfg.data_host = LOCALHOST;  //tests should always be pointing here
    }

    void apply_test_settings(ptree &settings)
    {
        using namespace aws::iot::securedtunneling::settings;
        apply_default_settings(settings);
        settings.put(KEY_TCP_CONNECTION_RETRY_COUNT, 0);
        settings.put(KEY_WEB_SOCKET_CONNECT_RETRY_COUNT, 0);
        settings.put(KEY_WEB_SOCKET_DATA_ERROR_RETRY, false);
    }
    
}}}}

using namespace std;
using namespace aws::iot::securedtunneling::test;

TEST_CASE( "Test source mode", "[source]") {
    boost::system::error_code ec;
    ptree settings;
    apply_test_settings(settings);
    TestWebsocketServer ws_server(LOCALHOST, settings);
    tcp::endpoint ws_address{ws_server.get_endpoint()};
    std::cout << "Test server is listening on address: " << ws_address.address() << " and port: " << ws_address.port() << endl;

    adapter_proxy_config adapter_cfg;
    apply_test_config(adapter_cfg, ws_address);
    adapter_cfg.mode = proxy_mode::SOURCE;
    adapter_cfg.data_port = 0;
    adapter_cfg.bind_address = LOCALHOST;
    adapter_cfg.access_token = "foobar_token";
    uint16_t adapter_chosen_port = 0;
    //capture the random listen port in source mode
    adapter_cfg.on_listen_port_assigned = [&adapter_chosen_port](uint16_t port) { adapter_chosen_port = port; };

    tcp_adapter_proxy proxy{ settings, adapter_cfg };

    //start web socket server thread and tcp adapter threads
    thread ws_server_thread{[&ws_server]() { ws_server.run(); } };
    thread tcp_adapter_thread{[&proxy]() { proxy.run_proxy(); } };

    boost::asio::io_context io_ctx{};
    tcp::socket client_socket{ io_ctx };

    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));
    CHECK( ws_server.get_handshake_request().method() == boost::beast::http::verb::get );
    CHECK( ws_server.get_handshake_request().target() == "/tunnel?local-proxy-mode=source" );
    CHECK( ws_server.get_handshake_request().base()["sec-websocket-protocol"] == "aws.iot.securetunneling-1.0" );
    CHECK( ws_server.get_handshake_request().base()["access-token"] == adapter_cfg.access_token );

    client_socket.connect( tcp::endpoint{boost::asio::ip::make_address(adapter_cfg.bind_address.get()), adapter_chosen_port} );

    uint8_t read_buffer[READ_BUFFER_SIZE];

    for(int i = 0; i < 5; ++i)
    {
        string const test_string = (boost::format("test message: %1%") % i).str();
        client_socket.send(boost::asio::buffer(test_string));
        client_socket.read_some(boost::asio::buffer(reinterpret_cast<void *>(read_buffer), READ_BUFFER_SIZE));
        CHECK( string(reinterpret_cast<char *>(read_buffer)) == test_string );
    }

    ws_server.expect_next_message(
        [](message const&msg)
        {
            return (msg.type() == com::amazonaws::iot::securedtunneling::Message_Type_STREAM_RESET) && msg.streamid() == 1;
        });
    client_socket.close();
    
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    client_socket.connect( tcp::endpoint{boost::asio::ip::make_address(adapter_cfg.bind_address.get()), adapter_chosen_port} );

    for(int i = 0; i < 5; ++i)
    {
        string const test_string = (boost::format("test message: %1%") % i).str();
        client_socket.send(boost::asio::buffer(test_string));
        client_socket.read_some(boost::asio::buffer(reinterpret_cast<void *>(read_buffer), READ_BUFFER_SIZE));
        CHECK( string(reinterpret_cast<char *>(read_buffer)) == test_string );
    }

    //instruct websocket to close on client
    ws_server.close_client("test_closure", boost::beast::websocket::internal_error);
    //attempt a read on the client which should now see the socket EOF (peer closed) caused by adapter
    client_socket.read_some(boost::asio::buffer(reinterpret_cast<void *>(read_buffer), READ_BUFFER_SIZE), ec);
    CHECK( ec.value() == BOOST_EC_SOCKET_CLOSED );

    client_socket.close();

    ws_server_thread.join();
    tcp_adapter_thread.join();
}


TEST_CASE( "Test destination mode", "[destination]") {
    using namespace com::amazonaws::iot::securedtunneling;

    boost::asio::io_context io_ctx{};
    tcp::socket destination_socket{ io_ctx };
    tcp::acceptor acceptor{io_ctx, {boost::asio::ip::make_address(LOCALHOST), 0}};
    cout << "Destination app listening on address: " << acceptor.local_endpoint().address().to_string()
        << ":" << acceptor.local_endpoint().port() << endl;
    bool accepted = false;
    thread tcp_accept_thread{[&acceptor, &destination_socket, &accepted]()
        {
            acceptor.accept(destination_socket);
            accepted = true;
        }};

    boost::system::error_code ec;
    ptree settings;
    apply_test_settings(settings);
    TestWebsocketServer ws_server(LOCALHOST, settings);
    tcp::endpoint ws_address{ws_server.get_endpoint()};
    //start web socket server thread and tcp adapter threads
    thread ws_server_thread{[&ws_server]() { ws_server.run(); } };
    std::cout << "Test server listening on address: " << ws_address.address() << " and port: " << ws_address.port() << endl;
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    adapter_proxy_config adapter_cfg;
    apply_test_config(adapter_cfg, ws_address);
    adapter_cfg.mode = proxy_mode::DESTINATION;
    adapter_cfg.data_host = acceptor.local_endpoint().address().to_string();
    adapter_cfg.data_port = acceptor.local_endpoint().port();
    adapter_cfg.bind_address = LOCALHOST;
    adapter_cfg.access_token = "foobar_dest_token";

    tcp_adapter_proxy proxy{ settings, adapter_cfg };

    thread tcp_adapter_thread{[&proxy]() { proxy.run_proxy(); } };
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    CHECK( ws_server.get_handshake_request().method() == boost::beast::http::verb::get );
    CHECK( ws_server.get_handshake_request().target() == "/tunnel?local-proxy-mode=destination" );
    CHECK( ws_server.get_handshake_request().base()["sec-websocket-protocol"] == "aws.iot.securetunneling-1.0" );
    CHECK( ws_server.get_handshake_request().base()["access-token"] == adapter_cfg.access_token );

    message outgoing_message{};
    outgoing_message.set_type(Message_Type_STREAM_START);
    outgoing_message.set_streamid(1);
    outgoing_message.set_ignorable(false);
    outgoing_message.clear_payload();

    ws_server.deliver_message(outgoing_message);
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    REQUIRE( accepted );
    tcp_accept_thread.join();

    uint8_t read_buffer[READ_BUFFER_SIZE];

    for(int i = 0; i < 5; ++i)
    {
        string const test_string = (boost::format("test message: %1%") % i).str();
        destination_socket.send(boost::asio::buffer(test_string));
        destination_socket.read_some(boost::asio::buffer(reinterpret_cast<void *>(read_buffer), READ_BUFFER_SIZE));
        CHECK( string(reinterpret_cast<char *>(read_buffer)) == test_string );
    }

    ws_server.expect_next_message(
        [](message const&msg)
        {
            return (msg.type() == com::amazonaws::iot::securedtunneling::Message_Type_STREAM_RESET) && msg.streamid() == 1;
        });
    destination_socket.close();

    accepted = false;
    tcp_accept_thread = std::thread{[&acceptor, &destination_socket, &accepted]()
        {
            acceptor.accept(destination_socket);
            accepted = true;
        }};
    ws_server.deliver_message(outgoing_message);
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));
    REQUIRE( accepted );
    tcp_accept_thread.join();

    for(int i = 0; i < 5; ++i)
    {
        string const test_string = (boost::format("test message: %1%") % i).str();
        destination_socket.send(boost::asio::buffer(test_string));
        destination_socket.read_some(boost::asio::buffer(reinterpret_cast<void *>(read_buffer), READ_BUFFER_SIZE));
        CHECK( string(reinterpret_cast<char *>(read_buffer)) == test_string );
    }

    //instruct websocket to close on client
    ws_server.close_client("test_closure", boost::beast::websocket::internal_error); //need to perform write to trigger close
    //attempt a read on the client which should now see the socket EOF (peer closed) caused by adapter
    destination_socket.read_some(boost::asio::buffer(reinterpret_cast<void *>(read_buffer), READ_BUFFER_SIZE), ec);
    CHECK( ec.value() == BOOST_EC_SOCKET_CLOSED );

    ws_server_thread.join();
    tcp_adapter_thread.join();
}

