// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include <TcpAdapterProxy.h>
#include <ProxySettings.h>
#include <config/ConfigFile.h>
#include <iostream>
#include <unordered_set>
#include <string>
#include <cstdio>
#include <boost/filesystem.hpp>
#include <thread>
#include <chrono>
#include "Message.pb.h"

#include "TestWebsocketServer.h"
#include "LocalproxyConfig.h"

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/system/error_code.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/lexical_cast.hpp>

using boost::property_tree::ptree;
using boost::system::errc::errc_t;
using aws::iot::securedtunneling::LocalproxyConfig;
using aws::iot::securedtunneling::tcp_adapter_proxy;
using aws::iot::securedtunneling::proxy_mode;

int const               IO_PAUSE_MS = 50;
size_t const            READ_BUFFER_SIZE = 63 * 1024;
char const * const      LOCALHOST = "127.0.0.1";
errc_t const            BOOST_EC_SOCKET_CLOSED = boost::system::errc::no_such_file_or_directory;

namespace aws { namespace iot { namespace securedtunneling { namespace test
{
    void apply_test_config(LocalproxyConfig &cfg, tcp::endpoint const& ws_endpoint)
    {
        cfg.proxy_host = ws_endpoint.address().to_string();
        cfg.proxy_port = ws_endpoint.port();
    }

    void apply_test_settings(ptree &settings)
    {
        using namespace aws::iot::securedtunneling::settings;
        apply_default_settings(settings);
        settings.put(KEY_TCP_CONNECTION_RETRY_COUNT, 0);
        settings.put(KEY_WEB_SOCKET_CONNECT_RETRY_COUNT, 0);
        settings.put(KEY_WEB_SOCKET_DATA_ERROR_RETRY, false);
    }

    uint16_t get_available_port(boost::asio::io_context & io_ctx)
    {
        boost::asio::ip::tcp::acceptor acceptor(io_ctx);
        boost::asio::ip::tcp::endpoint endPoint(boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 0));
        acceptor.open(endPoint.protocol());
        acceptor.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
        acceptor.bind(endPoint);
        acceptor.listen();
        boost::asio::ip::tcp::endpoint le = acceptor.local_endpoint();
        acceptor.close();
        return (uint16_t)le.port();
    }
    
}}}}

using namespace std;
using namespace aws::iot::securedtunneling::test;

namespace aws { namespace iot { namespace securedtunneling { namespace test { namespace config {
    std::string const       DEFAULT_CONFIG_DIR_SUFFIX = "/config";
    /**
    * Note: catch2 does not support mocking. So for now, create the files and directories.
    * For future, we can integrate with https://github.com/matepek/catch2-with-gmock
    */
    TEST_CASE("Unit tests for ConfigFile", "[config]") {
        namespace fs = boost::filesystem;
        // Test case set up
        fs::path full_path(boost::filesystem::current_path());
        string current_dir = fs::canonical(full_path).string();

        string const test_dir = "testDir";
        if (fs::exists(test_dir))
        {
            try {
                fs::remove_all(test_dir);
            }
            catch (const fs::filesystem_error & e) {
                std::cout << "Error deleting test dir " << e.what() << std::endl;
            }
        }
        REQUIRE(true == fs::create_directory(test_dir));

        string const test_config_file_name = "configFile";
        bool ok = static_cast<bool>(std::ofstream(test_config_file_name));
        REQUIRE(ok == true);
        /**
         * Create config file for unit test
         *  SSH1=555
         */
        ofstream test_file;
        test_file.open(test_config_file_name);
        string identifier = "SSH1";
        string endpoint = "5555";
        std::vector<std::string> tmp{identifier, endpoint};
        std::string file_content = boost::algorithm::join(tmp, "= ");
        test_file << file_content;
        test_file.close();

        SECTION("Test is_valid_directory: valid directory") {
            CHECK(true == aws::iot::securedtunneling::config_file::is_valid_directory(current_dir));
        }

        SECTION("Test invalid directory") {
            CHECK(false == aws::iot::securedtunneling::config_file::is_valid_directory("a"));
        }

        SECTION("Test is_valid_directory: empty directory") {
            CHECK(false == aws::iot::securedtunneling::config_file::is_valid_directory(test_dir));
        }

        SECTION("Test is_valid_directory: pass a file instead of a directory") {
            CHECK(false == aws::iot::securedtunneling::config_file::is_valid_directory(test_config_file_name));
        }

        SECTION("Test happy path for get_all_files") {
            CHECK_NOTHROW(aws::iot::securedtunneling::config_file::get_all_files(current_dir));
        }

        SECTION("Test happy path for read_service_ids_from_config_files, 1 service id") {
            std::unordered_map<string, string> serviceId_to_endpoint_mapping {};
            std::vector<std::string> file_paths {test_config_file_name};
            unordered_set<string>  service_ids {};
            service_ids.insert(identifier);
            aws::iot::securedtunneling::config_file::read_service_ids_from_config_files(file_paths, service_ids, serviceId_to_endpoint_mapping);
            CHECK(serviceId_to_endpoint_mapping.size() == 1);
            CHECK(serviceId_to_endpoint_mapping[identifier] == endpoint);
        }

        SECTION("Test happy path for read_service_ids_from_config_files, 0 service id") {
            std::unordered_map<string, string> serviceId_to_endpoint_mapping {};
            std::vector<std::string> file_paths {};
            unordered_set<string> service_ids {};
            aws::iot::securedtunneling::config_file::read_service_ids_from_config_files(file_paths, service_ids, serviceId_to_endpoint_mapping);
            CHECK(serviceId_to_endpoint_mapping.size() == 0);
        }

        SECTION("Test happy path for find_service_ids") {
            std::unordered_map<string, string> serviceId_to_endpoint_mapping;
            aws::iot::securedtunneling::config_file::update_port_mapping(file_content, serviceId_to_endpoint_mapping);
            CHECK(serviceId_to_endpoint_mapping.size() == 1);
            CHECK(serviceId_to_endpoint_mapping[identifier] == endpoint);
        }

        SECTION("Test happy path for get_default_port_mapping_dir") {
            CHECK(aws::iot::securedtunneling::config_file::get_default_port_mapping_dir() == current_dir + DEFAULT_CONFIG_DIR_SUFFIX);
        }

        // Test case clean up.
        int remove_file_stat = std::remove(test_config_file_name.c_str());
        if (remove_file_stat != 0)
        {
            std::cout << "Error deleting file " << test_config_file_name << std::endl;
        }
        // Can comment out below line if does not want to check for clean up.
        CHECK(remove_file_stat == 0);
        if (fs::exists(test_dir))
        {
            try {
                fs::remove_all(test_dir);
            }
            catch (const fs::filesystem_error & e) {
                std::cout << "Error deleting test dir " << e.what() << std::endl;
            }
        }
    }
}}}}}


TEST_CASE( "Test source mode", "[source]") {
    using namespace com::amazonaws::iot::securedtunneling;
    /**
    * Test case set up
    * 1. Create tcp socket to acts as destination app.
    * 2. Create web socket server to act as secure tunneling service (cloud side).
    * 3. Configure adapter config used for the local proxy.
    */
    boost::asio::io_context io_ctx{};
    tcp::socket client_socket{ io_ctx };

    boost::system::error_code ec;
    ptree settings;
    apply_test_settings(settings);
    TestWebsocketServer ws_server(LOCALHOST, settings);
    tcp::endpoint ws_address{ws_server.get_endpoint()};
    std::cout << "Test server is listening on address: " << ws_address.address() << " and port: " << ws_address.port() << endl;

    LocalproxyConfig adapter_cfg;
    apply_test_config(adapter_cfg, ws_address);
    adapter_cfg.mode = proxy_mode::SOURCE;
    adapter_cfg.bind_address = LOCALHOST;
    adapter_cfg.access_token = "foobar_token";
    const std::string service_id= "ssh1";
    uint16_t adapter_chosen_port = get_available_port(io_ctx);
    adapter_cfg.serviceId_to_endpoint_map[service_id] = boost::lexical_cast<std::string>(adapter_chosen_port);

    tcp_adapter_proxy proxy{ settings, adapter_cfg };

    //start web socket server thread and tcp adapter threads
    thread ws_server_thread{[&ws_server]() { ws_server.run(); } };
    thread tcp_adapter_thread{[&proxy]() { proxy.run_proxy(); } };

    // Verify web socket handshake request from local proxy
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));
    CHECK( ws_server.get_handshake_request().method() == boost::beast::http::verb::get );
    CHECK( ws_server.get_handshake_request().target() == "/tunnel?local-proxy-mode=source" );
    CHECK( ws_server.get_handshake_request().base()["sec-websocket-protocol"] == "aws.iot.securetunneling-2.0" );
    CHECK( ws_server.get_handshake_request().base()["access-token"] == adapter_cfg.access_token );

    // Simulate cloud side sends control message Message_Type_SERVICE_IDS
    message ws_server_message{};
    ws_server_message.set_type(Message_Type_SERVICE_IDS);
    ws_server_message.add_availableserviceids(service_id);
    ws_server_message.set_ignorable(false);
    ws_server_message.clear_payload();

    ws_server.deliver_message(ws_server_message);
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    // Simulate source app connects to source local proxy
    client_socket.connect( tcp::endpoint{boost::asio::ip::make_address(adapter_cfg.bind_address.get()), adapter_chosen_port} );

    uint8_t read_buffer[READ_BUFFER_SIZE];

    // Simulate sending data messages from source app
    for(int i = 0; i < 5; ++i)
    {
        string const test_string = (boost::format("test message: %1%") % i).str();
        client_socket.send(boost::asio::buffer(test_string));
        client_socket.read_some(boost::asio::buffer(reinterpret_cast<void *>(read_buffer), READ_BUFFER_SIZE));
        CHECK( string(reinterpret_cast<char *>(read_buffer)) == test_string );
    }

    // Verify local proxy sends Message_Type_STREAM_RESET
    ws_server.expect_next_message(
        [](message const&msg)
        {
            return (msg.type() == com::amazonaws::iot::securedtunneling::Message_Type_STREAM_RESET) && msg.streamid() == 1;
        });
    client_socket.close();
    
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    // Simulate source app connects to source local proxy
    client_socket.connect( tcp::endpoint{boost::asio::ip::make_address(adapter_cfg.bind_address.get()), adapter_chosen_port} );

    // Simulate sending data messages from source app
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
    /**
    * Test case set up
    * 1. Create tcp socket to acts as destination app.
    * 2. Create web socket server to act as secure tunneling service (cloud side).
    * 3. Configure adapter config used for the local proxy.
    */
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

    LocalproxyConfig adapter_cfg;
    apply_test_config(adapter_cfg, ws_address);
    adapter_cfg.mode = proxy_mode::DESTINATION;
    adapter_cfg.bind_address = LOCALHOST;
    adapter_cfg.access_token = "foobar_dest_token";
    const std::string service_id= "ssh1";
    std::string dst_host = acceptor.local_endpoint().address().to_string();
    std::string dst_port = boost::lexical_cast<std::string>(acceptor.local_endpoint().port());
    adapter_cfg.serviceId_to_endpoint_map[service_id] = dst_host+ + ":" + dst_port;

    tcp_adapter_proxy proxy{ settings, adapter_cfg };

    thread tcp_adapter_thread{[&proxy]() { proxy.run_proxy(); } };
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    // Verify web socket handshake request from local proxy
    CHECK( ws_server.get_handshake_request().method() == boost::beast::http::verb::get );
    CHECK( ws_server.get_handshake_request().target() == "/tunnel?local-proxy-mode=destination" );
    CHECK( ws_server.get_handshake_request().base()["sec-websocket-protocol"] == "aws.iot.securetunneling-2.0" );
    CHECK( ws_server.get_handshake_request().base()["access-token"] == adapter_cfg.access_token );

    // Simulate cloud side sends control message Message_Type_SERVICE_IDS
    message ws_server_message{};
    ws_server_message.set_type(Message_Type_SERVICE_IDS);
    ws_server_message.add_availableserviceids(service_id);
    ws_server_message.set_ignorable(false);
    ws_server_message.clear_payload();

    ws_server.deliver_message(ws_server_message);
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    // Simulate cloud side sends control message Message_Type_STREAM_START
    ws_server_message.set_type(Message_Type_STREAM_START);
    ws_server_message.set_serviceid(service_id);
    ws_server_message.set_streamid(1);
    ws_server_message.set_ignorable(false);
    ws_server_message.clear_payload();

    ws_server.deliver_message(ws_server_message);
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));

    // Verify destination app is connected
    REQUIRE( accepted );
    tcp_accept_thread.join();

    // Simulate sending data messages from destination app
    uint8_t read_buffer[READ_BUFFER_SIZE];

    for(int i = 0; i < 5; ++i)
    {
        string const test_string = (boost::format("test message: %1%") % i).str();
        destination_socket.send(boost::asio::buffer(test_string));
        destination_socket.read_some(boost::asio::buffer(reinterpret_cast<void *>(read_buffer), READ_BUFFER_SIZE));
        CHECK( string(reinterpret_cast<char *>(read_buffer)) == test_string );
    }

    // Verify local proxy sends Message_Type_STREAM_RESET
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
    ws_server.deliver_message(ws_server_message);
    this_thread::sleep_for(chrono::milliseconds(IO_PAUSE_MS));
    REQUIRE( accepted );
    tcp_accept_thread.join();

   // Simulate sending data messages from destination app
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
