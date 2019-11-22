// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include  "TestWebsocketServer.h"
#include <ProxySettings.h>
#include <exception>
#include <iostream>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>

#include <boost/beast/http.hpp>
#include <boost/format.hpp>

using namespace std;
using namespace aws::iot::securedtunneling::settings;

using boost::asio::ip::tcp;
using web_socket_stream = boost::beast::websocket::stream<boost::asio::ip::tcp::socket>;
using message = com::amazonaws::iot::securedtunneling::Message;
using boost::property_tree::ptree;

namespace aws { namespace iot { namespace securedtunneling { namespace test
{

namespace websocket = boost::beast::websocket;
namespace http = boost::beast::http;

TestWebsocketServer::TestWebsocketServer(std::string const &address, ptree const &adapter_settings) :
    adapter_settings(adapter_settings),
    io_ctx(),
    acceptor(io_ctx, {boost::asio::ip::make_address(address), 0}),
    closed(false),
    close_reason{},
    code(websocket::internal_error),
    incoming_message_buffer{ adapter_settings.get<size_t>(KEY_WEB_SOCKET_READ_BUFFER_SIZE) },
    message_parse_buffer{ adapter_settings.get<size_t>(KEY_MESSAGE_MAX_SIZE) }
{ }

void TestWebsocketServer::run()
{
    tcp::socket socket{io_ctx};
    acceptor.accept(socket);

    boost::beast::flat_buffer buffer;
    http::read(socket, buffer, handshake_request, ec);
    web_socket_stream ws{std::move(socket)};
    ws_stream = ws;
    ws.accept_ex(
        handshake_request,
        [](boost::beast::websocket::response_type& response)
        {
            response.set("channel-id", boost::uuids::to_string({}));    //default init for uuid is all 0s
            response.set("Sec-WebSocket-Protocol", "aws.iot.securetunneling-1.0");
        },
        ec);
    if(ec)
    {
        throw std::runtime_error((boost::format("Accept handshake error: %1%") % ec.message()).str().c_str());
    }
    ws.binary(true);
    //async for reading 
    ws.async_read_some(incoming_message_buffer, incoming_message_buffer.max_size() - incoming_message_buffer.size(),
        std::bind(&TestWebsocketServer::on_read_complete, this, std::ref(ws),
        std::placeholders::_1, std::placeholders::_2));

    io_ctx.run();
}

void TestWebsocketServer::on_read_complete(web_socket_stream &ws, boost::system::error_code const &ec, size_t bytes_read)
{
    if(!ec)
    {
        process_input_buffer(ws, incoming_message_buffer);
        ws.async_read_some(incoming_message_buffer, incoming_message_buffer.max_size() - incoming_message_buffer.size(),
            std::bind(&TestWebsocketServer::on_read_complete, this, std::ref(ws),
            std::placeholders::_1, std::placeholders::_2));
    }
    else if(!closed)
    {
        throw std::runtime_error((boost::format("Error on read: %1%") % ec.message()).str().c_str());
    }
}
      
void TestWebsocketServer::on_read_message(web_socket_stream &ws, message const &message)
{
    using namespace com::amazonaws::iot::securedtunneling;
    if(expect_messages.empty())
    {   //if not explicitly expecting something, ignore control messages, echo back data
            if (message.type() != Message_Type_DATA)
            {   //control message recieved
            }
            else if (message.type() == Message_Type_DATA)
            {
                send_message(ws, message);
            }
    }
    else
    {
        auto expect_check = expect_messages.front();
        expect_messages.pop();
        if(!expect_check(message))
        {
            throw std::runtime_error((boost::format("Unexpected message type recievedi: Type: %1%; StreamId: %2%") % message.type() % message.streamid()).str());
        }
    }
}

void TestWebsocketServer::on_write_complete(web_socket_stream &ws, boost::system::error_code const &ec, size_t bytes_written)
{
    if(ec)
    {
        throw std::runtime_error((boost::format("Error on write: %1%") % ec.message()).str().c_str());
    }
}

void TestWebsocketServer::process_input_buffer(web_socket_stream &ws_stream, boost::beast::multi_buffer &message_buffer)
{
    using namespace com::amazonaws::iot::securedtunneling;

    size_t const data_length_size = adapter_settings.get<size_t>(KEY_DATA_LENGTH_SIZE);
    boost::beast::flat_buffer data_length_buffer{ data_length_size };
    while (message_buffer.size() >= data_length_size)
    {
        boost::asio::buffer_copy(data_length_buffer.prepare(data_length_size), message_buffer.data(), data_length_size);
        uint16_t data_length = boost::endian::big_to_native(*reinterpret_cast<std::uint16_t const *>(data_length_buffer.data().data()));
        if (message_buffer.size() >= (data_length + data_length_size))
        {
            //consume the length since we've already read it
            message_buffer.consume(data_length_size);
            bool parsed_successfully = parse_protobuf_and_consume_input(message_buffer, static_cast<size_t>(data_length), incoming_message) && incoming_message.IsInitialized();
            if (!parsed_successfully)
            {
                throw std::runtime_error("Could not parse web socket binary frame into message");
            }
            on_read_message(ws_stream, incoming_message);
        }
        else
        {
            break;
        }
    }
}

void TestWebsocketServer::send_message(web_socket_stream &ws, message const &message)
{
    using namespace com::amazonaws::iot::securedtunneling;
    //calculate total frame size
    std::size_t const frame_size = static_cast<std::size_t>(message.ByteSizeLong()) +
        adapter_settings.get<size_t>(KEY_DATA_LENGTH_SIZE);
    boost::beast::flat_buffer outgoing_message_buffer{ frame_size };
    //get pointers to where data length and protobuf msg will be written to
    void *frame_data = outgoing_message_buffer.prepare(frame_size).data();
    void *frame_data_msg_offset = reinterpret_cast<void *>(reinterpret_cast<std::uint8_t *>(frame_data) 
        + adapter_settings.get<size_t>(KEY_DATA_LENGTH_SIZE));
    //get the protobuf data length and wirte it to start the frame
    std::uint16_t data_length = static_cast<std::uint16_t>(message.ByteSizeLong());
    *reinterpret_cast<std::uint16_t *>(frame_data) = boost::endian::native_to_big(data_length);
    //write the protobuf msg into the buffer next
    message.SerializeToArray(frame_data_msg_offset, static_cast<int>(adapter_settings.get<size_t>(KEY_MESSAGE_MAX_SIZE)));
    //commit the entire frame to the outgoing message buffer
    outgoing_message_buffer.commit(frame_size);
    //no controls in test mode over async writes, test flow dictates this
    ws.async_write(outgoing_message_buffer.data(),
        std::bind(&TestWebsocketServer::on_write_complete, this, std::ref(ws),
        std::placeholders::_1, std::placeholders::_2));
}

bool TestWebsocketServer::parse_protobuf_and_consume_input(boost::beast::multi_buffer &message_buffer, size_t data_length, message &msg)
{
    //copy into a continguous buffer for simplified protobuf parsing
    message_parse_buffer.consume(message_parse_buffer.size());
    msg.Clear();
    boost::asio::buffer_copy(message_parse_buffer.prepare(data_length), message_buffer.data(), data_length);
    message_buffer.consume(data_length);
    return msg.ParseFromArray(message_parse_buffer.data().data(), static_cast<int>(data_length));
}

void TestWebsocketServer::close_client(std::string const& close_reason, boost::beast::websocket::close_code code)
{
    closed = true;  //enable read loop failure to know that it was normal
    ws_stream.get().async_close({code, close_reason}, 
        [this](boost::system::error_code const &ec)
        {
            websocket::async_teardown(websocket::role_type::server, ws_stream.get().next_layer(),
                [this](boost::system::error_code const &ec)
                {
                    this->io_ctx.stop();
                });
        });
}

void TestWebsocketServer::expect_next_message(std::function<bool(message const &)> predicate)
{
    expect_messages.push(predicate);
}

}}}}
