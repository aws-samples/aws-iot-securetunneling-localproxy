// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <stdlib.h>
#include <boost/property_tree/ptree.hpp>
#include "ProxySettings.h"

namespace aws { namespace iot { namespace securedtunneling { namespace settings {
    using boost::property_tree::ptree;
    
    char const * const KEY_DEFAULT_BIND_ADDRESS = "tunneling.proxy.default_bind_address";
    std::string DEFAULT_DEFAULT_BIND_ADDRESS = "localhost";

    char const * const KEY_PROXY_ENDPOINT_HOST_FORMAT = "tunneling.proxy.endpoint_format";
    std::string DEFAULT_PROXY_ENDPOINT_HOST_FORMAT = "data.tunneling.iot.%s.amazonaws.com";

    char const * const KEY_DATA_LENGTH_SIZE = "tunneling.proxy.message.data_length_size";
    std::size_t const DEFAULT_DATA_LENGTH_SIZE = 2;

    char const * const KEY_MAX_DATA_FRAME_SIZE = "tunneling.proxy.message.data_frame_max_size";
    std::size_t const DEFAULT_MAX_DATA_FRAME_SIZE = DEFAULT_MESSAGE_MAX_SIZE + DEFAULT_DATA_LENGTH_SIZE;

    char const * const KEY_TCP_CONNECTION_RETRY_COUNT = "tunneling.proxy.tcp.connection_retry_count";
    std::int32_t const DEFAULT_TCP_CONNECTION_RETRY_COUNT = 5;

    char const * const KEY_TCP_CONNECTION_RETRY_DELAY_MS = "tunneling.proxy.tcp.connection_retry_delay_ms";
    std::uint32_t const DEFAULT_TCP_CONNECTION_RETRY_DELAY_MS = 1000;

    char const * const KEY_MESSAGE_MAX_PAYLOAD_SIZE = "tunneling.proxy.message.max_payload_size";
    //if this is too small with respect to the peer, this client will overflow
    std::size_t const DEFAULT_MESSAGE_MAX_PAYLOAD_SIZE = 63 * 1024;

    char const * const KEY_MESSAGE_MAX_SIZE = "tunneling.proxy.message.max_size";
    std::size_t const DEFAULT_MESSAGE_MAX_SIZE = 64 * 1024;
    
    char const * const KEY_WEB_SOCKET_PING_PERIOD_MS = "tunneling.proxy.websocket.ping_period_ms";
    std::uint32_t const DEFAULT_WEB_SOCKET_PING_PERIOD_MS = 5000;

    char const * const KEY_WEB_SOCKET_CONNECT_RETRY_DELAY_MS = "tunneling.proxy.websocket.retry_delay_ms";
    std::uint32_t const DEFAULT_WEB_SOCKET_CONNECT_RETRY_DELAY_MS = 2500;

    char const * const KEY_WEB_SOCKET_CONNECT_RETRY_COUNT = "tunneling.proxy.websocket.connect_retry_count";
    std::int32_t const DEFAULT_WEB_SOCKET_CONNECT_RETRY_COUNT = -1;

    char const * const KEY_WEB_SOCKET_DATA_ERROR_RETRY = "tunneling.proxy.websocket.reconnect_on_data_error";
    bool const DEFAULT_WEB_SOCKET_DATA_ERROR_RETRY = true;

    char const * const KEY_WEB_SOCKET_SUBPROTOCOL = "tunneling.proxy.websocket.subprotocol";
    std::string const DEFAULT_WEB_SOCKET_SUBPROTOCOL = "aws.iot.securetunneling-1.0";

    char const * const KEY_WEB_SOCKET_MAX_FRAME_SIZE = "tunneling.proxy.websocket.max_frame_size";
    std::size_t const DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE = DEFAULT_MAX_DATA_FRAME_SIZE * 2;

    char const * const KEY_TCP_READ_BUFFER_SIZE = "tunneling.proxy.tcp.read_buffer_size";
    std::size_t const DEFAULT_TCP_READ_BUFFER_SIZE = DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

    char const * const KEY_TCP_WRITE_BUFFER_SIZE = "tunneling.proxy.tcp.write_buffer_size";
    std::size_t const DEFAULT_TCP_WRITE_BUFFER_SIZE = DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

    char const * const KEY_WEB_SOCKET_WRITE_BUFFER_SIZE = "tunneling.proxy.websocket.write_buffer_size";
    std::size_t const DEFAULT_WEB_SOCKET_WRITE_BUFFER_SIZE = DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

    char const * const KEY_WEB_SOCKET_READ_BUFFER_SIZE = "tunneling.proxy.websocket.read_buffer_size";
    std::size_t const DEFAULT_WEB_SOCKET_READ_BUFFER_SIZE = DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

    //Create a more concise way to apply a settings default value only if it isn't already in the 
    //ptree. Macro saves a bunch of repeat typing of the key in code and needing to repeat the type
    #define ADD_SETTING_DEFAULT(settings, key) \
    if(!settings.get_optional<std::remove_const_t<decltype(DEFAULT_##key)>>(KEY_##key).has_value())  \
    {                                                                                                \
        settings.add<std::remove_const_t<decltype(DEFAULT_##key)>>(KEY_##key, DEFAULT_##key);        \
    }

    void apply_default_settings(ptree & settings)
    {
        ADD_SETTING_DEFAULT(settings, DEFAULT_BIND_ADDRESS);
        ADD_SETTING_DEFAULT(settings, DATA_LENGTH_SIZE);
        ADD_SETTING_DEFAULT(settings, MAX_DATA_FRAME_SIZE);
        ADD_SETTING_DEFAULT(settings, TCP_CONNECTION_RETRY_COUNT);
        ADD_SETTING_DEFAULT(settings, TCP_CONNECTION_RETRY_DELAY_MS);
        ADD_SETTING_DEFAULT(settings, TCP_READ_BUFFER_SIZE);
        ADD_SETTING_DEFAULT(settings, MESSAGE_MAX_PAYLOAD_SIZE);
        ADD_SETTING_DEFAULT(settings, MESSAGE_MAX_SIZE);
        ADD_SETTING_DEFAULT(settings, WEB_SOCKET_PING_PERIOD_MS);
        ADD_SETTING_DEFAULT(settings, WEB_SOCKET_CONNECT_RETRY_DELAY_MS);
        ADD_SETTING_DEFAULT(settings, WEB_SOCKET_CONNECT_RETRY_COUNT);
        ADD_SETTING_DEFAULT(settings, WEB_SOCKET_DATA_ERROR_RETRY);
        ADD_SETTING_DEFAULT(settings, WEB_SOCKET_SUBPROTOCOL);
        ADD_SETTING_DEFAULT(settings, WEB_SOCKET_MAX_FRAME_SIZE);
        ADD_SETTING_DEFAULT(settings, WEB_SOCKET_WRITE_BUFFER_SIZE);
        ADD_SETTING_DEFAULT(settings, WEB_SOCKET_READ_BUFFER_SIZE);
    }
}}}}
