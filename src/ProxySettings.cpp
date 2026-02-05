// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "ProxySettings.h"
#include <boost/format.hpp>
#include <boost/property_tree/ptree.hpp>
#include <stdlib.h>

namespace aws {
namespace iot {
    namespace securedtunneling {
        namespace settings {
            using boost::property_tree::ptree;

            const char *const KEY_DEFAULT_BIND_ADDRESS
                = "tunneling.proxy.default_bind_address";
            std::string DEFAULT_DEFAULT_BIND_ADDRESS = "localhost";

            const char *const KEY_PROXY_ENDPOINT_HOST_FORMAT
                = "tunneling.proxy.endpoint_format";
            std::string DEFAULT_PROXY_ENDPOINT_HOST_FORMAT
                = "data.tunneling.iot.%s.amazonaws.com";

            const char *const KEY_PROXY_ENDPOINT_REGION_MAP
                = "tunneling.proxy.region_endpoint_overrides";

            const char *const KEY_DATA_LENGTH_SIZE
                = "tunneling.proxy.message.data_length_size";
            const std::size_t DEFAULT_DATA_LENGTH_SIZE = 2;

            const char *const KEY_MAX_DATA_FRAME_SIZE
                = "tunneling.proxy.message.data_frame_max_size";
            const std::size_t DEFAULT_MAX_DATA_FRAME_SIZE
                = DEFAULT_MESSAGE_MAX_SIZE + DEFAULT_DATA_LENGTH_SIZE;

            const char *const KEY_TCP_CONNECTION_RETRY_COUNT
                = "tunneling.proxy.tcp.connection_retry_count";
            const std::int32_t DEFAULT_TCP_CONNECTION_RETRY_COUNT = 5;

            const char *const KEY_TCP_CONNECTION_RETRY_DELAY_MS
                = "tunneling.proxy.tcp.connection_retry_delay_ms";
            const std::uint32_t DEFAULT_TCP_CONNECTION_RETRY_DELAY_MS = 2500;

            const char *const KEY_MESSAGE_MAX_PAYLOAD_SIZE
                = "tunneling.proxy.message.max_payload_size";
            // if this is too small with respect to the peer, this client will
            // overflow
            const std::size_t DEFAULT_MESSAGE_MAX_PAYLOAD_SIZE = 63 * 1024;

            const char *const KEY_MESSAGE_MAX_SIZE
                = "tunneling.proxy.message.max_size";
            const std::size_t DEFAULT_MESSAGE_MAX_SIZE = 64 * 1024;

            const char *const KEY_MAX_ACTIVE_CONNECTIONS
                = "tunneling.proxy.tcp.max_active_connections";
            const std::uint32_t DEFAULT_MAX_ACTIVE_CONNECTIONS = 128;

            const char *const KEY_WEB_SOCKET_PING_PERIOD_MS
                = "tunneling.proxy.websocket.ping_period_ms";
            const std::uint32_t DEFAULT_WEB_SOCKET_PING_PERIOD_MS = 20000;

            const char *const KEY_WEB_SOCKET_CONNECT_RETRY_DELAY_MS
                = "tunneling.proxy.websocket.retry_delay_ms";
            const std::uint32_t DEFAULT_WEB_SOCKET_CONNECT_RETRY_DELAY_MS
                = 2500;

            const char *const KEY_WEB_SOCKET_CONNECT_RETRY_COUNT
                = "tunneling.proxy.websocket.connect_retry_count";
            const std::int32_t DEFAULT_WEB_SOCKET_CONNECT_RETRY_COUNT = -1;

            const char *const KEY_WEB_SOCKET_DATA_ERROR_RETRY
                = "tunneling.proxy.websocket.reconnect_on_data_error";
            const bool DEFAULT_WEB_SOCKET_DATA_ERROR_RETRY = true;

            const char *const KEY_WEB_SOCKET_SUBPROTOCOL
                = "tunneling.proxy.websocket.subprotocol";
            const std::string DEFAULT_WEB_SOCKET_SUBPROTOCOL
                = "aws.iot.securetunneling-3.0";

            const char *const KEY_WEB_SOCKET_MAX_FRAME_SIZE
                = "tunneling.proxy.websocket.max_frame_size";
            const std::size_t DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE
                = DEFAULT_MAX_DATA_FRAME_SIZE * 2;

            const char *const KEY_TCP_READ_BUFFER_SIZE
                = "tunneling.proxy.tcp.read_buffer_size";
            const std::size_t DEFAULT_TCP_READ_BUFFER_SIZE
                = DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

            const char *const KEY_TCP_WRITE_BUFFER_SIZE
                = "tunneling.proxy.tcp.write_buffer_size";
            const std::size_t DEFAULT_TCP_WRITE_BUFFER_SIZE
                = DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

            const char *const KEY_WEB_SOCKET_WRITE_BUFFER_SIZE
                = "tunneling.proxy.websocket.write_buffer_size";
            const std::size_t DEFAULT_WEB_SOCKET_WRITE_BUFFER_SIZE
                = DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

            const char *const KEY_WEB_SOCKET_READ_BUFFER_SIZE
                = "tunneling.proxy.websocket.read_buffer_size";
            const std::size_t DEFAULT_WEB_SOCKET_READ_BUFFER_SIZE
                = DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

// Create a more concise way to apply a settings default value only if it isn't
// already in the ptree. Macro saves a bunch of repeat typing of the key in code
// and needing to repeat the type
#define ADD_SETTING_DEFAULT(settings, key) \
    if (!settings \
             .get_optional<std::remove_const_t<decltype(DEFAULT_##key)>>( \
                 KEY_##key \
             ) \
             .has_value()) { \
        settings.add<std::remove_const_t<decltype(DEFAULT_##key)>>( \
            KEY_##key, DEFAULT_##key \
        ); \
    }

            void apply_default_settings(ptree &settings) {
                ADD_SETTING_DEFAULT(settings, DEFAULT_BIND_ADDRESS);
                ADD_SETTING_DEFAULT(settings, DATA_LENGTH_SIZE);
                ADD_SETTING_DEFAULT(settings, MAX_DATA_FRAME_SIZE);
                ADD_SETTING_DEFAULT(settings, TCP_CONNECTION_RETRY_COUNT);
                ADD_SETTING_DEFAULT(settings, TCP_CONNECTION_RETRY_DELAY_MS);
                ADD_SETTING_DEFAULT(settings, TCP_READ_BUFFER_SIZE);
                ADD_SETTING_DEFAULT(settings, MESSAGE_MAX_PAYLOAD_SIZE);
                ADD_SETTING_DEFAULT(settings, MESSAGE_MAX_SIZE);
                ADD_SETTING_DEFAULT(settings, MAX_ACTIVE_CONNECTIONS);
                ADD_SETTING_DEFAULT(settings, WEB_SOCKET_PING_PERIOD_MS);
                ADD_SETTING_DEFAULT(
                    settings, WEB_SOCKET_CONNECT_RETRY_DELAY_MS
                );
                ADD_SETTING_DEFAULT(settings, WEB_SOCKET_CONNECT_RETRY_COUNT);
                ADD_SETTING_DEFAULT(settings, WEB_SOCKET_DATA_ERROR_RETRY);
                ADD_SETTING_DEFAULT(settings, WEB_SOCKET_SUBPROTOCOL);
                ADD_SETTING_DEFAULT(settings, WEB_SOCKET_MAX_FRAME_SIZE);
                ADD_SETTING_DEFAULT(settings, WEB_SOCKET_WRITE_BUFFER_SIZE);
                ADD_SETTING_DEFAULT(settings, WEB_SOCKET_READ_BUFFER_SIZE);

                apply_region_overrides(settings);
            }

            void apply_region_overrides(ptree &settings) {
                settings.put<std::string>(
                    (boost::format("%1%.%2%") % KEY_PROXY_ENDPOINT_REGION_MAP
                     % "cn-north-1")
                        .str()
                        .c_str(),
                    "data.tunneling.iot.cn-north-1.amazonaws.com.cn"
                );
                settings.put<std::string>(
                    (boost::format("%1%.%2%") % KEY_PROXY_ENDPOINT_REGION_MAP
                     % "cn-northwest-1")
                        .str()
                        .c_str(),
                    "data.tunneling.iot.cn-northwest-1.amazonaws.com.cn"
                );
            }
        }
    }
}
}
