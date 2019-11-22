// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <boost/property_tree/ptree.hpp>
namespace aws { namespace iot { namespace securedtunneling { namespace settings {
    using boost::property_tree::ptree;

    extern char const * const KEY_PROXY_ENDPOINT_HOST_FORMAT;
    extern std::string DEFAULT_PROXY_ENDPOINT_HOST_FORMAT;

    extern char const * const KEY_DEFAULT_BIND_ADDRESS;
    extern std::string DEFAULT_DEFAULT_BIND_ADDRESS;

    extern char const * const KEY_DATA_LENGTH_SIZE;
    extern std::size_t const DEFAULT_DATA_LENGTH_SIZE;

    extern char const * const KEY_MAX_DATA_FRAME_SIZE;
    extern std::size_t const DEFAULT_MAX_DATA_FRAME_SIZE;

    extern char const * const KEY_TCP_CONNECTION_RETRY_COUNT;
    extern std::int32_t const DEFAULT_TCP_CONNECTION_RETRY_COUNT;

    extern char const * const KEY_TCP_CONNECTION_RETRY_DELAY_MS;
    extern std::uint32_t const DEFAULT_TCP_CONNECTION_RETRY_DELAY_MS;

    extern char const * const KEY_MESSAGE_MAX_PAYLOAD_SIZE;
    extern std::size_t const DEFAULT_MESSAGE_MAX_PAYLOAD_SIZE;

    extern char const * const KEY_MESSAGE_MAX_SIZE;
    extern std::size_t const DEFAULT_MESSAGE_MAX_SIZE;

    extern char const * const KEY_WEB_SOCKET_PING_PERIOD_MS;
    extern std::uint32_t const DEFAULT_WEB_SOCKET_PING_PERIOD_MS;

    extern char const * const KEY_WEB_SOCKET_CONNECT_RETRY_DELAY_MS;
    extern std::uint32_t const DEFAULT_WEB_SOCKET_CONNECT_RETRY_DELAY_MS;

    extern char const * const KEY_WEB_SOCKET_CONNECT_RETRY_COUNT;
    extern std::int32_t const DEFAULT_WEB_SOCKET_CONNECT_RETRY_COUNT;

    extern char const * const KEY_WEB_SOCKET_DATA_ERROR_RETRY;
    extern bool const DEFAULT_WEB_SOCKET_DATA_ERROR_RETRY;

    extern char const * const KEY_WEB_SOCKET_SUBPROTOCOL;
    extern std::string const DEFAULT_WEB_SOCKET_SUBPROTOCOL;

    extern char const * const KEY_WEB_SOCKET_MAX_FRAME_SIZE;
    extern std::size_t const DEFAULT_WEB_SOCKET_MAX_FRAME_SIZE;

    extern char const * const KEY_TCP_WRITE_BUFFER_SIZE;
    extern std::size_t const DEFAULT_TCP_WRITE_BUFFER_SIZE;

    extern char const * const KEY_TCP_READ_BUFFER_SIZE;
    extern std::size_t const DEFAULT_TCP_READ_BUFFER_SIZE;

    extern char const * const KEY_WEB_SOCKET_WRITE_BUFFER_SIZE;
    extern std::size_t const DEFAULT_WEB_SOCKET_WRITE_BUFFER_SIZE;

    extern char const * const KEY_WEB_SOCKET_READ_BUFFER_SIZE;
    extern std::size_t const DEFAULT_WEB_SOCKET_READ_BUFFER_SIZE;

    //Create a more concise way to apply a settings default value only if it isn't already in the 
    //ptree. Macro saves a bunch of repeat typing of the key in code and needing to repeat the type
    #define GET_SETTING(settings, key) (settings.get<std::remove_const_t<decltype(    \
        ::aws::iot::securedtunneling::settings::DEFAULT_##key)>>                      \
        (::aws::iot::securedtunneling::settings::KEY_##key,                           \
        ::aws::iot::securedtunneling::settings::DEFAULT_##key))

    void apply_default_settings(ptree & settings);
}}}}
