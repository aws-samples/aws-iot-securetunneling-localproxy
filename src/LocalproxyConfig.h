// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <tuple>
#include <functional>
#include <vector>
#include <queue>
#include <memory>
#include <boost/log/trivial.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/optional.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl/rfc2818_verification.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/format.hpp>
#include <boost/property_tree/ptree.hpp>
#include "ProxySettings.h"
#include "TcpConnection.h"
#include "TcpServer.h"
#include "TcpClient.h"
#include "Message.pb.h"
#include "Url.h"

namespace aws {
    namespace iot {
        namespace securedtunneling {
            enum proxy_mode {
                UNKNOWN = 0,
                SOURCE = 1,
                DESTINATION = 2
            };

            /**
             * This struct is for the global localproxy configurations, most of these properties are provided directly
             * by the user, directly deduced from user input or fallback to a default value.
             */
            struct LocalproxyConfig
            {
                /**
                 * Proxy server endpoint URL, either provided as input or deduced from the region
                 */
                std::string                             proxy_host { };
                /**
                 * Proxy server endpoint port, default to 443 unless the provided endpoint is not https, then it's 80.
                 */
                std::uint16_t                           proxy_port{ 0 };
                /**
                 * The web proxy endpoint URL. This will be set only if a web proxy is necessary.
                 */
                std::string                             web_proxy_host { };
                /**
                 * The web proxy endpoint port. This will be set only if a web proxy is necessary. defaults to 3128.
                 */
                std::uint16_t                           web_proxy_port {0 };
                /**
                 * The web proxy authN. This will be set only if an web proxy is necessary and it requires authN.
                 */
                std::string                             web_proxy_auth { };
                /**
                 * This flag indicates whether the connection to the web proxy will be use TLS or not.
                 */
                bool                                    is_web_proxy_using_tls { };
                /**
                 * The tunnel access token which the user gets when they open the tunnel.
                 */
                std::string                             access_token { };
                proxy_mode                              mode{ proxy_mode::UNKNOWN };
                /**
                 * local address to bind to for listening in source mode or a local socket address for destination mode,
                 * defaults localhost.
                 */
                boost::optional<std::string>            bind_address;
                /**
                 * Adds the directory containing certificate authority files to be used for performing verification
                 */
                boost::optional<std::string>            additional_ssl_verify_path;
                /**
                 * Turn off SSL host verification
                 */
                bool                                    no_ssl_host_verify {false};
                std::function<void(const std::uint16_t &, const std::string &)> on_listen_port_assigned;
                /**
                 * the configuration directory where service identifier mappings are stored. If not specified,
                 * will read mappings from default directory ./config (same directory where local proxy binary is running)
                 */
                std::vector<std::string>                config_files;
                /**
                 * Store mapping serviceId -> address:port
                 * The end point will store either source listening or destination service depends on the mode of local proxy.
                 */
                std::unordered_map<std::string, std::string>     serviceId_to_endpoint_map;
                /**
                 * A flag to judge if v2 local proxy needs to fallback to communicate using v1 local proxy message format.
                 * v1 local proxy format fallback will be enabled when a tunnel is opened with no or 1 service id.
                 * If this is set to true, it means that v2 local proxy won't validate service id field.
                 */
                bool                                             is_v1_message_format {false};
            };
        }
    }
}
