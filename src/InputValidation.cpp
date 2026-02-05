// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "InputValidation.h"
#include <boost/log/trivial.hpp>
#include <regex>
#include <stdexcept>

namespace aws {
namespace iot {
    namespace securedtunneling {
        namespace validation {

            void log_rejected_input(
                const std::string &input_name, const std::string &reason
            ) {
                BOOST_LOG_TRIVIAL(warning) << "SECURITY: Rejected input for '"
                                           << input_name << "': " << reason;
            }

            void validate_access_token(const std::string &token) {
                if (token.empty()) {
                    log_rejected_input("access-token", "empty token");
                    throw std::runtime_error("Access token cannot be empty");
                }
                if (token.length() > MAX_ACCESS_TOKEN_LENGTH) {
                    log_rejected_input(
                        "access-token", "exceeds maximum length"
                    );
                    throw std::runtime_error(
                        "Access token exceeds maximum allowed length"
                    );
                }
                // Reject control characters and null bytes
                for (char c : token) {
                    if (c < 0x20 || c == 0x7F) {
                        log_rejected_input(
                            "access-token", "contains control characters"
                        );
                        throw std::runtime_error(
                            "Access token contains invalid control characters"
                        );
                    }
                }
            }

            void validate_client_token(const std::string &token) {
                if (token.empty()) {
                    BOOST_LOG_TRIVIAL(trace)
                        << "Client token is empty, skipping validation";
                    return; // Client token is optional
                }
                if (token.length() < MIN_CLIENT_TOKEN_LENGTH
                    || token.length() > MAX_CLIENT_TOKEN_LENGTH) {
                    log_rejected_input(
                        "client-token", "invalid length (must be 32-128 chars)"
                    );
                    throw std::runtime_error(
                        "Client token must be between 32 and 128 characters"
                    );
                }
                // Reject control characters and null bytes
                for (char c : token) {
                    if (c < 0x20 || c == 0x7F) {
                        log_rejected_input(
                            "client-token", "contains control characters"
                        );
                        throw std::runtime_error(
                            "Client token contains invalid control characters"
                        );
                    }
                }
            }

            void validate_endpoint(const std::string &endpoint) {
                if (endpoint.empty()) {
                    log_rejected_input("proxy-endpoint", "empty endpoint");
                    throw std::runtime_error("Proxy endpoint cannot be empty");
                }
                if (endpoint.length() > MAX_ENDPOINT_LENGTH) {
                    log_rejected_input(
                        "proxy-endpoint", "exceeds maximum length"
                    );
                    throw std::runtime_error(
                        "Proxy endpoint exceeds maximum allowed length"
                    );
                }
                // Valid hostname/IP with optional port: hostname:port or
                // hostname Allow alphanumeric, dots, hyphens, colons (for
                // port), and brackets (for IPv6)
                static const std::regex endpoint_pattern(
                    "^[a-zA-Z0-9.:\\[\\]-]+$"
                );
                if (!std::regex_match(endpoint, endpoint_pattern)) {
                    log_rejected_input("proxy-endpoint", "invalid characters");
                    throw std::runtime_error(
                        "Proxy endpoint contains invalid characters"
                    );
                }
            }

            void validate_region(const std::string &region) {
                if (region.empty()) {
                    log_rejected_input("region", "empty region");
                    throw std::runtime_error("Region cannot be empty");
                }
                if (region.length() > MAX_REGION_LENGTH) {
                    log_rejected_input("region", "exceeds maximum length");
                    throw std::runtime_error(
                        "Region exceeds maximum allowed length"
                    );
                }
                // AWS region format: lowercase letters, numbers, and hyphens
                static const std::regex region_pattern("^[a-z0-9-]+$");
                if (!std::regex_match(region, region_pattern)) {
                    log_rejected_input("region", "invalid format");
                    throw std::runtime_error(
                        "Region must contain only lowercase letters, numbers, "
                        "and hyphens"
                    );
                }
            }

            void validate_service_id(const std::string &service_id) {
                if (service_id.empty()) {
                    return; // Empty service ID is valid for v1 format
                }
                if (service_id.length() > MAX_SERVICE_ID_LENGTH) {
                    log_rejected_input("service-id", "exceeds maximum length");
                    throw std::runtime_error(
                        "Service ID exceeds maximum allowed length"
                    );
                }
                // Service ID: alphanumeric, hyphens, underscores
                static const std::regex service_id_pattern("^[a-zA-Z0-9_-]+$");
                if (!std::regex_match(service_id, service_id_pattern)) {
                    log_rejected_input("service-id", "invalid characters");
                    throw std::runtime_error(
                        "Service ID must contain only alphanumeric characters, "
                        "hyphens, and underscores"
                    );
                }
            }

            void validate_port_string(const std::string &port_str) {
                if (port_str.empty()) {
                    log_rejected_input("port", "empty port string");
                    throw std::runtime_error("Port cannot be empty");
                }
                // Only digits allowed
                static const std::regex port_pattern("^[0-9]+$");
                if (!std::regex_match(port_str, port_pattern)) {
                    log_rejected_input("port", "non-numeric characters");
                    throw std::runtime_error("Port must contain only digits");
                }
                try {
                    int port_val = std::stoi(port_str);
                    if (port_val < MIN_PORT || port_val > MAX_PORT) {
                        log_rejected_input("port", "out of valid range");
                        throw std::runtime_error(
                            "Port must be between 1 and 65535"
                        );
                    }
                } catch (const std::out_of_range &) {
                    log_rejected_input("port", "value too large");
                    throw std::runtime_error("Port value is too large");
                }
            }

            void validate_path(const std::string &path) {
                if (path.empty()) {
                    log_rejected_input("path", "empty path");
                    throw std::runtime_error("Path cannot be empty");
                }
                if (path.length() > MAX_PATH_LENGTH) {
                    log_rejected_input("path", "exceeds maximum length");
                    throw std::runtime_error(
                        "Path exceeds maximum allowed length"
                    );
                }
                // Check for null bytes (potential injection)
                if (path.find('\0') != std::string::npos) {
                    log_rejected_input("path", "contains null byte");
                    throw std::runtime_error("Path contains invalid null byte");
                }
            }

            void validate_bind_address(const std::string &address) {
                if (address.empty()) {
                    return; // Empty bind address uses default
                }
                if (address.length() > MAX_BIND_ADDRESS_LENGTH) {
                    log_rejected_input(
                        "bind-address", "exceeds maximum length"
                    );
                    throw std::runtime_error(
                        "Bind address exceeds maximum allowed length"
                    );
                }
                // Valid hostname/IP: alphanumeric, dots, hyphens, colons
                // (IPv6), brackets
                static const std::regex address_pattern(
                    "^[a-zA-Z0-9.:\\[\\]-]+$"
                );
                if (!std::regex_match(address, address_pattern)) {
                    log_rejected_input("bind-address", "invalid characters");
                    throw std::runtime_error(
                        "Bind address contains invalid characters"
                    );
                }
            }

            void validate_destination_endpoint(const std::string &endpoint) {
                if (endpoint.empty()) {
                    log_rejected_input("endpoint", "empty endpoint");
                    throw std::runtime_error("Endpoint cannot be empty");
                }

                // Check if it's just a port number
                static const std::regex port_only_pattern("^[0-9]+$");
                if (std::regex_match(endpoint, port_only_pattern)) {
                    validate_port_string(endpoint);
                    return;
                }

                // It's host:port or just host - validate the address part
                validate_bind_address(endpoint);

                // Extract and validate port if present (last colon not inside
                // brackets)
                size_t last_colon = endpoint.rfind(':');
                if (last_colon != std::string::npos) {
                    // Check it's not inside IPv6 brackets
                    size_t bracket_close = endpoint.rfind(']');
                    if (bracket_close == std::string::npos
                        || last_colon > bracket_close) {
                        std::string port_str = endpoint.substr(last_colon + 1);
                        if (!port_str.empty()) {
                            validate_port_string(port_str);
                        }
                    }
                }
            }

        }
    }
}
}
