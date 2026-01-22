// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <cstdint>

namespace aws { namespace iot { namespace securedtunneling { namespace validation {

    // Input length limits
    constexpr size_t MAX_ACCESS_TOKEN_LENGTH = 4096;
    constexpr size_t MAX_CLIENT_TOKEN_LENGTH = 128;
    constexpr size_t MIN_CLIENT_TOKEN_LENGTH = 32;
    constexpr size_t MAX_ENDPOINT_LENGTH = 253;
    constexpr size_t MAX_REGION_LENGTH = 64;
    constexpr size_t MAX_PATH_LENGTH = 4096;
    constexpr size_t MAX_SERVICE_ID_LENGTH = 128;
    constexpr size_t MAX_BIND_ADDRESS_LENGTH = 253;
    constexpr uint16_t MIN_PORT = 1;
    constexpr uint16_t MAX_PORT = 65535;

    /**
     * Validates access token format and length
     * @param token The access token to validate
     * throws runtime_error id invalid
     */
    void validate_access_token(const std::string& token);

    /**
     * Validates client token format (alphanumeric and hyphens, 32-128 chars)
     * @param token The client token to validate
     * @throws runtime_error if invalid
     */
    void validate_client_token(const std::string& token);

    /**
     * Validates proxy endpoint format
     * @param endpoint The endpoint to validate
     * @throws runtime_error if invalid
     */
    void validate_endpoint(const std::string& endpoint);

    /**
     * Validates AWS region format
     * @param region The region to validate
     * @throws runtime_error if invalid
     */
    void validate_region(const std::string& region);

    /**
     * Validates service ID format
     * @param service_id The service ID to validate
     * @throws runtime_error if invalid
     */
    void validate_service_id(const std::string& service_id);

    /**
     * Validates port string and converts to uint16_t
     * @param port_str The port string to validate
     * @throws runtime_error if invalid
     */
    void validate_port_string(const std::string& port_str);

    /**
     * Validates file/directory path
     * @param path The path to validate
     * @throws runtime_error if invalid
     */
    void validate_path(const std::string& path);

    /**
     * Validates bind address format
     * @param address The bind address to validate
     * @throws runtime_error if invalid
     */
    void validate_bind_address(const std::string& address);

    /**
     * Validates destination endpoint format (port, host:port, or hostname)
     * @param endpoint The endpoint to validate
     * @throws runtime_error if invalid
     */
    void validate_destination_endpoint(const std::string& endpoint);

    /**
     * Logs rejected input for security monitoring
     * @param input_name Name of the input field
     * @param reason Reason for rejection
     */
    void log_rejected_input(const std::string& input_name, const std::string& reason);

}}}}
