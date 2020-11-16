// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdlib>
#include <string>
#include <utility>
#include <unordered_map>
#include <unordered_set>

using std::string;
using std::unordered_set;
using std::vector;
using std::unordered_map;

namespace aws { namespace iot { namespace securedtunneling { namespace config_file {
    bool is_valid_directory(string const & file_dir);
    std::vector<string> get_all_files(const string & file_dir);
    std::string get_default_port_mapping_dir();
    void read_service_ids_from_config_files(std::vector<std::string> const & file_paths,
            unordered_set<string> const & service_ids,
            unordered_map<string, string> & serviceId_to_endpoint_mapping);
    void update_port_mapping(const string & cli_input, unordered_map<string, string> & serviceId_to_endpoint_mapping);
}}}}
