// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

using std::string;
using std::unordered_map;
using std::unordered_set;
using std::vector;

namespace aws {
namespace iot {
    namespace securedtunneling {
        namespace config_file {
            bool is_valid_directory(const string &file_dir);
            std::vector<string> get_all_files(const string &file_dir);
            std::string get_default_port_mapping_dir();
            void read_service_ids_from_config_files(
                const std::vector<std::string> &file_paths,
                const unordered_set<string> &service_ids,
                unordered_map<string, string> &serviceId_to_endpoint_mapping
            );
            void update_port_mapping(
                const string &cli_input,
                unordered_map<string, string> &serviceId_to_endpoint_mapping
            );
            std::string PrintVersion();
        }
    }
}
}
