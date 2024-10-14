// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <chrono>
#include <algorithm>
#include <functional>
#include <iostream>
#include <tuple>

#include <boost/phoenix.hpp>
#include <boost/program_options.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/date_time/posix_time/time_formatters.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/expressions.hpp>
#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/sources/severity_feature.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/format.hpp>

#include "ConfigFile.h"
#include "Version.h"

using std::uint16_t;
using std::endl;
using std::exception;
using std::get;
using std::string;
using std::tuple;
using std::unordered_set;
using std::vector;
using std::unordered_map;

namespace filesys = boost::filesystem;
using boost::log::trivial::trace;
using boost::log::trivial::debug;
using boost::log::trivial::info;
using boost::log::trivial::warning;
using boost::log::trivial::error;
using boost::log::trivial::fatal;
using logger = boost::log::sources::severity_logger<boost::log::trivial::severity_level>;



namespace aws { namespace iot { namespace securedtunneling { namespace config_file {
    logger log;
    /**
     * Check if given path is a valid directory
     * @param file_dir : directory file path
     * @return true: valid configuration. false: invalid configuration
     */

    std::string PrintVersion()
    {
        return LOCAL_PROXY_VERSION_FULL;
    }

    bool is_valid_directory(string const & file_dir) {
        bool is_dir = false;
        try {
            filesys::path path_obj(file_dir);
            /**
             * Validate if:
             * 1. Directory path exists
             * 2. Is a directory
             * 3. Is an empty folder
             */
            if (filesys::exists(path_obj) && filesys::is_directory(path_obj) && (!filesys::is_empty(path_obj)))
            {
                is_dir = true;
            }
            else if (!filesys::exists(path_obj))
                BOOST_LOG_SEV(log, debug) << file_dir <<  " does not exist!";
            else if (!filesys::is_directory(path_obj))
                BOOST_LOG_SEV(log, debug) << file_dir <<  " is not a directory!";
            else if (filesys::is_empty(path_obj))
                BOOST_LOG_SEV(log, debug) << file_dir <<  " empty dir! Please add configuration files.";
            else
                BOOST_LOG_SEV(log, debug) << file_dir <<  " is not valid!";
        }
        catch (const filesys::filesystem_error & e) {
            BOOST_LOG_SEV(log, fatal) << e.what();
        }
        return is_dir;
    }

    /**
     * Recursively get the list of all files in the given directory
     * @param file_dir : directory file path
     * @return file paths under the given directory and its subdirectories.
     */
    vector<string> get_all_files(const string & file_dir) {
        vector<std::string> files_under_directory;
        filesys::recursive_directory_iterator end_iter;
        for (filesys::recursive_directory_iterator dir_itr(file_dir); dir_itr != end_iter; ++dir_itr) {
            BOOST_LOG_SEV(log, info) << "Detect configuration files: ";
            if (filesys::is_regular_file(dir_itr->status())) {
                BOOST_LOG_SEV(log, info) << dir_itr->path().generic_string();
                files_under_directory.push_back(dir_itr->path().generic_string());
            }
        }
        return files_under_directory;
    }

    void read_service_ids_from_config_files(std::vector<std::string> const & file_paths, unordered_set<string> const & service_ids, unordered_map<string, string> & serviceId_to_endpoint_mapping)
    {
        for (auto file_path: file_paths)
        {
            boost::property_tree::ptree pt;
            // If find all the service ids, stop searching
            if (serviceId_to_endpoint_mapping.size() == service_ids.size())
            {
                break;
            }
            // Parse file in .ini format, if having issues, skip this file and read the next file in the folder.
            try {
                boost::property_tree::ini_parser::read_ini(file_path, pt);
            }
            catch (const std::exception & e) {
                BOOST_LOG_SEV(log, warning) << "Fail to parse " << file_path << " .Please make sure your file is in .ini format.";
                BOOST_LOG_SEV(log, warning) <<  "Error message from parsing: " << e.what() << " .Continue to the next file.";
                continue;
            }
            for (auto service_id: service_ids) {
                 /**
                  * Search for service ids that does not have a port mapping detected.
                  * If more than one service id mappings found in the configuration files, use the first one found.
                  */
                if (serviceId_to_endpoint_mapping.find(service_id) != serviceId_to_endpoint_mapping.end())
                {
                    continue;
                }
                try {
                    string endpoint = pt.get<std::string>(service_id);
                    serviceId_to_endpoint_mapping.insert({service_id, endpoint});
                }
                catch (boost::property_tree::ptree_bad_path &e) {
                    BOOST_LOG_SEV(log, warning) << "Fail to read file: " << file_path << ". Error message: " << e.what() << ". Ignore this file.";
                }
            }
        }
    }

     /**
      * Interpret the CLI mappings for -s and -d and use this information to build: service_id to endpoint(address:port or port) mapping
      * @param cli_input: the string from -s and -d in the CLI. Example: -s SSH1=5555,SSH2=6666
      * @param serviceId_to_endpoint_mapping: the mapping to be updated: service_id -> endpoint
      * Mapping update is in place.
      */
    void update_port_mapping(const string & input, unordered_map<string, string> & serviceId_to_endpoint_mapping)
    {
        vector<string> splitting_1st_res;
        // Different mappings are delimited by ,
        boost::split(splitting_1st_res, input, boost::is_any_of(","), boost::algorithm::token_compress_on);

        if (splitting_1st_res.empty()) {
            throw std::runtime_error("Must provide at least one port or port mapping for destination-app!");
        }

        // Process each port mapping tags
        for (auto res: splitting_1st_res) {
            // Ignore empty string
            if (res.empty()) continue;
            vector<string> splitting_2rd_res;
            // Inside the mapping, the service_id and port are delimited by =
            boost::split(splitting_2rd_res,
                         res,
                         boost::algorithm::is_any_of("="), boost::algorithm::token_compress_on);
            if (splitting_2rd_res.size() != 2) {
                /** For v1 format, v2 local proxy will continue to support
                 *  Example 1: Local proxy starts in v1 source mode:
                 *  ./localproxy -r us-east-1 -s 3389 -t <source_client_access_token>
                 *  cli_input will be 3389
                 *  Example 2: Local proxy starts in v1 destination mode:
                 *  ./localproxy -r us-east-1 -d localhost:22 -t <destination_client_access_token>
                 *  cli_input will be localhost:22
                 */
                if (splitting_1st_res.size() == 1 && splitting_2rd_res.size() == 1) {
                    boost::trim(splitting_2rd_res[0]);
                    serviceId_to_endpoint_mapping[""] = splitting_2rd_res[0];
                    return;
                }
                else
                {
                    throw std::runtime_error("Wrong format for the port mappings! Example: SSH1=5555,SSH2=6666.");
                }
            }

            // Trim whitespace and insert
            string service_id = boost::trim_copy(splitting_2rd_res[0]);
            string endpoint = boost::trim_copy(splitting_2rd_res[1]);

            if (service_id.empty() || endpoint.empty()) {
                string error_message =
                        string("Wrong format for the port mappings: ") + res + string(" .Example: SSH1=5555");
                throw std::runtime_error(error_message);
            }
            // Check if it's a duplicate mapping, ignore if it has been provided
            if (serviceId_to_endpoint_mapping.find(service_id) != serviceId_to_endpoint_mapping.end()) {
                BOOST_LOG_SEV(log, warning) << "Duplicate mappings, ignore. This mapping already exists: " << service_id << " : "
                                         << serviceId_to_endpoint_mapping[service_id];
                continue;
            }
            serviceId_to_endpoint_mapping[service_id] = endpoint;
        }
    }

    std::string get_default_port_mapping_dir()
    {
        boost::filesystem::path full_path(boost::filesystem::current_path());
        return (boost::format("%1%/config") % full_path.string()).str();
    }
}}}}