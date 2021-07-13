// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <cstdlib>
#include <algorithm>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
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

#include "ProxySettings.h"
#include "TcpAdapterProxy.h"
#include "config/ConfigFile.h"
#include "LocalproxyConfig.h"

using std::uint16_t;
using std::endl;
using std::exception;
using std::get;
using std::string;
using std::tuple;
using std::unordered_set;
using std::vector;
using std::unordered_map;

using boost::property_tree::ptree;
using boost::program_options::value;
using boost::program_options::variables_map;
using boost::program_options::options_description;

using aws::iot::securedtunneling::LocalproxyConfig;
using aws::iot::securedtunneling::tcp_adapter_proxy;
using aws::iot::securedtunneling::proxy_mode;
using aws::iot::securedtunneling::get_region_endpoint;
using aws::iot::securedtunneling::settings::apply_region_overrides;

char const * const TOKEN_ENV_VARIABLE = "AWSIOT_TUNNEL_ACCESS_TOKEN";
char const * const ENDPOINT_ENV_VARIABLE = "AWSIOT_TUNNEL_ENDPOINT";
char const * const REGION_ENV_VARIABLE = "AWSIOT_TUNNEL_REGION";
char const * const WEB_PROXY_ENV_VARIABLE = "HTTPS_PROXY";
char const * const web_proxy_env_variable = "https_proxy";

tuple<string, uint16_t> get_host_and_port(string const & endpoint, uint16_t default_port)
{
    try
    {
        size_t position = endpoint.find(':');
        if (position != string::npos && position != endpoint.length() - 1)
        {
            const string host = endpoint.substr(0, position);
            const string port = endpoint.substr(position + 1, endpoint.length() - (position + 1));
            const auto portnum = static_cast<uint16_t>(stoi(port, &position));
            if (port.length() == 0 || position != port.length()) throw std::invalid_argument("");
            return std::make_tuple(host, portnum);
        }
        else
        {
            if (position == endpoint.length() - 1) throw std::invalid_argument("");
            return std::make_tuple(endpoint, default_port);
        }
    }
    catch (std::invalid_argument &)
    {
        throw std::invalid_argument((boost::format("Invalid endpoint specified: %1%") % endpoint).str());
    }
}

void log_formatter(boost::log::formatting_ostream& strm, boost::log::record_view const& rec)
{
    //Example log format:
    //[2019-01-17T21:37:15.528290]{632}[trace]   Waiting for stream start...
    std::ostringstream severity;
    //severity needs to be pulled out of the inline stream operations due to a gcc-8.2.0 compile error (seemingly a bug?)
    //error: 'class std::basic_ostream<char>' has no member named 'str'    -- clang and msvc are fine
    //.str() is not a member of std::basic_ostream<char> but is a member of ostringstream
    severity << "[" << boost::log::trivial::to_string(rec["Severity"].extract<boost::log::trivial::severity_level>().get()) << "]";
    strm <<
        "[" << boost::posix_time::to_iso_extended_string(rec["TimeStamp"].extract<boost::posix_time::ptime>().get()) << "]" <<
        "{" << std::dec << rec["ProcessID"].extract<boost::log::attributes::current_process_id::value_type>().get().native_id() << "}" <<
        std::setw(9) << std::left << severity.str() <<
        " " << rec["Message"].extract<std::string>();
}

void set_logging_filter(std::uint16_t level_numeric)
{
    level_numeric = level_numeric > 6 ? 6 : level_numeric;

    switch (level_numeric)
    {
    case 6:
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::trace);
        break;
    case 5:
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::debug);
        break;
    case 4:
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);
        break;
    case 3:
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::warning);
        break;
    case 2:
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::error);
        break;
    case 1:
        boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::fatal);
        break;
    case 0:
        boost::log::core::get()->set_logging_enabled(false);
        break;
    }
}

void init_logging(std::uint16_t &logging_level)
{
    boost::log::add_common_attributes();
    boost::log::add_console_log(std::cout, boost::log::keywords::format = boost::phoenix::bind(&log_formatter, boost::log::expressions::stream, boost::log::expressions::record));
    set_logging_filter(logging_level);
}

bool process_cli(int argc, char ** argv, LocalproxyConfig &cfg, ptree &settings, std::uint16_t &logging_level)
{
    using namespace aws::iot::securedtunneling::config_file;
#ifdef _AWSIOT_TUNNELING_NO_SSL
    std::cerr << "SSL is disabled" << std::endl;
#endif

    variables_map vm;
    options_description cliargs_desc("Allowed options");
    cliargs_desc.add_options()
        ("help,h", "Show help message")
        ("access-token,t", value<string>()->required(), "Client access token")
        ("proxy-endpoint,e", value<string>(), "Endpoint of proxy server with port (if not default 443). Example: data.tunneling.iot.us-east-1.amazonaws.com:443")
        ("region,r", value<string>(), "Endpoint region where tunnel exists. Mutually exclusive flag with --proxy-endpoint")
        ("source-listen-port,s", value<string>(), "Sets the mappings between source listening ports and service identifier. Example: SSH1=5555 or 5555")
        ("destination-app,d", value<string>(), "Sets the mappings between the endpoint(address:port/port) and service identifier. Example: SSH1=127.0.0.1:22 or 22")
        ("local-bind-address,b", value(&cfg.bind_address), "Assigns a specific local address to bind to for listening in source mode or a local socket address for destination mode.")
        ("capath,c", value(&cfg.additional_ssl_verify_path), "Adds the directory containing certificate authority files to be used for performing verification")
        ("no-ssl-host-verify,k", boost::program_options::bool_switch(&cfg.no_ssl_host_verify), "Turn off SSL host verification")
        ("export-default-settings", value<string>(), "Exports the default settings for the TCP adapter to the given file as json and exit program")
        ("settings-json", value<string>(), "Use the input JSON file to apply fine grained settings.")
        ("config", value<string>(), "Use the supplied configuration file to apply CLI args. Actual CLI args override the contents of this file")
        ("verbose,v", value<std::uint16_t>()->default_value(4), "Logging level to standard out. [0, 255] (0=off, 1=fatal, 2=error, 3=warning, 4=info, 5=debug, >=6=trace)")
        ("mode,m", value<string>(), "The mode local proxy will run: src(source) or dst(destination)")
        ("config-dir", value<string>(), "Set the configuration directory where service identifier mappings are stored. If not specified, will read mappings from default directory ./config (same directory where local proxy binary is running)")
        ;
    store(parse_command_line(argc, argv, cliargs_desc), vm);

    if (vm.count("help"))
    {
        std::cerr << cliargs_desc << "\n";
        return false;
    }
    else if (vm.count("export-default-settings"))
    {
        aws::iot::securedtunneling::settings::apply_default_settings(settings);
        boost::property_tree::json_parser::write_json(vm["export-default-settings"].as<string>(), settings, std::locale(), true);
        return false;
    }

    //collect and normalize CLI args to usable inputs
    logging_level = vm["verbose"].as<std::uint16_t>();
    init_logging(logging_level);

    bool token_cli_warning = vm.count("access-token") != 0;

    //dont allow above settings to be impacted by configuration file or environment variable parsers
    if (vm.count("config"))
    {
        store(parse_config_file(vm["config"].as<string>().c_str(), cliargs_desc), vm);
    }
    //either way, parse from environment
    store(parse_environment(cliargs_desc, 
        [](std::string name) -> std::string
        {
            if (name == TOKEN_ENV_VARIABLE)
                return "access-token";
            if (name == ENDPOINT_ENV_VARIABLE)
                return "proxy-endpoint";
            if (name == REGION_ENV_VARIABLE)
                return "region";
            return "";
        }), vm);

    apply_region_overrides(settings);
    if (vm.count("settings-json"))
    {
        BOOST_LOG_TRIVIAL(info) << "Using settings specified in file: " << vm["settings-json"].as<string>();
        boost::property_tree::json_parser::read_json(vm["settings-json"].as<string>(), settings);
    }


    if (vm.count("region") + vm.count("proxy-endpoint") > 1 || vm.count("region") + vm.count("proxy-endpoint") == 0)
    {
        throw std::runtime_error("Must specify one and only one of --region/-r or --proxy-endpoint/-e options");
    }

    //trigger validation of required options
    notify(vm);
    if (token_cli_warning)
    {
        BOOST_LOG_TRIVIAL(warning) << "Found access token supplied via CLI arg. Consider using environment variable " << TOKEN_ENV_VARIABLE << " instead";
    }
    cfg.access_token = vm["access-token"].as<string>();

    string proxy_endpoint = vm.count("proxy-endpoint") == 1 ? vm["proxy-endpoint"].as<string>() :
        get_region_endpoint(vm["region"].as<string>(), settings);

    transform(proxy_endpoint.begin(), proxy_endpoint.end(), proxy_endpoint.begin(), ::tolower);
    tuple<string, uint16_t> proxy_host_and_port = get_host_and_port(proxy_endpoint, aws::iot::securedtunneling::DEFAULT_PROXY_SERVER_PORT);
    cfg.proxy_host = std::get<0>(proxy_host_and_port);
    cfg.proxy_port = std::get<1>(proxy_host_and_port);

    // https_proxy environment variable takes precedence over HTTPS_PROXY environment variable
    const char * lowercase_web_proxy_endpoint = std::getenv(web_proxy_env_variable);
    const char * upper_web_proxy_endpoint = std::getenv(WEB_PROXY_ENV_VARIABLE);
    const string web_proxy_endpoint = lowercase_web_proxy_endpoint != nullptr ? std::string(lowercase_web_proxy_endpoint)
                                                                              : upper_web_proxy_endpoint != nullptr ? std::string(upper_web_proxy_endpoint)
                                                                                                                      : "";
    if (!web_proxy_endpoint.empty()) {
        std::shared_ptr<aws::iot::securedtunneling::url> url = nullptr;
        try {
            url = std::make_shared<aws::iot::securedtunneling::url>(web_proxy_endpoint);
        } catch (exception &e) {
            BOOST_LOG_TRIVIAL(fatal) << "Failed to parse the value of environment variable "
                << (lowercase_web_proxy_endpoint != nullptr ? web_proxy_env_variable : WEB_PROXY_ENV_VARIABLE);
            throw e;
        }
        cfg.web_proxy_host = url->host;
        if (url->port == 0) {
            cfg.web_proxy_port = aws::iot::securedtunneling::DEFAULT_WEB_PROXY_SERVER_PORT;
            BOOST_LOG_TRIVIAL(warning) << "No port was was provided for the web proxy, using default: " << cfg.web_proxy_port;
        } else {
            cfg.web_proxy_port = url->port;
        }
        cfg.web_proxy_auth = url->authentication;
        if (url->protocol == "https") {
            cfg.is_web_proxy_using_tls = true;
        } else if (url->protocol == "http") {
            cfg.is_web_proxy_using_tls = false;
        } else {
            throw std::invalid_argument("Unsupported protocol");
        }
        BOOST_LOG_TRIVIAL(info) << "Found Web proxy information in the environment variables, will use it to connect via the proxy.";
    }

    cfg.mode = vm.count("destination-app") == 1 ? proxy_mode::DESTINATION : proxy_mode::SOURCE;

    if (vm.count("mode"))
    {
        string mode = vm["mode"].as<string>();
        if (mode != "src" && mode != "dst" && mode != "source" && mode != "destination")
        {
            throw std::runtime_error("Mode value is wrong! Allowed values are: src, dst, source, destination");
        }
        // Assign the value to the right mode
        if (mode == "src" || mode == "source")
        {
            cfg.mode = proxy_mode::SOURCE;
        }
        else if (mode == "dst" || mode == "destination")
        {
            cfg.mode = proxy_mode::DESTINATION;
        }
        else
        {
            throw std::runtime_error("Internal error. Mode value is wrong!");
        }
    }

    /** Invalid input combination for: -s, -d and --mode
     * 1. -s and -d should NOT used together
     * 2. -s and mode value is dst/destination should NOT used together
     * 3. -d and mode value is src/source should NOT used together.
     * 4. At least one of the parameter should be provided to start local proxy in either source or destination mode:
     * -s, -d or -m
     */
    if (vm.count("source-listen-port") + vm.count("destination-app") > 1)
    {
        throw std::runtime_error("Must specify one and only one of --source-listen-port/-s or --destination-app/-d");
    }
    else if (vm.count("source-listen-port") + vm.count("destination-app") + vm.count("mode")== 0)
    {
        throw std::runtime_error("Must specify one of --source-listen-port/-s or --destination-app/-d or --mode");
    }
    else if (vm.count("source-listen-port") && vm.count("mode") && cfg.mode == proxy_mode::DESTINATION )
    {
        throw std::runtime_error("-s and --mode have mismatched mode. Mode is set to destination!");
    }
    else if (vm.count("destination-app") && vm.count("mode") && cfg.mode == proxy_mode::SOURCE )
    {
        throw std::runtime_error("-s and --mode have mismatched mode. Mode is set to source!");
    }

    /**
     * 1. Generate from the CLI parsing
     * 2. Have a reserve mapping for port_mappings
     */
     if (vm.count("destination-app"))
     {
         cfg.mode = proxy_mode::DESTINATION;
         update_port_mapping(vm["destination-app"].as<string>(), cfg.serviceId_to_endpoint_map);
         // Support v1 local proxy format
         if (cfg.serviceId_to_endpoint_map.size() == 1 && cfg.serviceId_to_endpoint_map.begin()->first.empty())
         {
             BOOST_LOG_TRIVIAL(debug) << "v2 local proxy starts with v1 local proxy format";
         }
         else
         {
             BOOST_LOG_TRIVIAL(debug) << "Detect port mapping configuration provided through CLI in destination mode:";
             BOOST_LOG_TRIVIAL(debug) << "----------------------------------------------------------";
             for (auto m: cfg.serviceId_to_endpoint_map)
             {
                 BOOST_LOG_TRIVIAL(debug) << m.first << " = " << m.second;
             }
             BOOST_LOG_TRIVIAL(debug) << "----------------------------------------------------------";
         }
     }


     if (vm.count("source-listen-port"))
     {
         cfg.mode = proxy_mode::SOURCE;
         update_port_mapping(vm["source-listen-port"].as<string>(), cfg.serviceId_to_endpoint_map);
         // Support v1 local proxy format
         if (cfg.serviceId_to_endpoint_map.size() == 1 && cfg.serviceId_to_endpoint_map.begin()->first.empty())
         {
             BOOST_LOG_TRIVIAL(debug) << "v2 local proxy starts with v1 local proxy format";
         }
         else
         {
             BOOST_LOG_TRIVIAL(debug) << "Detect port mapping configuration provided through CLI in source mode:";
             BOOST_LOG_TRIVIAL(debug) << "----------------------------------------------------------";
             for (auto m: cfg.serviceId_to_endpoint_map)
             {
                 BOOST_LOG_TRIVIAL(debug) << m.first << " = " << m.second;
             }
             BOOST_LOG_TRIVIAL(debug) << "----------------------------------------------------------";
         }
     }

    if (vm.count("config-dir"))
    {
        string config_dir = vm["config-dir"].as<string>();
        BOOST_LOG_TRIVIAL(debug) << "Detect port mapping configuration provided through configuration directory :" << config_dir;
        // Run validation against the input
        if (!is_valid_directory(config_dir)) {
            std::string error_message = std::string("Invalid configuration directory: ") + config_dir;
            throw std::runtime_error(error_message);
        }
        cfg.config_files = get_all_files(config_dir);
    }
    else if (is_valid_directory(get_default_port_mapping_dir()))
    {
        // read default directory, if no configuration directory is provided.
        cfg.config_files = get_all_files(get_default_port_mapping_dir());
    }

    if (cfg.mode == proxy_mode::SOURCE && cfg.config_files.empty() && cfg.serviceId_to_endpoint_map.empty())
    {
        BOOST_LOG_TRIVIAL(debug) << "Local proxy does not detect any port mapping configuration. Will pick up random ports to run in source mode.";
    }
    return true;
}


int main(int argc, char ** argv)
{
    try
    {
        LocalproxyConfig cfg;
        ptree settings;
        std::uint16_t logging_level;

        if (process_cli(argc, argv, cfg, settings, logging_level))
        {
            set_logging_filter(logging_level);
            tcp_adapter_proxy proxy{ settings, cfg };
            return proxy.run_proxy();
        }
    }
    catch (exception &e)
    {
        BOOST_LOG_TRIVIAL(fatal) << e.what();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

