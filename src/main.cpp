// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include <cstdlib>
#include <chrono>
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
#include <boost/asio.hpp>

#include "ProxySettings.h"
#include "TcpAdapterProxy.h"

using std::uint16_t;
using std::endl;
using std::exception;
using std::get;
using std::string;
using std::tuple;

using boost::property_tree::ptree;
using boost::program_options::value;
using boost::program_options::variables_map;
using boost::program_options::options_description;

using aws::iot::securedtunneling::adapter_proxy_config;
using aws::iot::securedtunneling::tcp_adapter_proxy;
using aws::iot::securedtunneling::proxy_mode;

char const * const TOKEN_ENV_VARIABLE = "AWSIOT_TUNNEL_ACCESS_TOKEN";
char const * const ENDPOINT_ENV_VARIABLE = "AWSIOT_TUNNEL_ENDPOINT";
char const * const REGION_ENV_VARIABLE = "AWSIOT_TUNNEL_REGION";

tuple<string, uint16_t> get_host_and_port(string const & endpoint, uint16_t default_port)
{
    try
    {
        size_t position = endpoint.find(':');
        if (position != string::npos && position != endpoint.length() - 1)
        {
            const string host = endpoint.substr(0, position);
            const string port = endpoint.substr(position + 1, endpoint.length() - (position + 1));
            const uint16_t portnum = static_cast<uint16_t>(stoi(port, &position));
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

tuple<string, uint16_t> get_host_and_port(string const & endpoint, std::string default_host)
{
    try
    {
        size_t position = endpoint.find(':');
        if (position != string::npos && position != endpoint.length() - 1)
        {
            const string host = endpoint.substr(0, position);
            const string port = endpoint.substr(position + 1, endpoint.length() - (position + 1));
            const uint16_t portnum = static_cast<uint16_t>(stoi(port, &position));
            if (port.length() == 0 || position != port.length()) throw std::invalid_argument("");
            return std::make_tuple(host, portnum);
        }
        else
        {
            if (position == endpoint.length() - 1) throw std::invalid_argument("");
            return std::make_tuple(default_host, stoi(endpoint));
        }
    }
    catch(std::invalid_argument &)
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
        //turning off is more efficient than having a filter that is 'basically off'
        boost::log::core::get()->set_logging_enabled(false);
        break;
    }
}

void init_logging()
{
    boost::log::add_common_attributes();
    boost::log::add_console_log(std::cout, boost::log::keywords::format = boost::phoenix::bind(&log_formatter, boost::log::expressions::stream, boost::log::expressions::record));
    set_logging_filter(4);  //default to info level until later overridden
}

bool process_cli(int argc, char ** argv, adapter_proxy_config &cfg, ptree &settings, std::uint16_t &logging_level)
{
    init_logging();
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
        ("source-listen-port,s", value<std::uint16_t>(), "Assigns source mode and sets the port to listen to.")
        ("destination-app,d", value<string>(), "Assigns destination mode and sets the endpoint with the arg in [host]:<port> or just <port> (default localhost) format.")
        ("local-bind-address,b", value(&cfg.bind_address), "Assigns a specific local address to bind to for listening in source mode or a local socket address for destination mode.")
        ("capath,c", value(&cfg.additional_ssl_verify_path), "Adds the directory containing certificate authority files to be used for performing verification")
        ("no-ssl-host-verify,k", boost::program_options::bool_switch(&cfg.no_ssl_host_verify), "Turn off SSL host verification")
        ("export-default-settings", value<string>(), "Exports the default settings for the TCP adapter to the given file as json and exit program")
        ("settings-json", value<string>(), "Use the input JSON file to apply fine grained settings.")
        ("config", value<string>(), "Use the supplied configuration file to apply CLI args. Actual CLI args override the contents of this file")
        ("verbose,v", value<std::uint16_t>()->default_value(4), "Logging level to standard out. [0, 255] (0=off, 1=fatal, 2=error, 3=warning, 4=info, 5=debug, >=6=trace)")
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

    if (vm.count("settings-json"))
    {   //can throw json_parser_error
        BOOST_LOG_TRIVIAL(info) << "Using settings specified in file: " << vm["settings-json"].as<string>();
        boost::property_tree::json_parser::read_json(vm["settings-json"].as<string>(), settings);
    }

    if (vm.count("source-listen-port") + vm.count("destination-app") > 1 || vm.count("source-listen-port") + vm.count("destination-app") == 0)
    {
        throw std::runtime_error("Must specify one and only one of --source-listen-port/-s or --destination-app/-d options");
    }

    if (vm.count("region") + vm.count("proxy-endpoint") > 1 || vm.count("region") + vm.count("proxy-endpoint") == 0)
    {
        throw std::runtime_error("Must specify one and only one of --region/-r or --proxy-endpoint/-e options");
    }

    //trigger validation of required options
    notify(vm);
    //collect and normalize CLI args to usable inputs
    logging_level = vm["verbose"].as<std::uint16_t>();
    if (token_cli_warning)
    {
        BOOST_LOG_TRIVIAL(warning) << "Found access token supplied via CLI arg. Consider using environment variable " << TOKEN_ENV_VARIABLE << " instead";
    }
    cfg.access_token = vm["access-token"].as<string>();

    //below endpoint need to be finalized
    string proxy_endpoint = vm.count("proxy-endpoint") == 1 ? vm["proxy-endpoint"].as<string>() :
        (boost::format(GET_SETTING(settings, PROXY_ENDPOINT_HOST_FORMAT))%vm["region"].as<string>()).str();

    transform(proxy_endpoint.begin(), proxy_endpoint.end(), proxy_endpoint.begin(), ::tolower);
    tuple<string, uint16_t> proxy_host_and_port = get_host_and_port(proxy_endpoint, aws::iot::securedtunneling::DEFAULT_PROXY_SERVER_PORT);
    cfg.proxy_host = std::get<0>(proxy_host_and_port);
    cfg.proxy_port = std::get<1>(proxy_host_and_port);

    cfg.mode = vm.count("destination-app") == 1 ? proxy_mode::DESTINATION : proxy_mode::SOURCE;
    if (cfg.mode == proxy_mode::DESTINATION)
    {
        string data_endpoint = vm["destination-app"].as<string>();
        transform(data_endpoint.begin(), data_endpoint.end(), data_endpoint.begin(), ::tolower);
        tuple<string, uint16_t> data_endpoint_and_point = get_host_and_port(data_endpoint, "");
        cfg.data_host = std::get<0>(data_endpoint_and_point);
        cfg.data_port = std::get<1>(data_endpoint_and_point);
    }
    else
    {
        //data host remains unused in source mode
        cfg.data_port = vm["source-listen-port"].as<std::uint16_t>();
        cfg.on_listen_port_assigned = [](std::uint16_t listen_port)
        {
            //this is an opportunity to use actual empheral port if it was assigned because
            //the specified port was 0
            BOOST_LOG_TRIVIAL(info) << "Listen port assigned: " << listen_port;
        };
    }

    return true;
}

int main(int argc, char ** argv)
{
    try
    {
        adapter_proxy_config cfg;
        ptree settings;
        std::uint16_t logging_level;

        if (process_cli(argc, argv, cfg, settings, logging_level))
        {
            set_logging_filter(logging_level);
            tcp_adapter_proxy proxy{ settings, cfg };
            proxy.run_proxy();
        }
    }
    catch (exception &e)
    {
        BOOST_LOG_TRIVIAL(fatal) << e.what();
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
