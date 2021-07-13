// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#include "Url.h"
#include <string>
#include <algorithm>
#include <cctype>
#include <functional>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/expressions.hpp>
using namespace std;

aws::iot::securedtunneling::url::url(const std::string &url_s) {
    parse(url_s);
}

void aws::iot::securedtunneling::url::parse(const string& url_s)
{
    auto get_substring = [](const string& s, const size_t& start, const size_t& end) {
        return s.substr(start, end - start );
    };

    // parse protocol
    const string protocol_end("://");
    const size_t protocol_end_i = url_s.find(protocol_end);
    if (protocol_end_i == string::npos) {
        BOOST_LOG_TRIVIAL(debug) << "No protocol is provided in the URL, assuming the default protocol: http.";
        protocol = "http";
    } else {
        BOOST_LOG_TRIVIAL(trace) << "Extracting protocol";
        protocol = get_substring(url_s, 0, protocol_end_i);
        if (protocol.empty()) {
            throw invalid_argument("Invalid URL, missing protocol");
        }
        transform(protocol.begin(), protocol.end(), protocol.begin(), ::tolower);
        BOOST_LOG_TRIVIAL(info) << "Parsed URL protocol";
    }

    // parse authentication
    const size_t authentication_end_i = url_s.find_last_of('@');
    const bool is_authN_included = authentication_end_i != string::npos;
    if (is_authN_included) {
        authentication = aws::iot::securedtunneling::url::url_decode(
                get_substring(url_s, protocol_end_i + protocol_end.size(), authentication_end_i)
        );
        if (authentication.empty())
            throw invalid_argument("Empty authentication, if you don't need to authentication information, remove `@`");
        if (authentication.find(':') == string::npos)
            throw invalid_argument("Missing the colon between the username and password in URL.");
        if (authentication.length() < 3)
            throw invalid_argument("Invalid authentication format, missing either username or password.");
        BOOST_LOG_TRIVIAL(debug) << "Parsed basic auth credentials for the URL";
    } else {
        BOOST_LOG_TRIVIAL(debug) << "No authentication is found in the URL, assuming no authentication is required.";
    }

    // parse the host and port
    const size_t host_i = is_authN_included ? authentication_end_i + 1 : protocol_end_i + protocol_end.size();
    const size_t port_i = url_s.find(':', host_i);

    host = get_substring(url_s, host_i, port_i);

    if (host.empty()) {
        throw invalid_argument("Missing HTTP host address");
    }
    transform(host.begin(), host.end(), host.begin(), ::tolower);
    if (port_i != string::npos) {
        const string port_s = get_substring(url_s, port_i + 1, url_s.length());
        try {
            port = static_cast<uint16_t>(stoi(port_s));
        } catch (exception &e) {
            BOOST_LOG_TRIVIAL(fatal) << "Failed to parse the port";
            BOOST_LOG_TRIVIAL(fatal) << e.what();
            throw invalid_argument(e.what());
        }
    }
}

string aws::iot::securedtunneling::url::url_decode(const string &url_s) {
    {
        string out;
        out.clear();
        out.reserve(url_s.size());
        for (std::size_t i = 0; i < url_s.size(); ++i) {
            if (url_s[i] == '%') {
                if (i + 3 <= url_s.size()) {
                    int value = 0;
                    std::istringstream is(url_s.substr(i + 1, 2));
                    if (is >> std::hex >> value) {
                        out += static_cast<char>(value);
                        i += 2;
                    } else {
                        throw invalid_argument("Invalid Hex number");
                    }
                } else {
                    throw invalid_argument("Invalid URL token");
                }
            }
            else if (url_s[i] == '+') {
                out += ' ';
            } else {
                out += url_s[i];
            }
        }
        return out;
    }
}