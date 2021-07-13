// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch.hpp>
#include <iostream>
#include <map>

#include <Url.h>
using namespace std;
namespace aws {
    namespace iot {
        namespace securedtunneling {
            namespace test {
                TEST_CASE("Unit tests for Url.h-happy-cases"){
                    cout << "Unit test happy cases for Url.h" << endl;
                    const int n = 4;
                    const vector<string> protocols{"https", "http", "tcp", "http"};
                    const vector<string> authNs{"", "user:12345", "user:F%40o%3Ao%21B%23ar+%24", "user:password", "%40fasdbla:12345"};
                    const vector<string> authNs_decoded{"", "user:12345", "user:F@o:o!B#ar $", "user:password", "@fasdbla:12345"};
                    const vector<string> hosts(n, "server.com");
                    const vector<uint16_t> ports{0, 90, 109, 3129, 30000};
                    for (int i = 0; i < n; ++i) {
                        const string https_proxy = protocols.at(i) + "://" + (authNs.at(i).empty() ? "" : authNs.at(i) + "@")
                                + hosts.at(i) + ":" + to_string(ports.at(i));
                        aws::iot::securedtunneling::url url{https_proxy};
                        REQUIRE(url.protocol == protocols.at(i));
                        REQUIRE(url.host == hosts.at(i));
                        REQUIRE(url.port == ports.at(i));
                        REQUIRE(url.authentication == authNs_decoded.at(i));
                    }
                }

                TEST_CASE("Unit tests for Url-invalid-urls"){
                    cout << "Unit test invalid URLs for Url.h" << endl;
                    const vector<string> invalid_urls{
                        "://server.com",
                        "tcp://:3128",
                        "http://@server.com:3128",
                        "http://:@server.com:3128",
                        "http://:1@server.com:3128",
                        "http://1:@server.com:3128",
                        "http://server.com:abs"
                    };
                    for (auto invalid_url : invalid_urls) {
                        REQUIRE_THROWS_AS([&]() {
                            iot::securedtunneling::url url{invalid_url};
                        }(), invalid_argument);
                    }
                }

                TEST_CASE("Unit tests for url_decode-happy case"){
                    cout << "Unit tests for url_decode-happy case" << endl;
                    const map<string, string> url_encoded_lookup {
                            {"F%40o%3Ao%21B%23ar+%24", "F@o:o!B#ar $"},
                            {"%40fasdbla", "@fasdbla"},
                            {"%24%20%26%20%3C%20%3E%20%3F%20%3B%20%23%20%3A%20%3D%20%2C%20%22%20%27%20~%20%2B%20%25", "$ & < > ? ; # : = , \" ' ~ + %"}
                    };
                    for (const auto& kv : url_encoded_lookup) {
                        REQUIRE(url::url_decode(kv.first) == kv.second);
                    }
                }

                TEST_CASE("Unit tests for url_decode-invalid case"){
                    cout << "Unit tests for url_decode-invalid case" << endl;
                    const vector<string> invalid_url_codes {
                        "%%",
                        "%",
                        "%gh",
                        "%h1",
                        "%x2",
                        "121fad%1"
                    };
                    for (const auto& invalid_url_code : invalid_url_codes) {
                        REQUIRE_THROWS_AS([&](){
                            cout << url::url_decode(invalid_url_code) << endl;
                        }(), invalid_argument);
                    }
                }
            }
        }
    }
}