// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
namespace aws {
    namespace iot {
        namespace securedtunneling {
            class url {
            private:
                void parse(const std::string& url_s);
            public:
                url(const std::string& url_s);
                std::string protocol, host, authentication;
                uint16_t port {0};
                static std::string url_decode(const std::string& url_s);
            };
        }
    }
}
