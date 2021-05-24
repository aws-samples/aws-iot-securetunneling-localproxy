#!/bin/bash

architecture=$(uname -m)

if [ "${architecture}" != aarch64 -a "${architecture}" != arm64 ]; then
	openssl_config=linux-generic64
else
	openssl_config=linux-aarch64
fi

echo Architecture: $architecture
echo OpenSSL configurations: $openssl_config
docker build --build-arg OPENSSL_CONFIG=$openssl_config -t aws-iot-securetunneling-localproxy:latest .
