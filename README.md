## AWS IoT Secure Tunneling Local Proxy Reference Implementation C++

Example C++ implementation of a local proxy for the AWS IoT Secure Tunneling service

## License

This library is licensed under the Apache 2.0 License.

## Overview

This code enables tunneling of a single threaded TCP client / server socket interaction through the IoT Secure Tunneling service. The code is targeted to run on Linux, Windows (7+), and macOS. If your device does not meet these requirements it is still possible to implement the underlying protocol documented in the protocol guide.

---

## Building the local proxy

### Prerequisites

* C++ 14 compiler
* CMake 3.6+
* Development libraries required:
    * Boost 1.68 or 1.69
    * Protobuf 3.6.x
    * zlib
    * OpenSSL 1.0+
    * Catch2 test framework
* Stage a dependency build directory and change directory into it:
    * `mkdir dependencies`
    * `cd dependencies`
* The next steps should start from this directory, and return back to it

#### 1. Download and install Zlib dependency

Note: This step may be simpler to complete via a native software application manager.

Ubuntu example:
`sudo apt install zlibc`

Fedora example:
`dnf install zlib`

    wget https://www.zlib.net/zlib-1.2.11.tar.gz -O /tmp/zlib-1.2.11.tar.gz
    tar xzvf /tmp/zlib-1.2.11.tar.gz
    cd zlib-1.2.11
    ./configure
    make
    sudo make install

#### 2. Download and install Boost dependency

    wget https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz -O /tmp/boost.tar.gz
    tar xzvf /tmp/boost.tar.gz
    cd boost_1_69_0
    ./bootstrap.sh
    sudo ./b2 install

#### 3. Download and install Protobuf dependency

    wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protobuf-all-3.6.1.tar.gz -O /tmp/protobuf-all-3.6.1.tar.gz
    tar xzvf /tmp/protobuf-all-3.6.1.tar.gz
    cd protobuf-3.6.1
    mkdir build
    cd build
    cmake ../cmake
    make
    sudo make install

#### 4. Download and install OpenSSL development libraries

We strongly recommend installing OpenSSL development libraries using your native platform package manager so the local proxy's integration with OpenSSL can use the platform's globally configured root CAs.

Ubuntu example:
`sudo apt install libssl-dev`

Fedora example:
`dnf install openssl-devel`

Source install example:

    git clone https://github.com/openssl/openssl.git
    cd openssl
    git checkout OpenSSL_1_1_1-stable
    ./Configure linux-generic64
    make depend
    make all

Run the ./Configure command without any arguments to check the available platform configuration options and the documentation here: https://wiki.openssl.org/index.php/Compilation_and_Installation

#### 5. Download and install Catch2 test framework

    git clone https://github.com/catchorg/Catch2.git
    cd Catch2
    mkdir build
    cd build
    cmake ../
    make
    sudo make install

### Download and build the local proxy

    git clone https://github.com/aws-samples/aws-iot-securetunneling-localproxy
    cd aws-iot-securetunneling-localproxy
    mkdir build
    cd build
    cmake ../
    make

On successful build, there will be two binary executables located at 'bin/localproxy' and 'bin/localproxytest'. You may choose to run localproxytest to ensure your platform is working properly. From here on, copy or distribute the _localproxy_ binary as you please. The same source code is used for both source mode and destination mode. Different binaries may be built if the source and destinations are on different platforms and/or architectures.

#### Harden your toolchain

We recommend configuring your compiler to enable all security features relevant to your platform and use cases. For additional information about security-relevant compiler flags, see: https://www.owasp.org/index.php/C-Based_Toolchain_Hardening

#### Cross-compilation

CMake cross-compilation can be accomplished using the following general steps:
1. Acquire cross-compiler toolchain for your target platform
1. Create and configure system root (sysroot) for your target platform
1. Build and install dependencies into the sysroot of the target platform
    1. Consult each dependency's documentation for guidance on how to cross compile
1. Build the local proxy
1. Run the test executable (also built for your platform)

CMake can perform cross-compilation builds when it is given a toolchain file. Here is an example filename: `raspberry_pi_3_b_plus.cmake.tc`

```
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_SYSROOT /home/fedora/cross_builds/sysroots/arm-unknown-linux-gnueabihf)

set(tools /home/fedora/x-tools/arm-unknown-linux-gnueabihf)
set(CMAKE_C_COMPILER ${tools}/bin/arm-unknown-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER ${tools}/bin/arm-unknown-linux-gnueabihf-g++)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
```

To perform the cross-compilation build files run `cmake ../ -DCMAKE_TOOLCHAIN_FILE=raspberry_pi_3_b_plus.cmake.tc && make` from a build directory.

Helpful links:

* https://crosstool-ng.github.io/ - crosstool-NG makes it convenient to build a toolchain, acquire and configure a system root
* https://wiki.osdev.org/Target_Triplet - Consult this to understand your platform triplet

---

## Running the local proxy:

The response of OpenTunnel via the AWS IoT Secure Tunneling management API is acquisition of a pair of client access tokens to use to connect two local proxy clients to the ends of the tunnel. One token is designated for the source local proxy, and the other is for the destination. They must be supplied with the matching local proxy run mode argument, otherwise connecting to the service will fail. Additionally, the region parameter supplied to the local proxy must match the AWS region the tunnel was opened in. In a production configuration, delivery of one or both tokens and launching the local proxy process may be automated. The following sections describe how to run the local proxy on both ends of a tunnel.

### Destination service and destination mode local proxy

Running the local proxy in destination mode makes it behave like a single TCP client with respect to a listening application that is reachable from the local device. In addition to the client access token, destination mode requires specifying the address and port that must be connected to when an incoming connection request is received over the tunnel. This is an example command to run the local proxy in destination mode, on a tunnel created in us-east-1, and forward incoming requests to a locally running application or service on port 3389.

    ./localproxy -r us-east-1 -d localhost:3389 -t <destination_client_access_token>

We recommend starting the destination application or server before starting the destination local proxy to ensure that when the local proxy attempts to connect to the destination port, it will succeed. When the local proxy starts in destination mode, it will first connect to the service, and then begin listening for a new connection request over the tunnel. Upon receiving a request, it will attempt to connect to the configured destination address and port. If successful, it will transmit data between the TCP connection and tunnel bi-directionally. Destination mode can only manage one connection at a time, so if a new connection request is received over the tunnel while a connection is already established, it will close the current TCP connection and establishes a new one.

### Client application and source mode local proxy

Running the local proxy in source mode makes it behave like a single connection TCP server, waiting for a TCP client to connect and then relaying data over that connection through the tunnel. In addition to the client access token, source mode requires choosing an available port for the local proxy to listen to.

This is an example command to run the local proxy in source mode, on a tunnel created in us-east-1, waiting for a connection on port 3389:

    ./localproxy -r us-east-1 -s 3389 -t <source_client_access_token>

When the local proxy starts in source mode, it will first connect to the service, and then begin listening for a new connection on the specified local port and bind address. While the local proxy is running, use the client application (e.g. RemoteDesktopClient, ssh client) to connect to the source local proxy's listening port. After accepting the TCP connection, the local proxy will forward the connection request over the tunnel and immediately transmit data the TCP connection data through the tunnel bidirectionally. Source mode will only accept and manage one connection at a time. If the established TCP connection is terminated for any reason, it will send a disconnect message over the tunnel so the service or server running on the other side can react appropriately. Similarly, if a notification that a disconnect happened on the other side is received by the source local proxy it will close the local TCP connection. Regardless of a local I/O failures, or if a notification of a disconnect comes from the tunnel, after the local TCP connection closes, it will begin listening again on the specified listen port and bind address.

* If a new connection request sent over the tunnel results in the remote (destination) side being unable to connect to a destination service, it will send a disconnect message back through the tunnel. The exact timing behavior of this depends on the TCP retry settings of the destination local proxy.

### Stopping the local proxy process

The local proxy process can be stopped using various methods:
* Sending a SIGTERM signal to the process
* Closing a tunnel explicitly via CloseTunnel API. This will result in the local proxy dropping the connection to the service and existing the process successfully.
* A tunnel expires after its lifetime expiry. This will result in the local proxy dropping the connection to the service and exiting the process successfully. 

### Security Considerations

#### Certificate setup

A likely issue with the local proxy running on Windows or macOS systems is the lack of native OpenSSL support and default configuration. This will prevent the local proxy from being able to properly perform TLS/SSL host verification with the service. To fix this, set up a certificate authority (CA) directory and direct the local proxy to use it via the `--capath <dir>` CLI argument:

1. Create a new folder or directory to store the root certificates that the local proxy can access. For example: D:\certs on Windows
1. Download Amazon CA certificates for server authentication from here: https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs
1. Utilize the 'c_rehash' script for Windows or 'openssl rehash' command for macOS. This script is part of the OpenSSL development toolset
 * macOS: `openssl rehash ./certs`
 * Windows example:
```
D:\lib\openssl>set OPENSSL=D:\lib\openssl\apps\openssl.exe

D:\lib\openssl>tools\c_rehash.pl D:\certs
Doing D:\certs
```
Note: c_rehash.pl script on Windows does not seem to cooperate with spaces in the path for the openssl.exe executable

After preparing this directory, point to it when running the local proxy with the -c [arg] option. Examples:
    * MacOSX: `./localproxy -r us-east-1 -s 3389 -c ./certs`
    * Windows: `.\localproxy.exe -r us-east-1 -s 3389 -c D:\certs`

#### Runtime environment 

* Avoid using the **-t** argument to pass in the access token. We recommend setting the **AWSIOT_TUNNEL_ACCESS_TOKEN** environment variable to specify the client access token with least visibility
* Run the local proxy executable with least privileges in the OS or environment
    * 
    * If your client application normally connects to a port less than 1024, this would normally require running the local proxy with admin privileges to listen on the same port. This can be avoided if the client application allows you to override the port to connect to. Choose any available port greater than 1024 for the source local proxy to listen to without administrator access. Then you may direct the client application to connect to that port. e.g. For connecting to a source local proxy with an SSH client, the local proxy can be run with `-s 5000` and the SSH client should be run with `-p 5000`
* On devices with multiple network interfaces, use the **-b** argument to bind the TCP socket to a specific network address restricting the local proxy to only proxy connections on an intended network
* Consider running the local proxy on separate hosts, containers, sandboxes, chroot jail, or a virtualized environment

### IPv6 support

The local proxy uses IPv4 and IPv6 dynamically based on how addresses are specified directly by the user, or how are they resolved on the system. For example, if 'localhost' resolves to '127.0.0.1' then IPv4 will is being used to connect or as the listening address. If localhost resolves to '::1' then IPv6 will be used.

**Note:** Specifying any argument that normally accepts _address:port_ will not work correctly if _address_ is specified using an IPv6 address.

**Note:** Systems that support both IPv4 and IPv6 may cause connectivity confusion if explicit address/port combinations are not used with the local proxy, client application, or destination service. Each component may behave differently with respect to support IP stack and default behaviors. Listening on the local IPv4 interface _127.0.0.1_ will not accept connection attempts to IPv6 loopback address _::1_. To add further complexity, hostname resolution may hide that this is happening, and different tools may prefer different IP stacks. To help with this from the local proxy, use verbose logging on the local proxy _(-v 6 CLI argument)_ to inspect how hostname resolution is happening and examine the address format being output.

### Options set via command line arguments

Most command line arguments have both a long form preceded by a double dash -- and a short form preceded by a single dash - character. Some commands only have a long form. Any options specified via command line arguments override values specified in both the config file specification, and environment variables.

**-h/--help**
Will show a help message and a short guide to all of the available CLI arguments to the console and cause it to exit immediately

**-t/--access-token [argvalue]**
Specifies the client access token to use when connecting to the service. We do not recommend using this option as the client access token will appear in shell history or in process listings that show full commands and arguments and may unintentionally expose access to the tunnel. Use the environment variable or set the option via config input file instead. An access token value must be found supplied via one of those three methods.

**-e/--proxy-endpoint [argvalue]**
Specifies an explicit endpoint to use to connect to the tunneling service. For some customers this may point to unique domain. You cannot specify this option and **-r/--region** together. Either this or **--region** is required

**-r/--region [argvalue]**
Endpoint region where tunnel exists. You cannot specify this option and **-e/--process-endpoint** together. Either this or **--proxy-endpoint** is required

**-s/--source-listen-port [argvalue]**
Directs the local proxy to run in source mode, and listen on the specified port for incoming connections. Either this or **--destination-app** is required

**-d/--destination-app [argvalue]**
Directs the local proxy to run in destination mode, and connect to the specified address which may be specified as _address:port_ or just _port_. Address may be specified an IPv4 address or hostname. Either this or **--source-listen-port** is required.

**-b/--local-bind-address [argvalue]**
Specifies the local bind address (network interface) to use for listening for new connections when running the local proxy in source mode, or the local bind address to use when reaching out to the destination service when running in destination mode

**-c/--capath [argvalue]**
Specifies an additional directory path that contains root CAs used for SSL certificate verification when connecting to the service

**-k/--no-ssl-host-verify**
Directs the local proxy to disable host verification when connecting to the service. This option should not be used in production configurations.

**--export-default-settings [argvalue]**
Specifies a file to write out all of the default fine-grained settings used by the local proxy and exits immediately. This file can be modified, and supplied as input to **--settings-json** to run the local proxy with non-default fine-grained settings.

**--settings-json [argvalue]**
Specifies a file to read fine-grained settings for the local proxy to use to override hard coded defaults. All of the settings need not be present. Settings that do not exist are ignored passively.

**--config [argvalue]**
Specifies a file to read command line arguments from. Actual command line arguments will overwrite contents of file if present in both.

**-v/--verbose [argvalue]**
Specifies the verbosity of the output. Value must be between 0-255, however meaningful values are between 0-6 where 0 = output off, 1 = fatal, 2 = error, 3 = warning, 4 = info [default], 5 = debug, 6 = trace. Any values greater than 6 will be treated the same trace level output.

### Options set via --config

A configuration file can be used to specify any or all of the CLI arguments. If an option is set via a config file and CLI argument, the CLI argument value overrides. Here is an example file named `config.ini`:

    region = us-east-1
    access-token = foobar
    source-listen-port = 5000

Local proxy run command using this configuration: `./localproxy --config config.ini` is equivalent to running the local proxy command `./localproxy -r us-east-1 -t foobar -s 5000`

To illustrate composition between using a configuration file and actual CLI arguments you could have a `config.ini` file with the following contents:

    capath = /opt/rootca
    region = us-west-2
    local-bind-address = ::1
    source-listen-port = 6000

and a local proxy launch command `./localproxy --config config.ini -t foobar` is equivalent to running the local proxy command `./localproxy -c /opt/rootca -r us-west-2 -b ::1 -s 6000 -t foobar`

### Options set via environment variables

There are a few environment variables that can set configuration options used by the local proxy. Environment variables have lowest priority in specifying options. Config and CLI arguments will always override them

* **AWSIOT_TUNNEL_ACCESS_TOKEN** - if present, specifies the access token for the local proxy to use
* **AWSIOT_TUNNEL_ENDPOINT** - if present, specifies the AWS IoT Secured Tunneling proxy endpoint. Leave out -e or --proxy-endpoint from CLI arg. Still mutually exclusive with specifying -r/--region and below environment variable
* **AWSIOT_TUNNEL_REGION** - if present, specifies the region the tunnel exists in. Allowing leaving out the -r CLI arg

### Fine-grained settings via --settings-json

There are additional fine-grained settings to control the behavior of the local proxy. These settings are unlikely to need to be changed, and unless necessary should be kept at their default values.

Running `./localproxy --export-default-settings lpsettings.json` will produce a file named `lpsettings.json` containing the default values for all settings. Example contents:

```
{
    "tunneling": {
        "proxy": {
            "default_bind_address": "localhost",
            "message": {
                "data_length_size": "2",
                "max_payload_size": "64512",
                "max_size": "65536"
            },
            "tcp": {
                "connection_retry_count": "5",
                "connection_retry_delay_ms": "1000",
                "read_buffer_size": "131076"
            },
            "websocket": {
                "ping_period_ms": "5000",
                "retry_delay_ms": "2500",
                "connect_retry_count": "-1",
                "reconnect_on_data_error": "true",
                "subprotocol": "aws.iot.securetunneling-1.0",
                "max_frame_size": "131076",
                "write_buffer_size": "131076",
                "read_buffer_size": "131076"
            }
        }
    }
}
```

After making edits to `lpsettings.json` and saving the changes, the following command will run the local proxy with the modified settings: `./localproxy -r us-east-1 -t foobar -d localhost:22 --settings-json lpsettings.json`.

**default_bind_address**
Defines the default bind address used when the **-b** bind address command line argument or option is not present. Address may be a hostname or IP address

**tunneling.proxy.tcp.connection_retry_count**
When a failure occurs while trying to establish a TCP connection in destination mode this is the number of consecutive connection attempts to make before sending a notification over the tunnel that the connection is closed. When running in source mode, this will be the number of consecutive attempts made to bind and listen on on the TCP socket. A value of -1 results in infinite retry

**tunneling.proxy.tcp.connection_retry_delay_ms**
Defines how long to wait before executing a retry for TCP connection failures (source or destination mode) in milliseconds.

**tunneling.proxy.websocket.ping_period_ms**
Defines the period (in milliseconds) between websocket pings to the AWS IoT Tunneling Service. These pings may be necessary to keep the connection alive.

**tunneling.proxy.websocket.connect_retry_count**
When a failure occurs while trying to connect to the service outside of an HTTP 4xx response on the handshake it may be retried based on the value of this property. This is the number of consecutive attempts to make before failing and closing the local proxy. Any HTTP 4xx response code on handshake does not retry. A value of -1 results in infinite retry

**tunneling.proxy.websocket.retry_delay_ms**
Defines how long to wait before executing another retry to connect to the service in milliseconds.

**tunneling.proxy.websocket.reconnect_on_data_error**
Flag indicating whether or not to try to restablish connection to the service if an I/O, protocol handling, or message parsing errors occur.

**tunneling.proxy.message.may_payload_size**
Defines the maximum data size allowed to be carried via a single tunnel message. The current protocol has a maximum value of 63kb (64512 bytes). Any two active peers communicating over the same tunnel must set this to the same value.

### Building local proxy on a windows
Follow instructions in [here](windows-localproxy-build.md) to build a local proxy on a windows environment.
