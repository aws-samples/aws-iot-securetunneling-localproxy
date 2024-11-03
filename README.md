## As of 3.1.2 May 2024 Update, `--destination-client-type V1` will be a required parameter when connecting with the following:
- AWS IoT Device Client
- AWS IoT Secure Tunneling Component
- Browser-based Secure Tunneling from the AWS Console
- any Secure Tunneling demo code written before 2022
- 1.x versions of the localproxy

# AWS IoT Secure Tunneling Local Proxy Reference Implementation C++

Example C++ implementation of a local proxy for the AWS IoT Secure Tunneling service

## License

This library is licensed under the Apache 2.0 License.

## Overview

This code enables tunneling of a single threaded TCP client / server socket interaction through the IoT Secure Tunneling service. The code is targeted to run on Linux, Windows (7+), and macOS. If your device does not meet these requirements it is still possible to implement the underlying protocol documented in the protocol guide.

---

## Quick Start for x86 Linux platforms

Install Docker https://docs.docker.com/get-started/get-docker/
`docker run --rm -it --network=host public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:amd64-latest`, then populate the missing required parameters.

## Building the local proxy via Docker

### Prerequisites

* Docker 18+

### Using Pre-built Docker Images

We provide several docker images on various platforms. Both x86 and ARM are supported, though armv7 is currently limited to the ubuntu images.
There are two types of images: base images and release images.
The base images come with all dependencies pre-installed. You will still need to download and build the source. These images are tagged with their corresponding arch.
These are useful if you want to modify and [compile](https://github.com/aws-samples/aws-iot-securetunneling-localproxy#download-and-build-the-local-proxy) the local proxy on your own, but are large (~1 GB each).
You can find them at:
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-base
- amd64/arm64/armv7
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/debian-base
- amd64/arm64
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/amazonlinux-base
- amd64/arm64
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/ubi8-base
- amd64/arm64
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/fedora-base
- amd64

The release images are minimum size images that include a pre-built binary with only the necessary shared libs installed. To use the release images, simply pass the localproxy CLI args into the docker run command. Example:

`docker run --rm -it --network=host public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:amd64-latest --region us-east-1 -s 5555 -t <ACCESS_TOKEN>`

On MacOS, --network=host does not work the way you expect it would. instead, do `docker run --rm -it -p 5555:5555 public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:amd64-latest --region us-east-1 -b 0.0.0.0 -s 5555 -t <ACCESS_TOKEN>`

This will automatically pull down the latest docker image and run the localproxy without having to manually install it on your system.
These images are tagged with the git commit and corresponding arch. Example: 33879dd7f1500f7b3e56e48ce8b002cd9b0f9e4e-amd64.
You can cross-check the git commit sha with the commits in the local proxy repo to see if the binary contains changes added in a specific commit.
The release images can be found at:
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin
- amd64/arm64/armv7
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/debian-bin
- amd64/arm64
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/amazonlinux-bin
- amd64/arm64
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/ubi8-bin
- amd64/arm64
#### https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/fedora-bin
- amd64

### Building a Docker Image

If you do not want to use the prebuilt images, you can build them yourself:

`cd .github/docker-images/base-images/<os of choice>`

`docker build -t <your tag> .`

Or, for the debian-ubuntu combined Dockerfile:

`docker build -t <your tag> . --build-arg OS=<choice of debian/ubuntu>:<platform>`

To build cross-platform images for ARM:

`docker buildx --platform linux/arm64 -t <your tag> .`

You may also try armv7 for 32 bit images, but supported functionality may be limited.

After the Docker build completes, run `docker run --rm -it <tag>` to open a shell inside the container created in the
previous step...

Because it may not make practical sense to SSH into a docker container, you can transfer binaries by exposing your machine's filesystem to the containerized filesystem via bind mount. To bind mount a volume on your physical machine's current directory: 
`docker run --rm -it -v $(pwd):/root <tag>`
and you can add ` -p <port_number>` to expose a port from the docker container. Note that when the localproxy runs in source mode, it binds by default to `localhost`, If you want to access the localproxy from outside the container, make sure to use the option `-b 0.0.0.0` when you run the localproxy from the container so that it binds to `0.0.0.0` since `localhost` can not be access from outside the container.

#### Deprecated Method
`./docker-build.sh`

---

## Building the local proxy from source

### Prerequisites

* Minimum System Requirements: >8GB of disk space and >1GB of RAM. We recommended building elsewhere and importing the binary if your device does not meet these requirements.
* C++ 14 compiler
* CMake 3.6+
* Development libraries required:
    * Boost 1.81
    * Protobuf 3.17.x
    * zlib 1.12.13+
    * OpenSSL 1.0+ OR OpenSSL 3
    * Catch2 test framework
* Stage a dependency build directory and change directory into it:
    * `mkdir dependencies`
    * `cd dependencies`
* The next steps should start from this directory, and return back to it

#### 1. Download and install Zlib dependency

Note: This step may be simpler to complete via a native software application manager.

Ubuntu example:
`sudo apt install zlib1g`

Fedora example:
`dnf install zlib`

    wget https://www.zlib.net/zlib-1.2.13.tar.gz -O /tmp/zlib-1.2.13.tar.gz
    tar xzvf /tmp/zlib-1.2.13.tar.gz
    cd zlib-1.2.13
    ./configure
    make
    sudo make install

#### 2. Download and install Boost dependency

    wget https://boostorg.jfrog.io/artifactory/main/release/1.81.0/source/boost_1_81_0.tar.gz -O /tmp/boost.tar.gz
    tar xzvf /tmp/boost.tar.gz
    cd boost_1_81_0
    ./bootstrap.sh
    sudo ./b2 install link=static

If you want to install an older version of boost, pass the version string through the cmake variable when compiling the local proxy: `-DBOOST_PKG_VERSION`
#### 3. Download and install Protobuf dependency

    wget https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protobuf-all-3.17.3.tar.gz -O /tmp/protobuf-all-3.17.3.tar.gz
    tar xzvf /tmp/protobuf-all-3.17.3.tar.gz
    cd protobuf-3.17.3
    mkdir build
    cd build
    cmake ../cmake
    make
    sudo make install

If you want to install an older version of protobuf, pass the version string through the cmake variable when compiling the local proxy: `-DPROTOBUF_PKG_VERSION`
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

##### Static vs. Dynamic linking OpenSSL
In the `CMakeLists.txt`, we provide a parameter -DLINK_STATIC_OPENSSL which by default is set to ON. You may link against shared libraries on your system by setting the value to OFF. Choosing to do so is completely optional depending on your own operational requirements. This is following guidance from https://github.com/aws-samples/aws-iot-securetunneling-localproxy/pull/145.

#### 5. Download and install Catch2 test framework

    git clone --branch v3.7.0 https://github.com/catchorg/Catch2.git
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

### Terms 

V1 local proxy: local proxy uses Sec-WebSocket-Protocol _aws.iot.securetunneling-1.0_ when communicates with AWS IoT Tunneling Service.

V2 local proxy: local proxy uses Sec-WebSocket-Protocol _aws.iot.securetunneling-2.0_ when communicates with AWS IoT Tunneling Service.

V3 local proxy: local proxy uses Sec-WebSocket-Protocol _aws.iot.securetunneling-3.0_ when communicates with AWS IoT Tunneling Service.

Source local proxy: local proxy that runs in source mode.

Destination local proxy:  local proxy that runs in destination mode.

### Multi-port tunneling feature support
Multi-port tunneling feature allows more than one stream multiplexed on same tunnel. 
This feature is only supported with V2 local proxy. If you have some devices that on V1 local proxy, some on V2 local proxy, simply upgrade the local proxy on the source device to V2 local proxy. When V2 local proxy talks to V1 local proxy, the backward compatibility is maintained. For more details, please refer to section [backward compatibility](#backward-compatibility)

### Simultaneous TCP connections feature support
Simultaneous TCP is a feature that allows application layer (e.g. HTTP) protocols to open multiple TCP connections over a single stream.
This feature is only supported with V3 local proxy. If you have some devices that on V1/V2 local proxy, some on V3 local proxy, simply upgrade the local proxy on the source device to V3 local proxy. When V3 local proxy talks to V1/V2 local proxy, the backward compatibility is maintained as long as users specify `V1` or `V2` as the value for `destination-client-type`. For more details, please refer to section [backward compatibility](#backward-compatibility)

### Service identifier (Service ID)
If you need to use multi-port tunneling feature, service ID is needed to start local proxy. A service identifier will be used as the new format to specify the source listening port or destination service when start local proxy. The identifier is like an alias for the source listening port or destination service. For the format requirement of service ID, please refer to AWS public doc [services in DestinationConfig ](https://docs.aws.amazon.com/iot/latest/apireference/API_iot-secure-tunneling_DestinationConfig.html). There is no restriction on how this service ID should be named, as long as it can help uniquely identifying a connection or stream. 

Example 1: _SSH1_

You can use the following format: protocol name + connection number. 
For example, if two SSH connections needed to be multiplexed over a tunnel , you can choose SSH1 and SSH2 as the service IDs.

Example 2: _ae5957ef-d6e3-42a5-ba0c-edc667d2b3fb_

You can use a UUID to uniquely identify a connection/stream.

Example 3: _ip-172-31-6-23.us-west-2.compute.internal_

You can use remote host name to uniquely identify a stream.

### Destination service and destination mode local proxy
Destination local proxy is responsible for forwarding application data received from tunnel to destination service. For V1 local proxy, only 1 stream is allowed over the tunnel. With V2 local proxy, more than one streams can be transferred at the same time. For more details, please read section [**Multi-port tunneling feature support**](#multi-port-tunneling-feature-support). 

Example 1:

    ./localproxy -r us-east-1 -d localhost:3389 -t <destination_client_access_token>
This is an example command to run the local proxy in destination mode, on a tunnel created in us-east-1, and forward data packets received from the tunnel to a locally running application/service on port 3389.

Example 2:

    ./localproxy -r us-east-1 -d HTTP1=80,SSH1=22 -t <destination_client_access_token>
This is an example command to run the local proxy in destination mode, on a tunnel created in us-east-1, and forward:
- data packets belongs to service ID HTTP1 to a locally running application/service on port 80.
- data packets belongs to service ID SSH1 to a locally running application/service on port 22.

We recommend starting the destination application or server before starting the destination local proxy to ensure that when the local proxy attempts to connect to the destination port, it will succeed. When the local proxy starts in destination mode, it will first connect to the service, and then begin listening for a new connection request over the tunnel. Upon receiving a request, it will attempt to connect to the configured destination address and port. If successful, it will transmit data between the TCP connection and tunnel bi-directionally. 

For a multiplexed tunnel, one connection drop or connect will not affect the other connections that share the same tunnel. All connections/streams in a multiplexed tunnel is independent.   


### Client application and source mode local proxy
Source local proxy is responsible for relaying application data to the tunnel. For V1 local proxy, only 1 stream is allowed over the tunnel. With V2 local proxy, more than one streams can be transferred at the same time. For more details, please read section [**Multi-port tunneling feature support**](#multi-port-tunneling-feature-support). 

Example 1:

    ./localproxy -r us-east-1 -s 3389 -t <source_client_access_token>
    
This is an example command to run the local proxy in source mode, on a tunnel created in us-east-1, waiting for a connection on port 3389.

Example 2:

    ./localproxy -r us-east-1 -s HTTP1=5555,SSH1=3333 -t <source_client_access_token>
  
This is an example command to run the local proxy in source mode, on a tunnel created in us-east-1,
 - waiting for a connection on port 5555, for service ID HTTP1.
 - waiting for a connection on port 3333, for service ID SSH1. 

When the local proxy starts in source mode, it will first connect to the service, and then begin listening for a new connection on the specified port and bind address. While the local proxy is running, use the client application (e.g. RemoteDesktopClient, ssh client) to connect to the source local proxy's listening port. After accepting the TCP connection, the local proxy will forward the connection request over the tunnel and immediately transmit data the TCP connection data through the tunnel bidirectionally. Source mode can manage more than one connection/stream at a time, if V2 local proxy is used. If the established TCP connection is terminated for any reason, it will send a disconnect message over the tunnel so the service or server running on the other side can react appropriately. Similarly, if a notification that a disconnect happened on the other side is received by the source local proxy it will close the local TCP connection. Regardless of a local I/O failures, or if a notification of a disconnect comes from the tunnel, after the local TCP connection closes, it will begin listening again on the specified listen port and bind address.

* If a new connection request sent over the tunnel results in the remote (destination) side being unable to connect to a destination service, it will send a disconnect message back through the tunnel. The exact timing behavior of this depends on the TCP retry settings of the destination local proxy.
* For a multiplexed tunnel, one connection drop or connect will not affect the other connections that share the same tunnel. All connections/streams in a multiplexed tunnel is independent. 

### Stopping the local proxy process

The local proxy process can be stopped using various methods: 
* Sending a SIGTERM signal to the process
* Closing a tunnel explicitly via CloseTunnel API. This will result in the local proxy dropping the connection to the service and existing the process successfully.
* A tunnel expires after its lifetime expiry. This will result in the local proxy dropping the connection to the service and exiting the process successfully. 

### Backward compatibility
V2 local proxy is able to communicate with V1 local proxy if only one connection needs to be established over the tunnel. This means when you open a tunnel,  no more than one service should be passed in the **services** list.

Example 1: 

     aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH1,SSH2
In this example, two service IDs are used (SSH1 and SSH2). Backward compatibility is NOT supported.

Example 2:  
   
    aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH2

In this example, one service ID is used (SSH2). Backward compatibility is supported.

Example 3: 

    aws iotsecuretunneling open-tunnel 

In this example, no service ID is used. Backward compatibility is supported.

V3 local proxy is able to communicate with V1 and V2 local proxy if only one connection/stream needs to be established over the tunnel. When connecting to older versions, you will need to pass the `destination-client-type` CLI arg if and only if starting the localproxy in source mode. The same rules listed above still apply when connecting over V1.

Example when targeting a V1 destination, like Device Client of the Greengrass Secure Tunneling Component: 

    ./localproxy -s 3333 --destination-client-type V1 -v 6 -r us-east-1

Example when targeting a V2 destination:
   
    ./localproxy -s 3333 --destination-client-type V2 -v 6 -r us-east-1

### HTTP proxy Support

The local proxy relies on the HTTP tunneling mechanism described by the [HTTP/1.1 specification](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.6). To comply with the specifications, your web proxy must allow devices to use the CONNECT method. For more details on how that works and how configure it properly, Please refer to "[Configure local proxy for devices that use web proxy](https://docs.aws.amazon.com/iot/latest/developerguide/configure-local-proxy-web-proxy.html)"

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

* Avoid using the **-t** argument to pass in the access token. We recommend setting the **AWSIOT_TUNNEL_ACCESS_TOKEN** environment variable to specify the client access token with the least visibility
* Run the local proxy executable with the least privileges in the OS or environment
    * If your client application normally connects to a port less than 1024, this would normally require running the local proxy with admin privileges to listen on the same port. This can be avoided if the client application allows you to override the port to connect to. Choose any available port greater than 1024 for the source local proxy to listen to without administrator access. Then you may direct the client application to connect to that port. e.g. For connecting to a source local proxy with an SSH client, the local proxy can be run with `-s 5000` and the SSH client should be run with `-p 5000`
* On devices with multiple network interfaces, use the **-b** argument to bind the TCP socket to a specific network address restricting the local proxy to only proxy connections on an intended network
* Consider running the local proxy on separate hosts, containers, sandboxes, chroot jail, or a virtualized environment

#### Access tokens
* After localproxy uses an access token, it will no longer be valid without an accompanying Client Token.
* You can revoke an existing token and get a new valid token by calling [RotateTunnelAccessToken](https://docs.aws.amazon.com/iot/latest/apireference/API_iot-secure-tunneling_RotateTunnelAccessToken.html).
* Refer to the [Developer Guide](https://docs.aws.amazon.com/iot/latest/developerguide/iot-secure-tunneling-troubleshooting.html) for troubleshooting connectivity issues that can be due to an invalid token.

#### Client Tokens
* The client token is an added security layer to protect the tunnel by ensuring that only the agent that generated the client token can use a particular access token to connect to a tunnel. 
* Only one client token value may be present in the request. Supplying multiple values will cause the handshake to fail.
* The client token is optional.
* The client token must be unique across all the open tunnels per AWS account
* It's recommended to use a UUID to generate the client token.
* The client token can be any string that matches the regex `^[a-zA-Z0-9-]{32,128}$`
* If a client token is provided, then local proxy needs to pass the same client token for subsequent retries (This is yet to be implemented in the current version of local proxy)
* If a client token is not provided, then the access token will become invalid after a successful handshake, and localproxy won't be able to reconnect using the same access token.
* The Client Token may be passed using the **-i** argument from the command line or setting the **AWSIOT_TUNNEL_CLIENT_TOKEN** environment variable.


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
Start local proxy in source mode and sets the mappings between service identifier and listening port. For example: SSH1=5555 or 5555. 
* It follows format serviceId1=port1, serviceId2=port2, ...
* If only one port is needed to start local proxy, service identifier is not needed. You can simply pass the port to be used, for example, 5555.
* SSH1=5555 means that local proxy will start listening requests on port 5555 for service ID SSH1.
* The value of service ID and how many service IDs are used needs to match with **services** in open tunnel call. For example:
    ```shell script
    aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH1,SSH2
    ```
    Then to start local proxy in source mode, need to use: ```-s SSH1=$port1,SSH2=$port2```

**-d/--destination-app [argvalue]**
Start local proxy in destination mode and sets the mappings between port and service identifier. For example: SSH1=5555 or 5555. 
* It follows format serviceId1=endpoint1, serviceId2=endpoint2, ...
* Endpoint can be IP address:port , port or hostname:port. 
* If only one port is needed to start local proxy, service ID is not needed. You can simply pass the port used, for example, 5555.
* An item of the mapping SSH1=5555 means that local proxy will forward data received from the tunnel to TCP port 5555 for service ID SSH1. 
* The value of service ID and how many service IDs are used needs to match with **services** in open tunnel call. For example:
    ```shell script
    aws iotsecuretunneling open-tunnel --destination-config thingName=foo,services=SSH1,SSH2
    ```
    Then to start local proxy in destination mode, need to use: ```-d SSH1=$port1,SSH2=$port2```

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

**-m/--mode [argvalue]**
Specifies the mode local proxy will run. Accepted values are: src, source, dst, destination.

**-y/--destination-client-type [argvalue]**
Specifies the backward compatibility mode the local proxy will run when opening a source connection to an older destination client. Currently supported values are: V1, V2. The localproxy will assume the destination to be V3 if no/invalid value is passed.

**--config-dir [argvalue]**
Specifies the configuration directory where service identifier mappings are configured. If this parameter is not specified, local proxy will read configuration files from default directory _./config_, under the file path where `localproxy` binary are located. 

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

**NOTE**: Service ID mappings should be configured by using parameter --config-dir, not --config. 

### Options set via --config-dir

If you want to start local proxy on fixed ports, you can configure these mappings using configuration files. By default, local proxy will read from directory _./config_, under the file path where `localproxy` binary are located. If you need to direct local proxy reads from specific file path, use parameter `--config-dir` to specify the full path of the configuration directory. 
You can put multiple files in this directory or organize them into the sub folders. Local proxy will read all the files in this directory and search for the port mapping needed for a tunnel connection. 

**NOTE**: The configuration files will be read once when local proxy starts and will not be read again unless it is restarted.

#### Sample configuration files on source device
File name: _SSHSource.ini_

Content example:

    SSH1=3333
    SSH2=5555

This example means:
* Service ID SSH1 is mapped to port 3333.
* Service ID SSH2 is mapped to port 5555.

#### Sample configuration files on  destination device

Example configuration file on destination device:
File name: _SSHDestination.ini_

Content example:

    SSH1=22
    SSH2=10.0.0.1:80
    
This example means:    
* Service ID SSH1 is mapped to port 22.
* Service ID SSH2 is mapped to host with IP address 10.0.0.1, port 80.


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

### Limits for multiplexed tunnels
#### Bandwidth limits
If the tunnel multi-port feature is enabled, multiplexed tunnels have the same bandwidth limit as non-multiplexed tunnels. This limit is mentioned in [AWS public doc](https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html) section **AWS IoT Secure Tunneling**, row _Maximum bandwidth per tunnel_. The bandwidth for a multiplexed tunnel is the bandwidth consumed by all active streams that transfer data over the tunnel connection. If you need this limit increased, please reach out to AWS support and ask for a limit increase. 

#### Service ID limits 
There are limits on the maximum streams that can be multiplexed on a tunnel connection. This limit is mentioned in [AWS public doc](https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html) section **AWS IoT Secure Tunneling**, row _Maximum services per tunnel_. If you need this limit increased, please reach out to AWS support and ask for a limit increase.	

#### Load balancing in multiplexed streams  
If more than one stream is transferred at the same time, local proxy will not load balance between these streams. If you have one stream that is dominating the bandwidth, the other streams sharing the same tunnel connection may see latency of data packet delivery. 

### Troubleshooting

#### SSL Handshake Issues

If you encounter SSL handshake issues, follow these steps to troubleshoot:

1. **Check SSL Certificates**: Ensure that the SSL certificates are correctly installed and configured on your system. Verify that the certificate chain is complete and trusted.

2. **Verify Network Configuration**: Check your network configuration to ensure that there are no firewall rules or network policies blocking the SSL handshake.

3. **Enable Detailed Logging**: Enable detailed logging in the localproxy to capture SSL handshake errors. Use the `-v` option with a higher verbosity level (e.g., `-v 6`) to get more detailed logs.

4. **Retry Mechanism**: The localproxy includes a retry mechanism for SSL handshake. If the handshake fails, the localproxy will automatically retry the handshake. Ensure that the retry mechanism is enabled in the configuration.

5. **Disable SSL Verification**: As a last resort, you can disable SSL verification if the handshake continues to fail. Use the `--no-ssl-host-verify` option to disable SSL host verification. Note that this should only be used for troubleshooting purposes and not in production environments.

6. **Check System Environment**: The issue may be specific to your system environment. Ensure that the localproxy works on other systems to rule out any system-specific issues.

7. **Update Dependencies**: Ensure that you are using the latest versions of the dependencies (e.g., OpenSSL, Boost) required by the localproxy. Outdated dependencies may cause SSL handshake issues.

8. **Consult Documentation**: Refer to the official documentation and troubleshooting guides provided by the localproxy project for additional troubleshooting steps and best practices.
