# AWS IoT Secure Tunneling Local Proxy Reference Implementation C++

Example C++ implementation of a local proxy for the AWS IoT Secure Tunneling
service.

> **As of the 3.1.2 May 2024 update, `--destination-client-type V1` is a
> required parameter** when connecting with the AWS IoT Device Client, the AWS
> IoT / Greengrass V2 Secure Tunneling Component, browser-based Secure Tunneling
> from the AWS Console, any Secure Tunneling demo code written before 2022, or
> 1.x versions of the localproxy. See
> [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Overview

This code enables tunneling of a single threaded TCP client / server socket
interaction through the IoT Secure Tunneling service. The code is targeted to
run on Linux, Windows (7+), and macOS. If your device does not meet these
requirements it is still possible to implement the underlying protocol
documented in the [protocol guides](#documentation).

## Quick start

On x86 Linux, with [Docker](https://docs.docker.com/get-started/get-docker/)
installed:

```bash
docker run --rm -it --network=host \
  public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:amd64-latest \
  --region us-east-1 -s 5555 -t <ACCESS_TOKEN>
```

Other architectures, macOS notes and base images are covered in
[docs/DOCKER.md](docs/DOCKER.md). To build from source instead:

```bash
mkdir -p build && cd build
cmake ../ -DLINK_STATIC_OPENSSL=OFF
make -j"$(nproc)"
```

Boost, Protobuf and Catch2 are fetched automatically when they are not
installed; only OpenSSL and zlib are never fetched for you. See
[docs/BUILD.md](docs/BUILD.md).

Either way — including when you download a prebuilt binary from the GitHub
releases — each host that runs `localproxy` needs these present:

```bash
# Debian/Ubuntu
sudo apt install -y libssl3 zlib1g libstdc++6

# Fedora/Amazon Linux/RHEL
sudo dnf install -y openssl-libs zlib libstdc++
```

Then start one local proxy at each end of the tunnel, using the matching access
token from `OpenTunnel`:

```bash
# on the device, forwarding tunnel traffic to a local SSH server
./localproxy -r us-east-1 -d localhost:22 -t <destination_client_access_token>

# on your machine, listening for the SSH client on port 5555
./localproxy -r us-east-1 -s 5555 -t <source_client_access_token>
```

[docs/RUNNING.md](docs/RUNNING.md) explains both modes in full, including the
[runtime dependencies](docs/RUNNING.md#runtime-dependencies).

## Documentation

Getting the local proxy:

- **[docs/DOCKER.md](docs/DOCKER.md)** — prebuilt ECR images and building your
  own.
- **[docs/BUILD.md](docs/BUILD.md)** — building from source: CMake options,
  offline builds, cross-compilation, static analysis.
  - **[docs/DEPENDENCIES.md](docs/DEPENDENCIES.md)** — installing the
    dependencies yourself, instead of letting the build fetch them.
  - **[windows-localproxy-build.md](docs/windows-localproxy-build.md)** —
    building on Windows.

Using the local proxy:

- **[docs/RUNNING.md](docs/RUNNING.md)** — runtime dependencies, source and
  destination mode, stopping the proxy, HTTP proxy support, IPv6.
- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** — every CLI argument,
  `--config` and `--config-dir` files, environment variables and
  `--settings-json` settings.
- **[docs/MULTIPLEXING.md](docs/MULTIPLEXING.md)** — multi-port tunneling,
  service IDs and tunnel limits.
- **[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md)** — V1/V2/V3 protocols,
  `--destination-client-type` and backward compatibility rules.
- **[docs/SECURITY.md](docs/SECURITY.md)** — TLS versions, certificate setup,
  runtime hardening, access and client tokens.

Protocol and project:

- **[V1](docs/V1WebSocketProtocolGuide.md) /
  [V2](docs/V2WebSocketProtocolGuide.md) /
  [V3](docs/V3WebSocketProtocolGuide.md) WebSocket protocol guides** — the wire
  protocol, for implementing your own client.
- **[CHANGELOG.md](CHANGELOG.md)** — release history.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — issues, pull requests, CLA;
  **[AGENTS.md](AGENTS.md)** — the commit, formatting and test workflow.

## License

This library is licensed under the Apache 2.0 License.
