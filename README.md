## As of 3.1.2 May 2024 Update, `--destination-client-type V1` will be a required parameter when connecting with the following:
- AWS IoT Device Client
- AWS IoT Secure Tunneling Component OR Greengrass V2 Secure Tunneling Component
- Browser-based Secure Tunneling from the AWS Console
- Any Secure Tunneling demo code written before 2022
- 1.x versions of the localproxy

# AWS IoT Secure Tunneling Local Proxy Reference Implementation C++

Example C++ implementation of a local proxy for the AWS IoT Secure Tunneling service.

## License

This library is licensed under the Apache 2.0 License.

## Overview

This code enables tunneling of a single threaded TCP client/server socket interaction through the IoT Secure Tunneling service. The code is targeted to run on Linux, Windows (7+), and macOS. If your device does not meet these requirements it is still possible to implement the underlying protocol documented in the protocol guide.

## Windows Pre-built Binary Requirements

For the pre-built Windows binary from GitHub Actions, download:
- Visual C++: https://aka.ms/vc14/vc_redist.x86.exe
- OpenSSL: https://slproweb.com/products/Win32OpenSSL.html (Select `Win64 OpenSSL v3.x.x Light`)

---

## Documentation

| Topic | Description |
|-------|-------------|
| [Docker Build](docs/docker-build.md) | Building and using Docker images |
| [Build from Source](docs/build-from-source.md) | Building the local proxy from source |
| [Running the Local Proxy](docs/running-localproxy.md) | Running in source and destination modes |
| [Multi-port Tunneling](docs/multi-port-tunneling.md) | Multi-port feature and backward compatibility |
| [CLI Options](docs/cli-options.md) | Command line arguments and configuration |
| [Security](docs/security.md) | Security considerations and best practices |
| [Windows Build](windows-localproxy-build.md) | Building on Windows |

---

## Quick Start (x86 Linux)

1. Install Docker: https://docs.docker.com/get-started/get-docker/

2. Run the local proxy:
```bash
docker run --rm -it --network=host public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:amd64-latest
```

3. Populate the required parameters when prompted.

**With SSL certs path (if SSL handshake issues occur):**
```bash
docker run --rm -it --network=host public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:amd64-latest --region us-east-1 -s 5555 -c /etc/ssl/certs -t <ACCESS_TOKEN>
```

See [Docker Build Guide](docs/docker-build.md) for ARM, macOS, and other Docker options.

---

## Basic Usage Examples

**Source mode:**
```bash
./localproxy -r us-east-1 -s 3389 -t <source_client_access_token>
```

**Destination mode:**
```bash
./localproxy -r us-east-1 -d localhost:3389 -t <destination_client_access_token>
```

**Multi-port source:**
```bash
./localproxy -r us-east-1 -s HTTP1=5555,SSH1=3333 -t <source_client_access_token>
```

**Connecting to V1 destination:**
```bash
./localproxy -r us-east-1 -s 3333 --destination-client-type V1 -t <source_client_access_token>
```

---

## Additional Resources

- [AWS IoT Secure Tunneling Documentation](https://docs.aws.amazon.com/iot/latest/developerguide/secure-tunneling.html)
- [AWS IoT Secure Tunneling Limits](https://docs.aws.amazon.com/general/latest/gr/iot_device_management.html)
- [Troubleshooting Guide](https://docs.aws.amazon.com/iot/latest/developerguide/iot-secure-tunneling-troubleshooting.html)
