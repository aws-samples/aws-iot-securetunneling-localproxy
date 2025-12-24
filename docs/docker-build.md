# Building the Local Proxy via Docker

## Prerequisites

* Docker 18+

## Quick Reference

| Image Type | Size | Use Case |
|------------|------|----------|
| Base Images | ~1 GB | Modify and compile local proxy |
| Release Images | Minimal | Run pre-built binary directly |

---

## Using Pre-built Docker Images

We provide several docker images on various platforms. Both x86 and ARM are supported, though armv7 is currently limited to the ubuntu images.
There are two types of images: base images and release images.

### Base Images

The base images come with all dependencies pre-installed. You will still need to download and build the source. These images are tagged with their corresponding arch.
These are useful if you want to modify and [compile](https://github.com/aws-samples/aws-iot-securetunneling-localproxy#download-and-build-the-local-proxy) the local proxy on your own, but are large (~1 GB each).

You can find them at:

| Image | Architectures |
|-------|---------------|
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-base | amd64/arm64/armv7 |
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/debian-base | amd64/arm64 |
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/amazonlinux-base | amd64/arm64 |
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/ubi8-base | amd64/arm64 |
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/fedora-base | amd64 |

### Release Images

The release images are minimum size images that include a pre-built binary with only the necessary shared libs installed. To use the release images, simply pass the localproxy CLI args into the docker run command.

**Example:**
```bash
docker run --rm -it --network=host public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:amd64-latest --region us-east-1 -s 5555 -t <ACCESS_TOKEN>
```

Sometimes there may be minute differences between the Ubuntu images depending on the arch, which may not end up giving openssl enough context about which cert stores to use for verifying server certificates. In such cases to avoid the SSL handshake failure we can provide the ssl certs path as well (`-c /etc/ssl/certs`).

**Example:**
```bash
sudo docker run --rm -it --network=host public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:arm64-latest --region us-west-2 -s 5555 -c /etc/ssl/certs -t <ACCESS_TOKEN>
```

**On MacOS**, `--network=host` does not work the way you expect it would. Instead, do:
```bash
docker run --rm -it -p 5555:5555 public.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin:amd64-latest --region us-east-1 -b 0.0.0.0 -s 5555 -t <ACCESS_TOKEN>
```

This will automatically pull down the latest docker image and run the localproxy without having to manually install it on your system.

These images are tagged with the git commit and corresponding arch. Example: `33879dd7f1500f7b3e56e48ce8b002cd9b0f9e4e-amd64`.
You can cross-check the git commit sha with the commits in the local proxy repo to see if the binary contains changes added in a specific commit.

The release images can be found at:

| Image | Architectures |
|-------|---------------|
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/ubuntu-bin | amd64/arm64/armv7 |
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/debian-bin | amd64/arm64 |
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/amazonlinux-bin | amd64/arm64 |
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/ubi8-bin | amd64/arm64 |
| https://gallery.ecr.aws/aws-iot-securetunneling-localproxy/fedora-bin | amd64 |

---

## Building a Docker Image

If you do not want to use the prebuilt images, you can build them yourself:

```bash
cd .github/docker-images/base-images/<os of choice>
docker build -t <your tag> .
```

Or, for the debian-ubuntu combined Dockerfile:

```bash
docker build -t <your tag> . --build-arg OS=<choice of debian/ubuntu>:<platform>
```

To build cross-platform images for ARM:

```bash
docker buildx --platform linux/arm64 -t <your tag> .
```

You may also try armv7 for 32 bit images, but supported functionality may be limited.

---

## Running and Transferring Binaries

After the Docker build completes, run `docker run --rm -it <tag>` to open a shell inside the container created in the previous step.

Because it may not make practical sense to SSH into a docker container, you can transfer binaries by exposing your machine's filesystem to the containerized filesystem via bind mount. To bind mount a volume on your physical machine's current directory:

```bash
docker run --rm -it -v $(pwd):/root <tag>
```

You can add `-p <port_number>` to expose a port from the docker container.

**Note:** When the localproxy runs in source mode, it binds by default to `localhost`. If you want to access the localproxy from outside the container, make sure to use the option `-b 0.0.0.0` when you run the localproxy from the container so that it binds to `0.0.0.0` since `localhost` can not be accessed from outside the container.

---

## Deprecated Method

```bash
./docker-build.sh
```
