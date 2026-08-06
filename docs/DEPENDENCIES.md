# Installing the dependencies yourself

The build fetches Boost, Protobuf and Catch2 automatically when they are
missing, so **you usually do not need this page** — see
[BUILD.md](BUILD.md#building-without-pre-installed-dependencies). It is here for
platforms where you would rather provide the libraries yourself, or where the
build must run in `system` mode.

The pinned version, download URL and checksum of Boost, Protobuf and Catch2 all
live in one place, [`../fc_deps.json`](../fc_deps.json); that file is the single
source of truth if you want to change them. OpenSSL and zlib are intentionally
not listed there and should always come from your platform package manager.

## Requirements

- Minimum System Requirements: >8GB of disk space and >1GB of RAM. We recommend
  building elsewhere and importing the binary if your device does not meet these
  requirements.
- C++ 14 compiler
- CMake 3.10+ to build against pre-installed dependencies; CMake 3.19+ to have
  the build fetch and compile them for you. `./bootstrap-cmake.sh` will obtain a
  suitable CMake if yours is older.
- Development libraries:
  - Boost 1.87
  - Protobuf 3.17.x
  - zlib 1.2.13+
  - OpenSSL 1.0.1+ OR OpenSSL 3 (must support TLS 1.2)
  - Catch2 test framework

Stage a dependency build directory and change directory into it; every step
below starts from — and returns to — this directory:

```bash
mkdir dependencies
cd dependencies
```

---

## 1. Zlib

Note: This step may be simpler to complete via a native software application
manager.

Ubuntu example: `sudo apt install zlib1g`

Fedora example: `dnf install zlib`

    wget https://www.zlib.net/zlib-1.2.13.tar.gz -O /tmp/zlib-1.2.13.tar.gz
    tar xzvf /tmp/zlib-1.2.13.tar.gz
    cd zlib-1.2.13
    ./configure
    make
    sudo make install

## 2. Boost

    wget https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz -O /tmp/boost_1_87_0.tar.gz
    tar xzvf /tmp/boost_1_87_0.tar.gz
    cd boost_1_87_0
    ./bootstrap.sh
    sudo ./b2 install link=static

If you want to install an older version of boost, pass the version string
through the cmake variable when compiling the local proxy: `-DBOOST_PKG_VERSION`

## 3. Protobuf

    wget https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protobuf-all-3.17.3.tar.gz -O /tmp/protobuf-all-3.17.3.tar.gz
    tar xzvf /tmp/protobuf-all-3.17.3.tar.gz
    cd protobuf-3.17.3
    mkdir build
    cd build
    cmake ../cmake
    make
    sudo make install

If you want to install an older version of protobuf, pass the version string
through the cmake variable when compiling the local proxy:
`-DPROTOBUF_PKG_VERSION`

## 4. OpenSSL development libraries

We strongly recommend installing OpenSSL development libraries using your native
platform package manager so the local proxy's integration with OpenSSL can use
the platform's globally configured root CAs.

Ubuntu example: `sudo apt install libssl-dev`

Fedora example: `dnf install openssl-devel`

Source install example:

    git clone https://github.com/openssl/openssl.git
    cd openssl
    git checkout OpenSSL_1_1_1-stable
    ./Configure linux-generic64
    make depend
    make all

Run the ./Configure command without any arguments to check the available
platform configuration options and the documentation here:
https://wiki.openssl.org/index.php/Compilation_and_Installation

### Static vs. dynamic linking of OpenSSL

`-DLINK_STATIC_OPENSSL` selects how OpenSSL is linked. It defaults to `ON`
(static), but we recommend `OFF` so the proxy picks up your platform's OpenSSL
security updates without being rebuilt:

**Dynamic OpenSSL (recommended):**

```bash
cmake ../ -DLINK_STATIC_OPENSSL=OFF
make
```

**Static OpenSSL (the build default):**

```bash
cmake ../
make
```

Static linking makes sense when you need a self-contained binary to copy onto a
host that has no matching `libssl` — at the cost of owning OpenSSL patching
yourself.

## 5. Catch2 test framework

    git clone --branch v3.7.0 https://github.com/catchorg/Catch2.git
    cd Catch2
    mkdir build
    cd build
    cmake ../
    make
    sudo make install

---

Once the dependencies are in place, continue with [BUILD.md](BUILD.md#building).
