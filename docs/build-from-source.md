# Building the Local Proxy from Source

## Prerequisites

### System Requirements

| Requirement  | Minimum |
| ------------ | ------- |
| Disk Space   | >8GB    |
| RAM          | >1GB    |
| C++ Standard | C++ 14  |
| CMake        | 3.6+    |

> **Note:** We recommend building elsewhere and importing the binary if your
> device does not meet these requirements.

### Required Development Libraries

| Library  | Version        |
| -------- | -------------- |
| Boost    | 1.87           |
| Protobuf | 3.17.x         |
| zlib     | 1.12.13+       |
| OpenSSL  | 1.0+ OR 3.x    |
| Catch2   | Test framework |

- **Minimum System Requirements:** >8GB of disk space and >1GB of RAM. We
  recommended building elsewhere and importing the binary if your device does
  not meet these requirements.
- C++ 14 compiler
- CMake 3.6+
- Development libraries required:
  - Boost 1.87
  - Protobuf 3.17.x
  - zlib 1.12.13+
  - OpenSSL 1.0+ OR OpenSSL 3
  - Catch2 test framework

## Setup

Stage a dependency build directory and change directory into it:

```bash
mkdir dependencies
cd dependencies
```

The next steps should start from this directory, and return back to it.

---

## 1. Download and Install Zlib Dependency

**Note:** This step may be simpler to complete via a native software application
manager.

**Ubuntu:**

```bash
sudo apt install zlib1g
```

**Fedora:**

```bash
dnf install zlib
```

**From source:**

```bash
wget https://www.zlib.net/zlib-1.2.13.tar.gz -O /tmp/zlib-1.2.13.tar.gz
tar xzvf /tmp/zlib-1.2.13.tar.gz
cd zlib-1.2.13
./configure
make
sudo make install
```

---

## 2. Download and Install Boost Dependency

```bash
wget https://archives.boost.io/release/1.87.0/source/boost_1_87_0.tar.gz -O /tmp/boost_1_87_0.tar.gz
tar xzvf /tmp/boost_1_87_0.tar.gz
cd boost_1_87_0
./bootstrap.sh
sudo ./b2 install link=static
```

If you want to install an older version of boost, pass the version string
through the cmake variable when compiling the local proxy: `-DBOOST_PKG_VERSION`

---

## 3. Download and Install Protobuf Dependency

```bash
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protobuf-all-3.17.3.tar.gz -O /tmp/protobuf-all-3.17.3.tar.gz
tar xzvf /tmp/protobuf-all-3.17.3.tar.gz
cd protobuf-3.17.3
mkdir build
cd build
cmake ../cmake
make
sudo make install
```

If you want to install an older version of protobuf, pass the version string
through the cmake variable when compiling the local proxy:
`-DPROTOBUF_PKG_VERSION`

---

## 4. Download and Install OpenSSL Development Libraries

We strongly recommend installing OpenSSL development libraries using your native
platform package manager so the local proxy's integration with OpenSSL can use
the platform's globally configured root CAs.

**Ubuntu:**

```bash
sudo apt install libssl-dev
```

**Fedora:**

```bash
dnf install openssl-devel
```

**From source:**

```bash
git clone https://github.com/openssl/openssl.git
cd openssl
git checkout OpenSSL_1_1_1-stable
./Configure linux-generic64
make depend
make all
```

Run the `./Configure` command without any arguments to check the available
platform configuration options and the documentation here:
https://wiki.openssl.org/index.php/Compilation_and_Installation

### Static vs. Dynamic Linking OpenSSL

| Linking Type     | CMake Flag                  | Recommended For        |
| ---------------- | --------------------------- | ---------------------- |
| Static (default) | `-DLINK_STATIC_OPENSSL=ON`  | Standalone deployments |
| Dynamic          | `-DLINK_STATIC_OPENSSL=OFF` | Faster CVE patching    |

In the `CMakeLists.txt`, we provide a parameter `-DLINK_STATIC_OPENSSL` which by
default is set to ON (static linking). You may link against shared libraries on
your system by setting the value to OFF:

**Static OpenSSL (default):**

```bash
cmake ../
make
```

**Dynamic OpenSSL:**

```bash
cmake ../ -DLINK_STATIC_OPENSSL=OFF
make
```

Choosing to use dynamic linking is completely optional depending on your own
operational requirements. But it is highly recommended to use it dynamically as
it will help out with faster patches when CVEs are discovered.

---

## 5. Download and Install Catch2 Test Framework

```bash
git clone --branch v3.7.0 https://github.com/catchorg/Catch2.git
cd Catch2
mkdir build
cd build
cmake ../
make
sudo make install
```

---

## Download and Build the Local Proxy

```bash
git clone https://github.com/aws-samples/aws-iot-securetunneling-localproxy
cd aws-iot-securetunneling-localproxy
mkdir build
cd build
cmake ../
make
```

On successful build, there will be two binary executables located at
`bin/localproxy` and `bin/localproxytest`. You may choose to run localproxytest
to ensure your platform is working properly. From here on, copy or distribute
the _localproxy_ binary as you please. The same source code is used for both
source mode and destination mode. Different binaries may be built if the source
and destinations are on different platforms and/or architectures.

---

## Harden Your Toolchain

We recommend configuring your compiler to enable all security features relevant
to your platform and use cases. For additional information about
security-relevant compiler flags, see:
https://www.owasp.org/index.php/C-Based_Toolchain_Hardening

---

## Cross-compilation

CMake cross-compilation can be accomplished using the following general steps:

1. Acquire cross-compiler toolchain for your target platform
2. Create and configure system root (sysroot) for your target platform
3. Build and install dependencies into the sysroot of the target platform
   - Consult each dependency's documentation for guidance on how to cross
     compile
4. Build the local proxy
5. Run the test executable (also built for your platform)

CMake can perform cross-compilation builds when it is given a toolchain file.
Here is an example filename: `raspberry_pi_3_b_plus.cmake.tc`

```cmake
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

To perform the cross-compilation build files run:

```bash
cmake ../ -DCMAKE_TOOLCHAIN_FILE=raspberry_pi_3_b_plus.cmake.tc && make
```

### Helpful Links

- https://crosstool-ng.github.io/ - crosstool-NG makes it convenient to build a
  toolchain, acquire and configure a system root
- https://wiki.osdev.org/Target_Triplet - Consult this to understand your
  platform triplet
