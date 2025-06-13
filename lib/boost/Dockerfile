FROM debian:buster-slim

# TARGETARCH is filled in by Docker Buildx
ARG TARGETARCH
ARG BOOST_VERSION="1.87.0"

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /tmp

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gnupg \
        build-essential \
        autoconf \
        automake \
        cmake \
        git \
        libssl-dev \
        libprotobuf-dev \
        protobuf-compiler \
        zlib1g-dev \
        libtool-bin \
        unzip \
        # which \
        curl \
        pkg-config \
        libatomic1 && \
    rm -rf /var/lib/apt/lists/*

# We need at least Boost 1.87.0 instead of the default 1.74.0 that comes with Debian Bookworm
RUN if [ "${TARGETARCH}" = "arm" ]; then \
      # If we're building for ARM, enable compiler optimizations for the TI Sitara AM335x processor
      # CPU Type: ARMv7-A
      # CPU Architecture: Cortex-A8
      # SIMD Coprocessor: NEON
      # Floating Point ABI: Hard (generates floating-point instructions with FPU-specific calling conventions)
      export CFLAGS="-march=armv7-a -mtune=cortex-a8 -mfloat-abi=hard -mfpu=neon -pipe"; \
      export CXXFLAGS="-march=armv7-a -mtune=cortex-a8 -mfloat-abi=hard -mfpu=neon -pipe"; \
    fi && \
    BOOST_PREFIX="boost_$(echo "${BOOST_VERSION}" | sed 's/\./_/g')" && \
    curl -sL "https://sourceforge.net/projects/boost/files/boost/${BOOST_VERSION}/${BOOST_PREFIX}.tar.gz/download" | tar xz -C /tmp/ && \
    cd /tmp/${BOOST_PREFIX} && \
    ./bootstrap.sh && \
    ./b2 install link=static && \
    cd /tmp/ \
    && rm -rf ${BOOST_PREFIX}

# Build zlib 1.2.13
RUN cd /tmp && \
    curl -sSLO https://github.com/madler/zlib/releases/download/v1.2.13/zlib-1.2.13.tar.gz && \
    tar xzvf /tmp/zlib-1.2.13.tar.gz && \
    cd zlib-1.2.13 && \
    ./configure --static && \
    make && \
    make install

# Build Protobuf 3.17.3
RUN cd /tmp && \
    curl -sSLO https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protobuf-all-3.17.3.tar.gz && \
    tar xzvf /tmp/protobuf-all-3.17.3.tar.gz && \
    cd protobuf-3.17.3 && \
    mkdir build && \
    cd build && \
    cmake ../cmake \
        -DBUILD_SHARED_LIBS=OFF \
        -Dprotobuf_BUILD_SHARED_LIBS=OFF \
        -Dprotobuf_BUILD_PROTOC_BINARIES=ON \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON && \
    make && \
    make install
