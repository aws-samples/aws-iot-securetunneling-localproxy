FROM mcr.microsoft.com/devcontainers/cpp:1-debian-12

# Let Docker buildx inject the target architecture
ARG TARGETARCH

ARG REINSTALL_CMAKE_VERSION_FROM_SOURCE="3.22.2"
ARG BOOST_VERSION="1.87.0"
ARG PROTOBUF_VERSION="3.17.3"
ARG GIT_DELTA_VERSION="0.18.2"
ARG CROSSTOOLS_NG_VERSION="1.27.0"

# Optionally install the cmake for vcpkg
COPY ./reinstall-cmake.sh /tmp/

RUN if [ "${REINSTALL_CMAKE_VERSION_FROM_SOURCE}" != "none" ]; then \
        chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${REINSTALL_CMAKE_VERSION_FROM_SOURCE}; \
    fi \
    && rm -f /tmp/reinstall-cmake.sh

# [Optional] Uncomment this section to install additional vcpkg ports.
# RUN su vscode -c "${VCPKG_ROOT}/vcpkg install <your-port-name-here>"

RUN echo 'deb [trusted=yes] https://repo.goreleaser.com/apt/ /' | sudo tee /etc/apt/sources.list.d/goreleaser.list
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        # For cross-compiling to ARMv7 architecture which includes the Cortex-A8 processors used in our EDGs.
        gcc-arm-linux-gnueabihf \
        g++-arm-linux-gnueabihf \
        # OpenSSL and Zlib development libraries
        libssl-dev \
        zlib1g \
        # Crosstool-NG dependencies
        autoconf \
        automake \
        gawk \
        gperf \
        bison \
        file \
        flex \
        texinfo \
        help2man \
        patch \
        make \
        libtool-bin \
        libncurses-dev \
        # For building Debian packages
        debhelper \
        dpkg-dev \
        dh-make \
        lintian \
        nfpm

# Install Boost library
RUN curl -sL "https://sourceforge.net/projects/boost/files/boost/${BOOST_VERSION}/boost_$(echo ${BOOST_VERSION} | sed 's/\./_/g').tar.gz/download" | tar xz -C /tmp/ \
    && cd /tmp/boost_$(echo ${BOOST_VERSION} | sed 's/\./_/g') \
    && ./bootstrap.sh \
    && ./b2 install link=static \
    && cd /tmp/ \
    && rm -rf boost_1_87_0

# Install Protobuf
RUN curl -sL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOBUF_VERSION}/protobuf-all-${PROTOBUF_VERSION}.tar.gz" | tar xzv -C /tmp/ \
    && cd /tmp/protobuf-${PROTOBUF_VERSION} \
    && mkdir build \
    && cd build \
    && cmake ../cmake \
    && make -j 4 \
    && make install \
    && cd /tmp/ \
    && rm -rf protobuf-3.17.3

# Install Catch2
RUN git clone --branch v3.7.0 https://github.com/catchorg/Catch2.git /tmp/Catch2 \
    && cd /tmp/Catch2 \
    && mkdir build \
    && cd build \
    && cmake ../ \
    && make -j 4 \
    && make install \
    && cd /tmp/ \
    && rm -rf Catch2

# Install crosstools-NG
RUN gpg --keyserver pgp.surfnet.nl --recv-keys 35B871D1 11D618A4 721B0FB1CDC8318AEBB888B809F6DD5F1F30EF2E \
    && curl -sLO --output-dir /tmp "http://crosstool-ng.org/download/crosstool-ng/crosstool-ng-${CROSSTOOLS_NG_VERSION}.tar.xz.sig" \
    && curl -sLO --output-dir /tmp "http://crosstool-ng.org/download/crosstool-ng/crosstool-ng-${CROSSTOOLS_NG_VERSION}.tar.xz" \
    && cd /tmp \
    && gpg --verify crosstool-ng-${CROSSTOOLS_NG_VERSION}.tar.xz.sig crosstool-ng-${CROSSTOOLS_NG_VERSION}.tar.xz \
    && tar -xf crosstool-ng-${CROSSTOOLS_NG_VERSION}.tar.xz -C /tmp/ \
    && cd /tmp/crosstool-ng-${CROSSTOOLS_NG_VERSION} \
    && ./bootstrap \
    && ./configure --prefix=/usr/local \
    && make -j 4 \
    && make install \
    && cd /tmp/ \
    && rm -rf crosstool-ng-${CROSSTOOLS_NG_VERSION} \
    && rm -f crosstool-ng-${CROSSTOOLS_NG_VERSION}.tar.xz \
    && rm -f crosstool-ng-${CROSSTOOLS_NG_VERSION}.tar.xz.sig

# Install Delta
RUN if [ "$TARGETARCH" = "arm" ]; then \
      ARCH="armhf"; \
    else \
      ARCH="$TARGETARCH"; \
    fi && \
    curl -fsSL "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" -o /tmp/git-delta.deb && \
    dpkg -i /tmp/git-delta.deb && \
    rm -f /tmp/git-delta.deb
