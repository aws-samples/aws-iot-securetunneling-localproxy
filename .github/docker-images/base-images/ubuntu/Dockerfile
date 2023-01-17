FROM ubuntu:latest as base
ARG OPENSSL_CONFIG=linux-generic64
# Install Prerequisites
RUN apt-get update && \
apt-get install -y build-essential git && \
apt-get install -y wget tar libssl-dev openssl cmake python3
# Install Dependencies
RUN mkdir /home/dependencies
WORKDIR /home/dependencies
RUN wget https://www.zlib.net/zlib-1.2.13.tar.gz -O /tmp/zlib-1.2.13.tar.gz && \
    tar xzvf /tmp/zlib-1.2.13.tar.gz && \
    cd zlib-1.2.13 && \
    ./configure && \
    make && \
    make install
WORKDIR /home/dependencies
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.79.0/source/boost_1_79_0.tar.gz -O /tmp/boost.tar.gz && \
    tar xzvf /tmp/boost.tar.gz && \
    cd boost_1_79_0 && \
    ./bootstrap.sh && \
    ./b2 install link=static
WORKDIR /home/dependencies
RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protobuf-all-3.17.3.tar.gz -O /tmp/protobuf-all-3.17.3.tar.gz && \
    tar xzvf /tmp/protobuf-all-3.17.3.tar.gz && \
    cd protobuf-3.17.3 && \
    mkdir build && \
    cd build && \
    cmake ../cmake && \
    make && \
    make install
WORKDIR /home/dependencies
RUN git clone https://github.com/openssl/openssl.git && \
    cd openssl && \
    git checkout OpenSSL_1_1_1-stable && \
    ./Configure $OPENSSL_CONFIG && \
    make depend && \
    make all
WORKDIR /home/dependencies
RUN git clone --branch v2.13.6 https://github.com/catchorg/Catch2.git && \
    cd Catch2 && \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make && \
    make install
WORKDIR /src
