ARG OS
FROM ${OS} AS base

# Install Prerequisites

RUN apt update && apt upgrade -y && \
	apt install -y git libboost-all-dev autoconf automake \
	wget libtool curl make g++ unzip cmake python3

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
RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.81.0/source/boost_1_81_0.tar.gz -O /tmp/boost.tar.gz && \
	tar xzvf /tmp/boost.tar.gz && \
	cd boost_1_81_0 && \
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
RUN wget https://github.com/openssl/openssl/archive/refs/tags/openssl-3.0.2.tar.gz -O /tmp/openssl-3.0.2.tar.gz && \
    tar xzvf /tmp/openssl-3.0.2.tar.gz && \
	cd openssl-openssl-3.0.2 && \
	./config && \
    make && \
	make install

WORKDIR /home/dependencies
RUN git clone --branch v2.13.6 https://github.com/catchorg/Catch2.git && \
	cd Catch2 && \
	mkdir build && \
	cd build && \
	cmake ../ && \
	make && \
	make install
