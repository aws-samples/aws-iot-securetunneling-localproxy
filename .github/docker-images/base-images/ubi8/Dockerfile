FROM redhat/ubi8:latest AS base

# Install Prerequisites

RUN yum -y update \
    && yum -y install git autoconf automake libatomic \
	wget libtool curl make gcc-c++ unzip cmake python3 openssl-devel perl

RUN mkdir /home/dependencies

WORKDIR /home/dependencies
RUN wget https://www.openssl.org/source/openssl-3.0.12.tar.gz \
    && tar xzvf openssl-3.0.12.tar.gz \
    && cd openssl-3.0.12 \
    && ./config \
    && make \
    && make install

WORKDIR /home/dependencies
RUN wget https://github.com/madler/zlib/archive/v1.2.13.tar.gz -O /tmp/zlib-1.2.13.tar.gz && \
	tar xzvf /tmp/zlib-1.2.13.tar.gz && \
	cd zlib-1.2.13 && \
	./configure && \
	make && \
	make install

WORKDIR /home/dependencies
RUN wget https://sourceforge.net/projects/boost/files/boost/1.87.0/boost_1_87_0.tar.gz/download -O /tmp/boost_1_87_0.tar.gz && \
	tar xzvf /tmp/boost_1_87_0.tar.gz && \
	cd boost_1_87_0 && \
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
RUN git clone --branch v3.7.0 https://github.com/catchorg/Catch2.git && \
	cd Catch2 && \
	mkdir build && \
	cd build && \
	cmake ../ && \
	make && \
	make install
