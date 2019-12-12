FROM ubuntu:18.04

# Install Prerequisites

RUN apt update && apt upgrade -y && \
	apt install -y git libboost-all-dev autoconf automake \
	wget libtool curl make g++ unzip cmake libssl-dev

# Install Dependencies

RUN mkdir /home/dependencies
WORKDIR /home/dependencies

RUN wget https://www.zlib.net/zlib-1.2.11.tar.gz -O /tmp/zlib-1.2.11.tar.gz && \
	tar xzvf /tmp/zlib-1.2.11.tar.gz && \
	cd zlib-1.2.11 && \
	./configure && \
	make && \
	make install && \
	cd /home/dependencies

RUN wget https://dl.bintray.com/boostorg/release/1.69.0/source/boost_1_69_0.tar.gz -O /tmp/boost.tar.gz && \
	tar xzvf /tmp/boost.tar.gz && \
	cd boost_1_69_0 && \
	./bootstrap.sh && \
	./b2 install && \
	cd /home/dependencies

RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protobuf-all-3.6.1.tar.gz -O /tmp/protobuf-all-3.6.1.tar.gz && \
	tar xzvf /tmp/protobuf-all-3.6.1.tar.gz && \
	cd protobuf-3.6.1 && \
	mkdir build && \
	cd build && \
	cmake ../cmake && \
	make && \
	make install && \
	cd /home/dependencies

RUN git clone https://github.com/openssl/openssl.git && \
	cd openssl && \
	git checkout OpenSSL_1_1_1-stable && \
	./Configure linux-generic64 && \
	make depend && \
	make all && \
	cd /home/dependencies

RUN git clone https://github.com/catchorg/Catch2.git && \
	cd Catch2 && \
	mkdir build && \
	cd build && \
	cmake ../ && \
	make && \
	make install && \
	cd /home/dependencies

RUN git clone https://github.com/aws-samples/aws-iot-securetunneling-localproxy && \
	cd aws-iot-securetunneling-localproxy && \
	mkdir build && \
	cd build && \
	cmake ../ && \
	make

WORKDIR aws-iot-securetunneling-localproxy/build/bin/