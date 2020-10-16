# FROM ubuntu:18.04
FROM ubuntu:18.04 as builder

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

RUN git clone --branch v2.13.2 https://github.com/catchorg/Catch2.git && \
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

# If you'd like to use this Dockerfile to build your LOCAL revisions to the
# local proxy source code, uncomment the following three commands and comment
# out the command above. Otherwise, we'll build the local proxy container
# with fresh source from the GitHub repo.

#RUN mkdir /home/dependencies/aws-iot-securetunneling-localproxy
#
#COPY ./ /home/dependencies/aws-iot-securetunneling-localproxy/
#
#RUN cd /home/dependencies/aws-iot-securetunneling-localproxy && \
#    rm -rf build/ && \
#    mkdir build && \
#    cd build && \
#    cmake ../ && \
#    make

RUN mkdir -p /home/aws-iot-securetunneling-localproxy && \
	cd /home/aws-iot-securetunneling-localproxy && \
	cp /home/dependencies/aws-iot-securetunneling-localproxy/build/bin/* /home/aws-iot-securetunneling-localproxy/

RUN rm -rf /home/dependencies

WORKDIR /home/aws-iot-securetunneling-localproxy/

## Actual docker image

FROM ubuntu:18.04

# Install openssl for libssl dependency.

RUN apt update && apt upgrade -y && \
    apt install -y openssl wget && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

RUN mkdir -p /home/aws-iot-securetunneling-localproxy/certs && \
    cd /home/aws-iot-securetunneling-localproxy/certs && \
    wget https://www.amazontrust.com/repository/AmazonRootCA1.pem && \
	openssl rehash ./

# # Copy the binaries from builder stage.

COPY --from=builder /home/aws-iot-securetunneling-localproxy /home/aws-iot-securetunneling-localproxy

WORKDIR /home/aws-iot-securetunneling-localproxy
