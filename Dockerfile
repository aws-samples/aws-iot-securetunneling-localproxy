# FROM amazonlinux:latest
FROM amazonlinux:latest as builder
ARG OPENSSL_CONFIG

# Install Prerequisites

RUN yum check-update; yum upgrade -y && \
	yum install -y git boost-devel autoconf automake \
	wget libtool curl make gcc-c++ unzip cmake3 openssl11-devel \
	python-devel which

# Install Dependencies

RUN mkdir /home/dependencies
WORKDIR /home/dependencies

RUN wget https://www.zlib.net/zlib-1.2.12.tar.gz -O /tmp/zlib-1.2.12.tar.gz && \
	tar xzvf /tmp/zlib-1.2.12.tar.gz && \
	cd zlib-1.2.12 && \
	./configure && \
	make && \
	make install && \
	cd /home/dependencies

RUN wget https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.gz -O /tmp/boost.tar.gz && \
	tar xzvf /tmp/boost.tar.gz && \
	cd boost_1_76_0 && \
	./bootstrap.sh && \
	./b2 install link=static && \
	cd /home/dependencies

RUN wget https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protobuf-all-3.17.3.tar.gz -O /tmp/protobuf-all-3.17.3.tar.gz && \
	tar xzvf /tmp/protobuf-all-3.17.3.tar.gz && \
	cd protobuf-3.17.3 && \
	mkdir build && \
	cd build && \
	cmake3 ../cmake && \
	make && \
	make install && \
	cd /home/dependencies

RUN git clone https://github.com/openssl/openssl.git && \
	cd openssl && \
	git checkout OpenSSL_1_1_1-stable && \
	./Configure $OPENSSL_CONFIG && \
	make depend && \
	make all && \
	cd /home/dependencies

RUN git clone --branch v2.13.6 https://github.com/catchorg/Catch2.git && \
	cd Catch2 && \
	mkdir build && \
	cd build && \
	cmake3 ../ && \
	make && \
	make install && \
	cd /home/dependencies

RUN git clone https://github.com/aws-samples/aws-iot-securetunneling-localproxy && \
	cd aws-iot-securetunneling-localproxy && \
	mkdir build && \
	cd build && \
	cmake3 ../ && \
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

FROM amazonlinux:latest

# Install openssl for libssl dependency.

RUN yum check-update; yum upgrade -y && \
    yum install -y openssl11 wget libatomic && \
    rm -rf /var/cache/yum && \
    yum clean all

RUN mkdir -p /home/aws-iot-securetunneling-localproxy/certs && \
    cd /home/aws-iot-securetunneling-localproxy/certs && \
    wget https://www.amazontrust.com/repository/AmazonRootCA1.pem && \
	openssl11 rehash ./

# # Copy the binaries from builder stage.

COPY --from=builder /home/aws-iot-securetunneling-localproxy /home/aws-iot-securetunneling-localproxy

WORKDIR /home/aws-iot-securetunneling-localproxy
