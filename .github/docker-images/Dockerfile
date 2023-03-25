ARG OS
ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS deploy

RUN apt update && apt upgrade -y &&  \
    apt install -y git wget curl make g++ cmake

WORKDIR /root
RUN wget https://www.openssl.org/source/openssl-3.0.8.tar.gz \
    && tar xzvf openssl-3.0.8.tar.gz \
    && cd openssl-3.0.8 \
    && ./config \
    && make depend \
    && make all

###############################################################################
# Copy and build local proxy
###############################################################################
WORKDIR /root
COPY . /root/aws-iot-securetunneling-localproxy
RUN mkdir -p /root/aws-iot-securetunneling-localproxy/build \
    && cd /root/aws-iot-securetunneling-localproxy/build \
    && cmake .. \
    && make

FROM ${OS} AS minimum_size

COPY --from=deploy /root/aws-iot-securetunneling-localproxy/build/bin/localproxy /root/bin/localproxy

COPY ./.github/docker-images/oss-compliance /root/oss-compliance
RUN HOME_DIR=/root \
    && cd ${HOME_DIR}/oss-compliance \
    && chmod +x ${HOME_DIR}/oss-compliance/generate-oss-compliance.sh \
    && chmod +x ${HOME_DIR}/oss-compliance/test/test-oss-compliance.sh \
    && bash ${HOME_DIR}/oss-compliance/generate-oss-compliance.sh ${HOME_DIR} \
    && rm -rf ${HOME_DIR}/oss-compliance*

ENTRYPOINT ["/root/bin/localproxy"]