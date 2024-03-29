ARG OS
ARG BASE_IMAGE
FROM ${BASE_IMAGE} AS deploy

###############################################################################
# Copy and build local proxy
###############################################################################

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

# OS-specific commands
RUN apt update && apt upgrade -y && apt install -y ca-certificates && update-ca-certificates

ENTRYPOINT ["/root/bin/localproxy"]