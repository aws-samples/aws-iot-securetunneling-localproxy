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

FROM redhat/ubi8:latest AS minimum_size

COPY --from=deploy /root/aws-iot-securetunneling-localproxy/build/bin/localproxy /root/bin/localproxy

COPY ./.github/docker-images/oss-compliance /root/oss-compliance
RUN HOME_DIR=/root \
    && cd ${HOME_DIR}/oss-compliance \
    && chmod +x ${HOME_DIR}/oss-compliance/generate-oss-compliance.sh \
    && chmod +x ${HOME_DIR}/oss-compliance/test/test-oss-compliance.sh \
    && bash ${HOME_DIR}/oss-compliance/generate-oss-compliance.sh ${HOME_DIR} \
    && rm -rf ${HOME_DIR}/oss-compliance*

# OS-specific commands
RUN yum check-update; yum upgrade -y && \
	yum install -y libatomic libicu ca-certificates && \
    update-ca-trust extract

ENTRYPOINT ["/root/bin/localproxy"]
