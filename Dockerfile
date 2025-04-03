FROM verdigristech/boost:1.87.0 AS builder

# TARGETARCH is filled in by Docker Buildx
ARG TARGETARCH
ARG TARGETVARIANT
ARG BOOST_VERSION="1.87.0"

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /tmp

# If we're building for ARMv7, enable compiler optimizations for the TI Sitara AM335x processor
# CPU Type: ARMv7-A
# CPU Architecture: Cortex-A8
# SIMD Coprocessor: NEON
# Floating Point ABI: Hard (generates floating-point instructions with FPU-specific calling conventions)
RUN if [ "${TARGETARCH}" = "arm" ] && [ "${TARGETVARIANT}" = "v7" ]; then \
      export CFLAGS="-march=armv7-a -mtune=cortex-a8 -mfloat-abi=hard -mfpu=neon -pipe"; \
      export CXXFLAGS="-march=armv7-a -mtune=cortex-a8 -mfloat-abi=hard -mfpu=neon -pipe"; \
    fi && \
    git clone https://github.com/VerdigrisTech/localproxy && \
    cd localproxy && \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make -j 16 && \
    cp bin/localproxy /usr/local/bin/localproxy && \
    cd /tmp

# Keep the final image minimal; we only need the statically compiled localproxy binary
FROM scratch

COPY --from=builder /usr/local/bin/localproxy /usr/local/bin/localproxy
COPY --from=builder /lib /lib

CMD ["/usr/local/bin/localproxy"]
