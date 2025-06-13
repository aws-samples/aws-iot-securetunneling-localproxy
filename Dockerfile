FROM verdigristech/boost:1.87.0-buster AS builder

# TARGETARCH is filled in by Docker Buildx
ARG TARGETARCH
ARG TARGETVARIANT
ARG BOOST_VERSION="1.87.0"

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /tmp

# Hardening flags for Debian builds
# These flags help to ensure that the build process is secure and that the resulting binaries are hardened against common vulnerabilities.
ENV DEB_BUILD_HARDENING=1

# If we're building for ARMv7, enable compiler optimizations for the TI Sitara AM335x processor
# CPU Type: ARMv7-A
# CPU Architecture: Cortex-A8
# SIMD Coprocessor: NEON
# Floating Point ABI: Hard (generates floating-point instructions with FPU-specific calling conventions)
RUN if [ "${TARGETARCH}" = "arm" ] && [ "${TARGETVARIANT}" = "v7" ]; then \
      export CFLAGS="-O2 -march=armv7-a -mtune=cortex-a8 -mfloat-abi=hard -mfpu=neon -pipe -fstack-protector-strong -Wformat -Werror=format-security"; \
      export CXXFLAGS="-O2 -march=armv7-a -mtune=cortex-a8 -mfloat-abi=hard -mfpu=neon -pipe -fstack-protector-strong -Wformat -Werror=format-security"; \
    else \
      export CFLAGS="-O2 -pipe -fstack-protector-strong -Wformat -Werror=format-security"; \
      export CXXFLAGS="-O2 -pipe -fstack-protector-strong -Wformat -Werror=format-security"; \
    fi && \
    git clone https://github.com/VerdigrisTech/localproxy && \
    cd localproxy && \
    mkdir build && \
    cd build && \
    cmake ../ && \
    make -j 16 && \
    cp bin/localproxy /usr/local/bin/localproxy && \
    cd /tmp

# Copy the shared libraries required by localproxy
RUN ldd /usr/local/bin/localproxy | grep -o '/[^ ]*' | sort -u | xargs -I {} cp {} /usr/local/lib

# Strip the localproxy binary to reduce its size
RUN strip --strip-unneeded /usr/local/bin/localproxy

# Keep the final image minimal; we only need the statically compiled localproxy binary
FROM scratch

COPY --from=builder /usr/local/bin/localproxy /usr/local/bin/localproxy
COPY --from=builder /usr/local/lib /lib

CMD ["/usr/local/bin/localproxy"]
