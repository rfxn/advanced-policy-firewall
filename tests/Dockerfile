FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    procps \
    kmod \
    coreutils \
    diffutils \
    wget \
    gawk \
    sed \
    grep \
    net-tools \
    iputils-ping \
    netcat-openbsd \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install bats and helpers from tarballs
RUN mkdir -p /opt/bats && \
    wget -qO- https://github.com/bats-core/bats-core/archive/refs/tags/v1.11.0.tar.gz | \
      tar xz -C /opt/bats --strip-components=1 && \
    /opt/bats/install.sh /usr/local && \
    mkdir -p /usr/local/lib/bats/bats-support && \
    wget -qO- https://github.com/bats-core/bats-support/archive/refs/tags/v0.3.0.tar.gz | \
      tar xz -C /usr/local/lib/bats/bats-support --strip-components=1 && \
    mkdir -p /usr/local/lib/bats/bats-assert && \
    wget -qO- https://github.com/bats-core/bats-assert/archive/refs/tags/v2.1.0.tar.gz | \
      tar xz -C /usr/local/lib/bats/bats-assert --strip-components=1

# Prepare for network namespace support
RUN mkdir -p /run/netns

# Copy APF source tree
COPY . /opt/apf-src

# Copy tests
COPY tests/ /opt/tests/

WORKDIR /opt/tests

# Default: run all tests with tap formatter
# Override with: docker run ... apf-smoke-test <bats-args> <test-path>
CMD ["bats", "--formatter", "tap", "/opt/tests/"]
