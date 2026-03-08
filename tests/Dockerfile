ARG BASE_IMAGE=apf-base-debian12
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    kmod \
    net-tools \
    iputils-ping \
    netcat-openbsd \
    ipset \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Prepare for network namespace support
RUN mkdir -p /run/netns

# Copy APF source tree
COPY . /opt/apf-src

# Copy tests
COPY tests/ /opt/tests/

# Pre-install APF with test config
RUN cd /opt/apf-src && INSTALL_PATH=/opt/apf bash install.sh && \
    conf="/opt/apf/conf.apf" && \
    sed -i 's/^SET_MONOKERN=.*/SET_MONOKERN="1"/' "$conf" && \
    sed -i 's/^DEVEL_MODE=.*/DEVEL_MODE="0"/' "$conf" && \
    sed -i 's/^VF_ROUTE=.*/VF_ROUTE="0"/' "$conf" && \
    sed -i 's/^DLIST_PHP=.*/DLIST_PHP="0"/' "$conf" && \
    sed -i 's/^DLIST_SPAMHAUS=.*/DLIST_SPAMHAUS="0"/' "$conf" && \
    sed -i 's/^DLIST_DSHIELD=.*/DLIST_DSHIELD="0"/' "$conf" && \
    sed -i 's/^DLIST_RESERVED=.*/DLIST_RESERVED="0"/' "$conf" && \
    sed -i 's/^DLIST_ECNSHAME=.*/DLIST_ECNSHAME="0"/' "$conf" && \
    sed -i 's/^USE_RGT=.*/USE_RGT="0"/' "$conf" && \
    sed -i 's/^RAB=.*/RAB="0"/' "$conf" && \
    sed -i 's/^SET_FASTLOAD=.*/SET_FASTLOAD="0"/' "$conf" && \
    sed -i 's/^SET_REFRESH=.*/SET_REFRESH="0"/' "$conf" && \
    sed -i 's/^BLK_RESNET=.*/BLK_RESNET="0"/' "$conf" && \
    sed -i 's/^USE_IPSET=.*/USE_IPSET="0"/' "$conf" && \
    sed -i 's/^USE_GRE=.*/USE_GRE="0"/' "$conf"

# Save clean state for test resets
RUN for f in allow_hosts.rules deny_hosts.rules cc_deny.rules cc_allow.rules; do \
      sed '/^[^#]/d' "/opt/apf/$f" > "/opt/apf/$f.clean"; \
    done && \
    cp /opt/apf/conf.apf /opt/apf/conf.apf.clean && \
    cp /opt/apf/hook_pre.sh /opt/apf/hook_pre.sh.clean && \
    cp /opt/apf/hook_post.sh /opt/apf/hook_post.sh.clean && \
    cp /opt/apf/silent_ips.rules /opt/apf/silent_ips.rules.clean

WORKDIR /opt/tests

# Default: run all tests with tap formatter
CMD ["bats", "--formatter", "tap", "/opt/tests/"]
