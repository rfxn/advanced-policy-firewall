#!/bin/bash
#
# Creates network namespace with veth pairs for multi-interface testing.
#
# Topology (when netns available):
#   [default ns]                         [client_ns]
#   veth-pub  (203.0.113.1/24)    <-->   veth-pub-peer  (203.0.113.100/24)
#   veth-priv (10.0.0.1/24)      <-->   veth-priv-peer (10.0.0.100/24)
#
# Fallback (no netns — rule-only tests):
#   veth-pub  (203.0.113.1/24)   <-->   veth-pub-peer  (203.0.113.100/24)  [both default ns]
#   veth-priv (10.0.0.1/24)      <-->   veth-priv-peer (10.0.0.100/24)     [both default ns]
#
# APF runs in default namespace. Traffic tests require NETNS_AVAILABLE=true.

# Exported so .bats files can check it
export NETNS_AVAILABLE=false

setup_netns() {
    # Ensure /run/netns exists (required by iproute2)
    mkdir -p /run/netns 2>/dev/null || true

    # Create veth pairs first (only requires NET_ADMIN)
    ip link add veth-pub type veth peer name veth-pub-peer 2>/dev/null || true
    ip link add veth-priv type veth peer name veth-priv-peer 2>/dev/null || true

    # Try to create network namespace (requires SYS_ADMIN or privileged)
    if ip netns add client_ns 2>/dev/null; then
        NETNS_AVAILABLE=true
        export NETNS_AVAILABLE

        # Move peer ends into namespace
        ip link set veth-pub-peer netns client_ns
        ip netns exec client_ns ip addr add 203.0.113.100/24 dev veth-pub-peer
        ip netns exec client_ns ip link set veth-pub-peer up
        ip netns exec client_ns ip link set lo up

        ip link set veth-priv-peer netns client_ns
        ip netns exec client_ns ip addr add 10.0.0.100/24 dev veth-priv-peer
        ip netns exec client_ns ip link set veth-priv-peer up
    else
        # Fallback: keep peer ends in default namespace (sufficient for rule verification)
        ip addr add 203.0.113.100/24 dev veth-pub-peer 2>/dev/null || true
        ip link set veth-pub-peer up
        ip addr add 10.0.0.100/24 dev veth-priv-peer 2>/dev/null || true
        ip link set veth-priv-peer up
    fi

    # Configure host-side interfaces (always in default namespace)
    ip addr add 203.0.113.1/24 dev veth-pub 2>/dev/null || true
    ip link set veth-pub up
    ip addr add 10.0.0.1/24 dev veth-priv 2>/dev/null || true
    ip link set veth-priv up
}

setup_netns
