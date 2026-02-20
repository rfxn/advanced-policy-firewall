#!/bin/bash
#
# Cleans up network namespaces and veth pairs created by setup-netns.sh

teardown_netns() {
    ip link del veth-pub 2>/dev/null || true
    ip link del veth-priv 2>/dev/null || true
    ip netns del client_ns 2>/dev/null || true
}

teardown_netns
