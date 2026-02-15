#!/usr/bin/env bats
#
# 05: Multi-interface — IFACE_UNTRUSTED/TRUSTED, traffic verification
#
# Traffic tests require network namespace support (--privileged or SYS_ADMIN).
# Rule verification tests always run.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash
source /opt/tests/helpers/detect-nc.sh

APF="/opt/apf/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    # Export for individual tests to check
    export NETNS_AVAILABLE
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    # veth-pub = untrusted (internet-facing), veth-priv = trusted (LAN)
    apf_set_interface "veth-pub" "veth-priv"
    apf_set_ports "22,80" "" "" ""
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "trusted interface has ACCEPT rule in INPUT" {
    assert_rule_exists INPUT "ACCEPT.*veth-priv"
}

@test "trusted interface has ACCEPT rule in OUTPUT" {
    assert_rule_exists OUTPUT "ACCEPT.*veth-priv"
}

@test "ping via public interface works (ICMP allowed)" {
    if [ "$NETNS_AVAILABLE" != "true" ]; then
        skip "network namespaces not available (need --privileged)"
    fi
    # ICMP type 8 (echo-request) is in IG_ICMP_TYPES by default
    run ip netns exec client_ns ping -c 1 -W 2 203.0.113.1
    assert_success
}

@test "ping via trusted interface works" {
    if [ "$NETNS_AVAILABLE" != "true" ]; then
        skip "network namespaces not available (need --privileged)"
    fi
    run ip netns exec client_ns ping -c 1 -W 2 10.0.0.1
    assert_success
}

@test "TCP to open port via public succeeds" {
    if [ "$NETNS_AVAILABLE" != "true" ]; then
        skip "network namespaces not available (need --privileged)"
    fi
    nc_listen 80
    local pid=$!
    sleep 1

    run ip netns exec client_ns $NC_BIN -z -w 2 203.0.113.1 80
    assert_success

    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
}

@test "TCP to closed port via public is blocked" {
    if [ "$NETNS_AVAILABLE" != "true" ]; then
        skip "network namespaces not available (need --privileged)"
    fi
    # Port 3306 is not in IG_TCP_CPORTS — should be filtered
    run ip netns exec client_ns $NC_BIN -z -w 1 203.0.113.1 3306
    assert_failure
}

@test "any port via trusted interface succeeds" {
    if [ "$NETNS_AVAILABLE" != "true" ]; then
        skip "network namespaces not available (need --privileged)"
    fi
    # Trusted interface bypasses all rules — even non-configured ports
    nc_listen 9999
    local pid=$!
    sleep 1

    run ip netns exec client_ns $NC_BIN -z -w 2 10.0.0.1 9999
    assert_success

    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
}
