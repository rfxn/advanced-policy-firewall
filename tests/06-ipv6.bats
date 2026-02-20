#!/usr/bin/env bats
#
# 06: IPv6 dual-stack — chains, NDP, sanity, multicast, trust

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    if ! ip6tables_available; then
        return 0
    fi
    apf_set_config "USE_IPV6" "1"
    apf_set_config "PKT_SANITY" "1"
    apf_set_config "BLK_MCATNET" "1"
    apf_set_config "EGF" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    if ip6tables_available; then
        "$APF" -f 2>/dev/null || true
        source /opt/tests/helpers/apf-config.sh
        apf_set_config "USE_IPV6" "0"
        apf_set_config "BLK_MCATNET" "0"
    fi
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
}

teardown() {
    if ! ip6tables_available; then return 0; fi
    # Clean IPv6 test entries from trust files on failure
    for pattern in "2001:db8"; do
        sed -i "/${pattern}/d" "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${pattern}/d" "$APF_DIR/deny_hosts.rules" 2>/dev/null || true
    done
    ip6tables -F TALLOW 2>/dev/null || true
    ip6tables -F TDENY 2>/dev/null || true
}

@test "IPv6 loopback uses ::/0 not 0/0" {
    local rules
    rules=$(ip6tables -L INPUT -nv)
    # Verify loopback ACCEPT rule exists with ::/0 addresses
    echo "$rules" | grep "ACCEPT" | grep -q "lo"
    echo "$rules" | grep "ACCEPT" | grep "lo" | grep -q "::/0"
    # Ensure the loopback line does NOT contain bare 0/0 (IPv4 format)
    # Note: ::/0 contains /0 but not 0/0 as a substring
    if echo "$rules" | grep "ACCEPT" | grep "lo" | grep -qw "0/0"; then
        echo "IPv6 loopback rule incorrectly uses 0/0" >&2
        return 1
    fi
}

@test "IPv6 TALLOW chain exists" {
    assert_chain_exists_ip6 TALLOW
}

@test "IPv6 TDENY chain exists" {
    assert_chain_exists_ip6 TDENY
}

@test "IPv6 TGALLOW chain exists" {
    assert_chain_exists_ip6 TGALLOW
}

@test "IPv6 TGDENY chain exists" {
    assert_chain_exists_ip6 TGDENY
}

@test "IPv6 PROHIBIT chain has icmp6-adm-prohibited" {
    assert_rule_exists_ip6 PROHIBIT "icmp6-adm-prohibited"
}

@test "NDP type 133 (router solicitation) permitted" {
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 133"
}

@test "NDP type 134 (router advertisement) permitted" {
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 134"
}

@test "NDP type 135 (neighbor solicitation) permitted" {
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 135"
}

@test "NDP type 136 (neighbor advertisement) permitted" {
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 136"
}

@test "IN_SANITY6 chain exists" {
    assert_chain_exists_ip6 IN_SANITY6
}

@test "OUT_SANITY6 chain exists" {
    assert_chain_exists_ip6 OUT_SANITY6
}

@test "PZERO6 chain exists" {
    assert_chain_exists_ip6 PZERO6
}

@test "MCAST6 chain exists and blocks ff00::/8" {
    assert_chain_exists_ip6 MCAST6
    assert_rule_exists_ip6 MCAST6 "ff00::/8"
}

@test "MCAST6 exempts NDP ICMPv6 from multicast block" {
    assert_rule_exists_ip6s MCAST6 "(ipv6-icmp|icmpv6).*RETURN"
}

@test "IPv6 trust add goes to ip6tables only" {
    "$APF" -u 2001:db8::50 2>/dev/null || true
    run "$APF" -a 2001:db8::50 "ipv6 test"
    assert_success

    # Should be in ip6tables TALLOW
    assert_rule_exists_ip6 TALLOW "2001:db8::50"

    # Should NOT be in iptables (IPv4) TALLOW
    assert_rule_not_exists TALLOW "2001:db8::50"

    "$APF" -u 2001:db8::50 2>/dev/null || true
}

@test "apf -u removes IPv6 host" {
    "$APF" -a 2001:db8::51 "ipv6 remove test" 2>/dev/null
    run "$APF" -u 2001:db8::51
    assert_success

    # Verify host entry line removed from file (anchor to line start; comments may remain)
    run grep "^2001:db8::51" "$APF_DIR/allow_hosts.rules"
    assert_failure
}

@test "ICMPv6 configured types accepted" {
    # Type 128 (echo-request) should be in the default IG_ICMPV6_TYPES
    assert_rule_exists_ip6 INPUT "ipv6-icmp.*type 128"
}
