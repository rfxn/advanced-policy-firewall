#!/usr/bin/env bats
#
# 09: Flush removes rules, policies reset to ACCEPT

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_config "PKT_SANITY" "1"
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "flush removes rules from built-in chains" {
    "$APF" -s
    # Verify rules exist first
    assert_chain_exists TALLOW
    local before
    before=$(iptables -S INPUT | grep -c '^-A' || true)
    [ "$before" -gt 0 ]

    "$APF" -f

    # After flush, INPUT should have no rules (chain jumps, port rules all gone)
    local after
    after=$(iptables -S INPUT | grep -c '^-A' || true)
    [ "$after" -eq 0 ]
}

@test "flush after start resets all state" {
    "$APF" -s
    "$APF" -f

    # All built-in chain policies reset to ACCEPT
    assert_chain_policy INPUT ACCEPT
    assert_chain_policy OUTPUT ACCEPT
    assert_chain_policy FORWARD ACCEPT

    # No filter rules remain
    local rule_count
    rule_count=$(iptables -S | grep -c '^-A' || true)
    [ "$rule_count" -eq 0 ]

    # Mangle table cleared
    rule_count=$(iptables -t mangle -S | grep -c '^-A' || true)
    [ "$rule_count" -eq 0 ]
}

@test "start-flush-start creates chains cleanly" {
    "$APF" -s
    "$APF" -f
    "$APF" -s

    # All chains should be recreated without errors
    assert_chain_exists TALLOW
    assert_chain_exists TDENY
    assert_chain_exists RESET
    assert_chain_exists PROHIBIT

    "$APF" -f
}

@test "USE_IPV6=1 flush also clears ip6tables" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    "$APF" -s

    # Verify IPv6 chains exist
    assert_chain_exists_ip6 TALLOW

    "$APF" -f

    # IPv6 should have no rules after flush
    local rule_count
    rule_count=$(ip6tables -S | grep -c '^-A' || true)
    [ "$rule_count" -eq 0 ]

    # IPv6 policies should be ACCEPT
    assert_chain_policy_ip6 INPUT ACCEPT
    assert_chain_policy_ip6 OUTPUT ACCEPT

    apf_set_config "USE_IPV6" "0"
}
