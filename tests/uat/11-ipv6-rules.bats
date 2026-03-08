#!/usr/bin/env bats
# 11-ipv6-rules.bats -- APF IPv6 Rules UAT
# Verifies: USE_IPV6=1 with ip6tables chain creation, IPv6 trust entry,
# dual-stack chain parity. EVERY test uses ip6tables_available() skip guard.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../helpers/assert-iptables'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
    # Only enable IPv6 if ip6tables is available in this environment
    if ! ip6tables_available; then
        # Write marker so individual tests can skip consistently
        export _UAT_IPV6_UNAVAILABLE=1
        return 0
    fi
    uat_apf_enable_ipv6
    apf -s
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:ipv6
@test "UAT: ip6tables has APF chains when USE_IPV6=1" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    assert_chain_exists_ip6 "TALLOW"
    assert_chain_exists_ip6 "TDENY"
}

# bats test_tags=uat,uat:ipv6
@test "UAT: IPv6 trust entry adds to allow file and ip6tables" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    uat_capture "ipv6" apf -a 2001:db8::10 "UAT IPv6 allow"
    assert_success
    run grep -c "2001:db8::10" /opt/apf/allow_hosts.rules
    assert_success
    assert_rule_exists_ip6s TALLOW "2001:db8::10"
}

# bats test_tags=uat,uat:ipv6
@test "UAT: IPv6 trust removal cleans file and ip6tables" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    uat_capture "ipv6" apf -u 2001:db8::10
    assert_success
    run grep -c "2001:db8::10" /opt/apf/allow_hosts.rules
    assert_failure
    run ip6tables -S TALLOW 2>/dev/null
    refute_output --partial "2001:db8::10"
}

# bats test_tags=uat,uat:ipv6
@test "UAT: dual-stack: both iptables and ip6tables have TALLOW chain" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    # IPv4 chain
    assert_chain_exists "TALLOW"
    # IPv6 chain
    assert_chain_exists_ip6 "TALLOW"
}

# bats test_tags=uat,uat:ipv6
@test "UAT: info shows IPv6 enabled when USE_IPV6=1" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    uat_capture "ipv6" apf --info
    assert_success
    assert_output --partial "IPv6:"
    assert_output --partial "enabled"
}
