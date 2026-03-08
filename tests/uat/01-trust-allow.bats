#!/usr/bin/env bats
# 01-trust-allow.bats — APF Trust Lifecycle (Allow) UAT
# Verifies: add allow, verify file+live, CIDR, remove, re-add

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
    apf -s
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:trust-allow
@test "UAT: allow single IP adds to allow_hosts.rules" {
    uat_capture "trust-allow" apf -a 192.0.2.10 "UAT test allow"
    assert_success
    run grep -c 192.0.2.10 /opt/apf/allow_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:trust-allow
@test "UAT: allowed IP is live in iptables TALLOW chain" {
    run iptables -S TALLOW 2>/dev/null
    assert_success
    assert_output --partial "192.0.2.10"
}

# bats test_tags=uat,uat:trust-allow
@test "UAT: allow CIDR block succeeds" {
    uat_capture "trust-allow" apf -a 198.51.100.0/24 "UAT CIDR allow"
    assert_success
    run grep -c "198.51.100.0/24" /opt/apf/allow_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:trust-allow
@test "UAT: CIDR allow is live in iptables" {
    run iptables -S TALLOW 2>/dev/null
    assert_success
    assert_output --partial "198.51.100.0/24"
}

# bats test_tags=uat,uat:trust-allow
@test "UAT: remove allowed IP cleans file and iptables" {
    uat_capture "trust-allow" apf -u 192.0.2.10
    assert_success
    # Verify removed from file
    run grep -c 192.0.2.10 /opt/apf/allow_hosts.rules
    assert_failure
    # Verify removed from iptables
    run iptables -S TALLOW 2>/dev/null
    refute_output --partial "192.0.2.10"
}

# bats test_tags=uat,uat:trust-allow
@test "UAT: re-add previously removed IP succeeds" {
    uat_capture "trust-allow" apf -a 192.0.2.10 "UAT re-add"
    assert_success
    run grep -c 192.0.2.10 /opt/apf/allow_hosts.rules
    assert_success
    run iptables -S TALLOW 2>/dev/null
    assert_output --partial "192.0.2.10"
}

# bats test_tags=uat,uat:trust-allow
@test "UAT: duplicate allow reports already exists" {
    uat_capture "trust-allow" apf -a 192.0.2.10 "duplicate"
    assert_success
    assert_output --partial "already exists"
}

# bats test_tags=uat,uat:trust-allow
@test "UAT: allow with comment preserves comment in file" {
    run grep "UAT re-add" /opt/apf/allow_hosts.rules
    assert_success
}
