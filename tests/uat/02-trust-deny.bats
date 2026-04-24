#!/usr/bin/env bats
# 02-trust-deny.bats — APF Deny Lifecycle UAT
# Verifies: deny host, verify file+live, CIDR, remove, verify clean

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

# bats test_tags=uat,uat:trust-deny
@test "UAT: deny single IP adds to deny_hosts.rules" {
    uat_capture "trust-deny" apf -d 192.0.2.20 "UAT test deny"
    assert_success
    run grep -c 192.0.2.20 /opt/apf/deny_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:trust-deny
@test "UAT: denied IP is live in iptables TDENY chain" {
    run iptables -S TDENY 2>/dev/null
    assert_success
    assert_output --partial "192.0.2.20"
}

# bats test_tags=uat,uat:trust-deny
@test "UAT: deny CIDR block succeeds" {
    uat_capture "trust-deny" apf -d 198.51.100.0/24 "UAT CIDR deny"
    assert_success
    run grep -c "198.51.100.0/24" /opt/apf/deny_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:trust-deny
@test "UAT: CIDR deny is live in iptables" {
    run iptables -S TDENY 2>/dev/null
    assert_success
    assert_output --partial "198.51.100.0/24"
}

# bats test_tags=uat,uat:trust-deny
@test "UAT: remove denied IP cleans file and iptables" {
    uat_capture "trust-deny" apf -u 192.0.2.20
    assert_success
    # Verify removed from file
    run grep -c 192.0.2.20 /opt/apf/deny_hosts.rules
    assert_failure
    # Verify removed from iptables
    run iptables -S TDENY 2>/dev/null
    refute_output --partial "192.0.2.20"
}

# bats test_tags=uat,uat:trust-deny
@test "UAT: deny with comment preserves comment in file" {
    uat_capture "trust-deny" apf -d 192.0.2.21 "UAT comment check"
    assert_success
    run grep "UAT comment check" /opt/apf/deny_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:trust-deny
@test "UAT: duplicate deny reports already exists" {
    uat_capture "trust-deny" apf -d 192.0.2.21 "duplicate"
    assert_success
    assert_output --partial "already exists"
}
