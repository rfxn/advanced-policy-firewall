#!/usr/bin/env bats
# 06-restart-persistence.bats — APF Restart Persistence UAT
# Verifies: start, add trust, restart, verify file+iptables survival

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
    apf -f 2>/dev/null || true   # flush: safe if already stopped
    uat_apf_reset
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:restart-persistence
@test "UAT: add allow entry before restart" {
    uat_capture "restart" apf -a 192.0.2.60 "persist allow"
    assert_success
    run grep -c 192.0.2.60 /opt/apf/allow_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:restart-persistence
@test "UAT: add deny entry before restart" {
    uat_capture "restart" apf -d 192.0.2.61 "persist deny"
    assert_success
    run grep -c 192.0.2.61 /opt/apf/deny_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:restart-persistence
@test "UAT: restart succeeds" {
    uat_capture "restart" apf -r
    assert_success
}

# bats test_tags=uat,uat:restart-persistence
@test "UAT: allow entry survives restart in file" {
    run grep -c 192.0.2.60 /opt/apf/allow_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:restart-persistence
@test "UAT: allow entry survives restart in iptables" {
    run iptables -S TALLOW 2>/dev/null
    assert_success
    assert_output --partial "192.0.2.60"
}

# bats test_tags=uat,uat:restart-persistence
@test "UAT: deny entry survives restart in file" {
    run grep -c 192.0.2.61 /opt/apf/deny_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:restart-persistence
@test "UAT: deny entry survives restart in iptables" {
    run iptables -S TDENY 2>/dev/null
    assert_success
    assert_output --partial "192.0.2.61"
}

# bats test_tags=uat,uat:restart-persistence
@test "UAT: APF chains intact after restart" {
    run iptables -S 2>/dev/null
    assert_success
    assert_output --partial "TALLOW"
    assert_output --partial "TDENY"
}
