#!/usr/bin/env bats
# 04-firewall-lifecycle.bats — APF Firewall Lifecycle UAT
# Verifies: start, verify iptables loaded, add trust while running,
#           restart persistence, stop/flush

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../infra/lib/uat-helpers'

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
}

teardown_file() {
    apf -f 2>/dev/null || true   # flush: safe if already stopped
    uat_apf_reset
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:firewall-lifecycle
@test "UAT: firewall starts successfully" {
    uat_capture "fw-lifecycle" apf -s
    assert_success
}

# bats test_tags=uat,uat:firewall-lifecycle
@test "UAT: iptables has APF chains after start" {
    run iptables -S 2>/dev/null
    assert_success
    # APF creates custom chains like INPUT, TALLOW, TDENY
    assert_output --partial "TALLOW"
    assert_output --partial "TDENY"
}

# bats test_tags=uat,uat:firewall-lifecycle
@test "UAT: firewall info shows active status" {
    uat_capture "fw-lifecycle" apf --info
    assert_success
    assert_output --partial "Active:"
    assert_output --partial "yes"
}

# bats test_tags=uat,uat:firewall-lifecycle
@test "UAT: add trust while firewall is running" {
    uat_capture "fw-lifecycle" apf -a 192.0.2.40 "while running"
    assert_success
    run iptables -S TALLOW 2>/dev/null
    assert_output --partial "192.0.2.40"
}

# bats test_tags=uat,uat:firewall-lifecycle
@test "UAT: stop flushes all rules" {
    uat_capture "fw-lifecycle" apf -f
    assert_success
    # After flush, custom chains should be gone
    run iptables -S 2>/dev/null
    refute_output --partial "TALLOW"
    refute_output --partial "TDENY"
}

# bats test_tags=uat,uat:firewall-lifecycle
@test "UAT: firewall info shows inactive after stop" {
    uat_capture "fw-lifecycle" apf --info
    assert_success
    assert_output --partial "Active:"
    assert_output --partial "no"
}

# bats test_tags=uat,uat:firewall-lifecycle
@test "UAT: restart brings firewall back up" {
    uat_capture "fw-lifecycle" apf -r
    assert_success
    run iptables -S 2>/dev/null
    assert_output --partial "TALLOW"
}
