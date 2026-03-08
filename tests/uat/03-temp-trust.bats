#!/usr/bin/env bats
# 03-temp-trust.bats — APF Temporary Trust UAT
# Verifies: temp allow/deny with TTL, list, flush

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

# bats test_tags=uat,uat:temp-trust
@test "UAT: temp allow with TTL succeeds" {
    uat_capture "temp-trust" apf -ta 192.0.2.30 1h "UAT temp allow"
    assert_success
}

# bats test_tags=uat,uat:temp-trust
@test "UAT: temp allowed IP in allow_hosts.rules with ttl marker" {
    run grep "192.0.2.30" /opt/apf/allow_hosts.rules
    assert_success
    assert_output --partial "ttl="
}

# bats test_tags=uat,uat:temp-trust
@test "UAT: temp deny with TTL succeeds" {
    uat_capture "temp-trust" apf -td 192.0.2.31 7d "UAT temp deny"
    assert_success
}

# bats test_tags=uat,uat:temp-trust
@test "UAT: temp denied IP in deny_hosts.rules with ttl marker" {
    run grep "192.0.2.31" /opt/apf/deny_hosts.rules
    assert_success
    assert_output --partial "ttl="
}

# bats test_tags=uat,uat:temp-trust
@test "UAT: temp list shows both entries with remaining TTL" {
    uat_capture "temp-trust" apf --templ
    assert_success
    assert_output --partial "192.0.2.30"
    assert_output --partial "192.0.2.31"
    assert_output --partial "remains="
}

# bats test_tags=uat,uat:temp-trust
@test "UAT: temp flush removes all temp entries" {
    uat_capture "temp-trust" apf --tempf
    assert_success
    assert_output --partial "flushed"
    assert_output --partial "temporary trust entries"
    # Verify entries are gone from files
    run grep "ttl=.*expire=" /opt/apf/allow_hosts.rules /opt/apf/deny_hosts.rules
    assert_failure
}

# bats test_tags=uat,uat:temp-trust
@test "UAT: temp list shows no entries after flush" {
    uat_capture "temp-trust" apf --templ
    assert_success
    assert_output --partial "No temporary entries"
}
