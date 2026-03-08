#!/usr/bin/env bats
# 05-search-diagnostics.bats — APF Search & Diagnostics UAT
# Verifies: search allowed/denied/unknown IPs, validate, dump rules

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
    # Add entries for search tests
    apf -a 192.0.2.50 "search test allow"
    apf -d 192.0.2.51 "search test deny"
}

teardown_file() {
    apf -f 2>/dev/null || true   # flush: safe if already stopped
    uat_apf_reset
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: search finds allowed IP" {
    uat_capture "search" apf -g 192.0.2.50
    assert_success
    assert_output --partial "192.0.2.50"
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: search finds denied IP" {
    uat_capture "search" apf -g 192.0.2.51
    assert_success
    assert_output --partial "192.0.2.51"
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: search for unknown IP returns no matches" {
    uat_capture "search" apf -g 192.0.2.99
    # search returns 0 even with no matches (prints "no matches")
    assert_output --partial "192.0.2.99"
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: validate config passes" {
    uat_capture "diagnostics" apf --validate
    assert_success
    assert_output --partial "validated"
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: dump rules produces iptables output" {
    uat_capture "diagnostics" apf --rules
    assert_success
    # Should contain iptables -S style output
    assert_output --partial -- "-A"
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: list-allow shows allowed entries" {
    uat_capture "diagnostics" apf --la
    assert_success
    assert_output --partial "192.0.2.50"
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: list-deny shows denied entries" {
    uat_capture "diagnostics" apf --ld
    assert_success
    assert_output --partial "192.0.2.51"
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: lookup finds existing trust entry" {
    uat_capture "diagnostics" apf --lookup 192.0.2.50
    assert_success
}

# bats test_tags=uat,uat:search-diagnostics
@test "UAT: lookup for non-existent entry fails" {
    run apf --lookup 192.0.2.99
    assert_failure
}
