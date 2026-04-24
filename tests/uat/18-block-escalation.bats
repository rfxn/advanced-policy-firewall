#!/usr/bin/env bats
# 18-block-escalation.bats — APF Block Escalation (PERMBLOCK) UAT
# Validates: repeated temp denies escalate to permanent, threshold behavior,
# escalated entries survive temp flush, different IPs tracked independently.

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
    # Enable block escalation: 3 temp denies within 86400s → permanent
    uat_apf_set_config "PERMBLOCK_COUNT" "3"
    uat_apf_set_config "PERMBLOCK_INTERVAL" "86400"
    apf -s
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

teardown() {
    # Clean up test IPs between tests
    apf -u 198.51.100.130 2>/dev/null || true  # cleanup
    apf -u 198.51.100.131 2>/dev/null || true  # cleanup
    rm -f /opt/apf/internals/.block_history
}

# =========================================================================
# UAT-BE01: Block history is tracked for temp denies
# Scenario: Sysadmin temp-denies an IP — system records it for escalation
# =========================================================================

# bats test_tags=uat,uat:block-escalation
@test "UAT: temp deny records entry in block history" {
    uat_capture "block-esc" apf -td 198.51.100.130 1h "first offense"
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.130"

    # Block history file should exist and contain the IP
    [ -f /opt/apf/internals/.block_history ]
    run grep "198.51.100.130" /opt/apf/internals/.block_history
    assert_success
}

# =========================================================================
# UAT-BE02: Below threshold does NOT escalate
# Scenario: 2 temp denies with threshold of 3 — must stay temporary
# =========================================================================

# bats test_tags=uat,uat:block-escalation
@test "UAT: temp deny below threshold remains temporary" {
    # First temp deny
    apf -td 198.51.100.130 1h "offense 1" 2>/dev/null
    apf -u 198.51.100.130 2>/dev/null || true  # cleanup
    # Second temp deny
    apf -td 198.51.100.130 1h "offense 2" 2>/dev/null

    # Entry should still be temporary (has ttl marker)
    run grep "198.51.100.130" /opt/apf/deny_hosts.rules
    assert_success
    run grep "ttl=" /opt/apf/deny_hosts.rules
    assert_success

    # Should NOT have "PERMBLOCK" / "static noexpire" marker
    run grep "PERMBLOCK" /opt/apf/deny_hosts.rules
    assert_failure
}

# =========================================================================
# UAT-BE03: At threshold, escalation triggers permanent deny
# Scenario: 3rd temp deny crosses threshold — entry becomes permanent
# =========================================================================

# bats test_tags=uat,uat:block-escalation
@test "UAT: third temp deny triggers escalation to permanent" {
    # Simulate 3 temp denies (remove between each to allow re-add)
    apf -td 198.51.100.130 1h "offense 1" 2>/dev/null
    apf -u 198.51.100.130 2>/dev/null || true  # cleanup

    apf -td 198.51.100.130 1h "offense 2" 2>/dev/null
    apf -u 198.51.100.130 2>/dev/null || true  # cleanup

    uat_capture "block-esc" apf -td 198.51.100.130 1h "offense 3"
    assert_success

    # Entry should now be permanent (static noexpire with PERMBLOCK comment)
    run grep "PERMBLOCK" /opt/apf/deny_hosts.rules
    assert_success
    run grep "static noexpire" /opt/apf/deny_hosts.rules
    assert_success
}

# =========================================================================
# UAT-BE04: Escalated entry survives temp flush
# Scenario: Sysadmin flushes temp entries — escalated permanent stays
# =========================================================================

# bats test_tags=uat,uat:block-escalation
@test "UAT: escalated permanent entry survives temp flush" {
    # Set up escalated entry
    apf -td 198.51.100.131 1h "o1" 2>/dev/null
    apf -u 198.51.100.131 2>/dev/null || true  # cleanup
    apf -td 198.51.100.131 1h "o2" 2>/dev/null
    apf -u 198.51.100.131 2>/dev/null || true  # cleanup
    apf -td 198.51.100.131 1h "o3" 2>/dev/null

    # Verify escalated
    run grep "198.51.100.131" /opt/apf/deny_hosts.rules
    assert_success
    run grep "static noexpire" /opt/apf/deny_hosts.rules
    assert_success

    # Flush temp entries
    uat_capture "block-esc" apf --tempf
    assert_success

    # Escalated entry must survive (it's permanent now)
    run grep "198.51.100.131" /opt/apf/deny_hosts.rules
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.131"
}

# =========================================================================
# UAT-BE05: Different IPs tracked independently
# Scenario: Two different attackers — each has their own counter
# =========================================================================

# bats test_tags=uat,uat:block-escalation
@test "UAT: block escalation tracks IPs independently" {
    # One temp deny for IP .130
    apf -td 198.51.100.130 1h "ip130 offense" 2>/dev/null

    # Two temp denies for IP .131
    apf -td 198.51.100.131 1h "ip131 offense 1" 2>/dev/null
    apf -u 198.51.100.131 2>/dev/null || true  # cleanup
    apf -td 198.51.100.131 1h "ip131 offense 2" 2>/dev/null

    # Neither should be escalated (both below threshold of 3)
    run grep "PERMBLOCK" /opt/apf/deny_hosts.rules
    assert_failure

    # Verify history has both IPs tracked
    run grep "198.51.100.130" /opt/apf/internals/.block_history
    assert_success
    run grep "198.51.100.131" /opt/apf/internals/.block_history
    assert_success
}

# =========================================================================
# UAT-BE06: PERMBLOCK_COUNT=0 disables escalation
# =========================================================================

# bats test_tags=uat,uat:block-escalation
@test "UAT: PERMBLOCK_COUNT=0 disables block escalation entirely" {
    uat_apf_set_config "PERMBLOCK_COUNT" "0"
    apf -r 2>/dev/null

    # Multiple temp denies should NOT create block history
    apf -td 198.51.100.130 1h "no escalation 1" 2>/dev/null
    apf -u 198.51.100.130 2>/dev/null || true  # cleanup
    apf -td 198.51.100.130 1h "no escalation 2" 2>/dev/null
    apf -u 198.51.100.130 2>/dev/null || true  # cleanup
    apf -td 198.51.100.130 1h "no escalation 3" 2>/dev/null

    # No PERMBLOCK escalation should occur
    run grep "PERMBLOCK" /opt/apf/deny_hosts.rules
    assert_failure

    # Entry should still be temporary
    run grep "ttl=" /opt/apf/deny_hosts.rules
    assert_success

    # Restore
    uat_apf_set_config "PERMBLOCK_COUNT" "3"
}
