#!/usr/bin/env bats
#
# 29: Block escalation (PERMBLOCK) — auto-promote repeat temp denies
#
# Validates PERMBLOCK_COUNT/PERMBLOCK_INTERVAL configuration,
# record_block/check_block_escalation/escalate_to_permanent functions,
# and integration with cli_trust_temp.

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
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    source /opt/tests/helpers/apf-config.sh
    # Clean up test IPs from trust files and iptables
    for host in 192.0.2.60 192.0.2.61 192.0.2.62 192.0.2.63 "2001:db8::60"; do
        local escaped
        escaped=$(echo "$host" | sed 's/[.\/\:]/\\&/g')
        sed -i "/${escaped}/d" "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${escaped}/d" "$APF_DIR/deny_hosts.rules" 2>/dev/null || true
    done
    iptables -F TALLOW 2>/dev/null || true
    iptables -F TDENY 2>/dev/null || true
    if ip6tables_available; then
        ip6tables -F TALLOW 2>/dev/null || true
        ip6tables -F TDENY 2>/dev/null || true
    fi
    rm -f "$APF_DIR/internals/.block_history"
    # Reset PERMBLOCK to disabled
    apf_set_config "PERMBLOCK_COUNT" "0"
    apf_set_config "PERMBLOCK_INTERVAL" "86400"
}

# =====================================================================
# PERMBLOCK disabled (default)
# =====================================================================

@test "PERMBLOCK disabled by default — no escalation on repeat temp deny" {
    # PERMBLOCK_COUNT=0 (default), so no escalation should happen
    "$APF" -td 192.0.2.60 1h "deny1"
    # Clean up the temp entry to allow re-adding
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.60 1h "deny2"
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.60 1h "deny3"

    # Should NOT have block_history file (feature disabled)
    [ ! -f "$APF_DIR/internals/.block_history" ]

    # Entry should still be temporary, not permanent
    run grep "192.0.2.60.*ttl=.*expire=" "$APF_DIR/deny_hosts.rules"
    assert_success
    run grep "static noexpire" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

# =====================================================================
# PERMBLOCK enabled — counting
# =====================================================================

@test "PERMBLOCK_COUNT=3 — 2 temp denies, no escalation yet" {
    apf_set_config "PERMBLOCK_COUNT" "3"

    "$APF" -td 192.0.2.60 1h "deny1"
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.60 1h "deny2"

    # Block history should have count=2
    run grep -F "192.0.2.60|" "$APF_DIR/internals/.block_history"
    assert_success
    assert_output --partial "192.0.2.60|2|"

    # Should still be temporary
    run grep "192.0.2.60.*ttl=.*expire=" "$APF_DIR/deny_hosts.rules"
    assert_success
    run grep "static noexpire.*PERMBLOCK" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

@test "PERMBLOCK_COUNT=3 — 3rd temp deny triggers escalation" {
    apf_set_config "PERMBLOCK_COUNT" "3"

    "$APF" -td 192.0.2.60 1h "deny1"
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.60 1h "deny2"
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.60 1h "deny3"

    # Should have been escalated to permanent
    run grep "static noexpire.*auto-escalated.*PERMBLOCK" "$APF_DIR/deny_hosts.rules"
    assert_success
    run grep "^192.0.2.60$" "$APF_DIR/deny_hosts.rules"
    assert_success

    # Temp markers should be gone
    run grep "192.0.2.60.*ttl=.*expire=" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

# =====================================================================
# Block history
# =====================================================================

@test "block history file format is IP|count|first_epoch|last_epoch" {
    apf_set_config "PERMBLOCK_COUNT" "5"

    "$APF" -td 192.0.2.60 1h "test"

    run cat "$APF_DIR/internals/.block_history"
    assert_success
    # Format: IP|count|epoch|epoch
    local pat='^192\.0\.2\.60\|1\|[0-9]+\|[0-9]+$'
    [[ "$output" =~ $pat ]]
}

@test "block history prunes stale entries outside PERMBLOCK_INTERVAL" {
    apf_set_config "PERMBLOCK_COUNT" "3"
    apf_set_config "PERMBLOCK_INTERVAL" "60"

    # Inject a stale history entry (first_epoch far in the past)
    local stale_epoch=$(($(date +%s) - 3600))
    echo "192.0.2.61|2|${stale_epoch}|${stale_epoch}" > "$APF_DIR/internals/.block_history"

    # Add a new temp deny for a different IP — triggers history rewrite
    "$APF" -td 192.0.2.62 1h "trigger"

    # Stale entry should have been pruned
    run grep -F "192.0.2.61|" "$APF_DIR/internals/.block_history"
    assert_failure

    # New entry should exist
    run grep -F "192.0.2.62|" "$APF_DIR/internals/.block_history"
    assert_success
}

# =====================================================================
# Escalation details
# =====================================================================

@test "escalated entry has static noexpire markers (exempt from expirebans)" {
    apf_set_config "PERMBLOCK_COUNT" "2"

    "$APF" -td 192.0.2.60 1h "deny1"
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.60 1h "deny2"

    # Check for permanent markers
    run grep "static noexpire" "$APF_DIR/deny_hosts.rules"
    assert_success
    assert_output --partial "auto-escalated from temp deny (PERMBLOCK)"
}

@test "escalation removes entry from block history" {
    apf_set_config "PERMBLOCK_COUNT" "2"

    "$APF" -td 192.0.2.60 1h "deny1"
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.60 1h "deny2"

    # After escalation, IP should be removed from history
    if [ -f "$APF_DIR/internals/.block_history" ]; then
        run grep -F "192.0.2.60|" "$APF_DIR/internals/.block_history"
        assert_failure
    fi
}

@test "escalation log message present in LOG_APF" {
    apf_set_config "PERMBLOCK_COUNT" "2"

    "$APF" -td 192.0.2.60 1h "deny1"
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.60 1h "deny2"

    run grep "auto-escalated to permanent deny" /var/log/apf_log
    assert_success
    assert_output --partial "PERMBLOCK_COUNT=2"
}

# =====================================================================
# Flush cleanup
# =====================================================================

@test "flush clears block history file" {
    apf_set_config "PERMBLOCK_COUNT" "5"

    "$APF" -td 192.0.2.60 1h "test"
    [ -f "$APF_DIR/internals/.block_history" ]

    "$APF" -f

    [ ! -f "$APF_DIR/internals/.block_history" ]

    # Restart for subsequent tests
    "$APF" -s
}

# =====================================================================
# IPv6
# =====================================================================

@test "IPv6 address block escalation" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    apf_set_config "PERMBLOCK_COUNT" "2"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    "$APF" -td "2001:db8::60" 1h "v6deny1"
    "$APF" -u "2001:db8::60"
    "$APF" -td "2001:db8::60" 1h "v6deny2"

    # Should be escalated
    run grep "static noexpire.*auto-escalated.*PERMBLOCK" "$APF_DIR/deny_hosts.rules"
    assert_success
    run grep "^2001:db8::60$" "$APF_DIR/deny_hosts.rules"
    assert_success

    # Restore non-IPv6 state
    apf_set_config "USE_IPV6" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

# =====================================================================
# Validation
# =====================================================================

@test "PERMBLOCK_INTERVAL < 60 rejected by validate_config" {
    apf_set_config "PERMBLOCK_COUNT" "3"
    apf_set_config "PERMBLOCK_INTERVAL" "30"
    "$APF" -f 2>/dev/null || true

    run "$APF" -s
    assert_failure
    assert_output --partial "PERMBLOCK_INTERVAL must be at least 60 seconds"

    # Restore valid config
    apf_set_config "PERMBLOCK_COUNT" "0"
    apf_set_config "PERMBLOCK_INTERVAL" "86400"
    "$APF" -s
}

# =====================================================================
# Multiple IPs
# =====================================================================

@test "multiple IPs tracked independently in block history" {
    apf_set_config "PERMBLOCK_COUNT" "3"

    "$APF" -td 192.0.2.60 1h "ip1-deny1"
    "$APF" -u 192.0.2.60
    "$APF" -td 192.0.2.61 1h "ip2-deny1"

    # Both should be in history with count=1
    run grep -F "192.0.2.60|1|" "$APF_DIR/internals/.block_history"
    assert_success
    run grep -F "192.0.2.61|1|" "$APF_DIR/internals/.block_history"
    assert_success
}
