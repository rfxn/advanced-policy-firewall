#!/usr/bin/env bats
#
# 13: Refresh and ban expiry — apf -e, expirebans()

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
    apf_set_config "SET_REFRESH" "10"
    apf_set_config "SET_EXPIRE" "120"
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    # Clean test entries
    for pattern in "192.0.2" "198.51.100" "2001:db8"; do
        sed -i "/${pattern}/d" "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${pattern}/d" "$APF_DIR/deny_hosts.rules" 2>/dev/null || true
    done
    sed -i '/tcp:in:d=22/d' "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
}

teardown() {
    # Same cleanup on exit — prevents dirty state if test fails mid-execution
    for pattern in "192.0.2" "198.51.100" "2001:db8"; do
        sed -i "/${pattern}/d" "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${pattern}/d" "$APF_DIR/deny_hosts.rules" 2>/dev/null || true
    done
    sed -i '/tcp:in:d=22/d' "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
}

@test "apf -e with loaded rules succeeds" {
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    run "$APF" -e
    assert_success
}

@test "apf -e without loaded rules fails gracefully" {
    "$APF" -f 2>/dev/null || true
    run "$APF" -e
    # Should exit non-zero when no rules loaded
    assert_failure
}

@test "after refresh, trust entries still present" {
    echo "192.0.2.50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Verify entry exists
    assert_rule_exists_ips TALLOW "192.0.2.50"

    # Refresh
    "$APF" -e

    # Entry should still be present after refresh
    assert_rule_exists_ips TALLOW "192.0.2.50"
}

@test "expirebans removes expired deny entry" {
    # Add a deny entry with a timestamp from 2 days ago
    local old_date
    old_date=$(date -d "2 days ago" +"%D %H:%M:%S" 2>/dev/null || date -v-2d +"%D %H:%M:%S" 2>/dev/null)
    if [ -z "$old_date" ]; then
        skip "date -d not supported on this platform"
    fi
    echo "# added 192.0.2.51 on $old_date" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.51" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -e

    # Entry should be removed (SET_EXPIRE=120 seconds, entry is 2 days old)
    run grep "^192.0.2.51" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

@test "expirebans preserves non-expired deny entry" {
    # Add a deny entry with current timestamp
    local now
    now=$(date +"%D %H:%M:%S")
    echo "# added 192.0.2.52 on $now" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.52" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -e

    # Entry should still exist (not expired)
    run grep "^192.0.2.52" "$APF_DIR/deny_hosts.rules"
    assert_success
}

@test "expirebans preserves static entries" {
    # Add a deny entry marked as static
    echo "# added 192.0.2.53 on 01/01/20 00:00:00 static" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.53" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -e

    # Static entries should never be removed
    run grep "^192.0.2.53" "$APF_DIR/deny_hosts.rules"
    assert_success
}

@test "expirebans preserves noexpire entries" {
    echo "# added 192.0.2.54 on 01/01/20 00:00:00 noexpire" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.54" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -e

    run grep "^192.0.2.54" "$APF_DIR/deny_hosts.rules"
    assert_success
}

@test "refresh preserves IPv6 trust entries in REFRESH_TEMP" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"

    echo "2001:db8::50" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Verify entry exists in TALLOW
    assert_rule_exists_ip6s TALLOW "2001:db8::50"

    # Refresh — IPv6 entry should be protected in REFRESH_TEMP
    "$APF" -e

    # Entry should still be present after refresh
    assert_rule_exists_ip6s TALLOW "2001:db8::50"
}

@test "refresh skips advanced trust entries in REFRESH_TEMP" {
    echo "tcp:in:d=22:s=192.0.2.60" >> "$APF_DIR/allow_hosts.rules"
    echo "192.0.2.61" >> "$APF_DIR/allow_hosts.rules"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Both entries should exist in TALLOW
    assert_rule_exists_ips TALLOW "192.0.2.61"
    assert_rule_exists_ips TALLOW "192.0.2.60"

    # Refresh
    "$APF" -e

    # Bare IP should survive (protected by REFRESH_TEMP)
    assert_rule_exists_ips TALLOW "192.0.2.61"
    # Advanced trust entry should also survive (reloaded from trust file)
    assert_rule_exists_ips TALLOW "192.0.2.60"
}

@test "expirebans removes expired entry with addedtime= marker" {
    # Add a deny entry with addedtime= from 2 days ago
    local old_epoch
    old_epoch=$(($(date +%s) - 172800))
    echo "# added 192.0.2.70 on 01/01/20 00:00:00 addedtime=$old_epoch" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.70" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -e

    # Both the IP line and comment line should be removed
    run grep "192.0.2.70" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

@test "expirebans preserves non-expired entry with addedtime=" {
    # Add a deny entry with current addedtime=
    local now_epoch
    now_epoch=$(date +%s)
    echo "# added 192.0.2.71 on $(date +"%D %H:%M:%S") addedtime=$now_epoch" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.71" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -e

    # Entry should still exist (not expired)
    run grep "^192.0.2.71" "$APF_DIR/deny_hosts.rules"
    assert_success
}

@test "expirebans handles legacy entry without addedtime=" {
    # Add an old-format entry (no addedtime= marker) from 2 days ago
    local old_date
    old_date=$(date -d "2 days ago" +"%D %H:%M:%S" 2>/dev/null || date -v-2d +"%D %H:%M:%S" 2>/dev/null)
    if [ -z "$old_date" ]; then
        skip "date -d not supported on this platform"
    fi
    echo "# added 192.0.2.72 on $old_date" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.72" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -e

    # Entry should be removed via legacy date --date fallback
    run grep "192.0.2.72" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

@test "expirebans removes comment line alongside IP line" {
    # Add a deny entry with both comment and IP lines
    local old_epoch
    old_epoch=$(($(date +%s) - 172800))
    echo "# added 192.0.2.73 on 01/01/20 00:00:00 addedtime=$old_epoch with comment: test entry" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.73" >> "$APF_DIR/deny_hosts.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -e

    # Both the comment and bare IP should be gone
    run grep "# added 192.0.2.73" "$APF_DIR/deny_hosts.rules"
    assert_failure
    run grep "^192.0.2.73$" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

@test "cli_trust -d writes addedtime= marker" {
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    "$APF" -d 192.0.2.74 "test addedtime marker"

    # Verify addedtime= marker is present and numeric
    run grep "addedtime=" "$APF_DIR/deny_hosts.rules"
    assert_success
    # Extract the epoch value and verify it's numeric
    local epoch_val
    epoch_val=$(grep "192.0.2.74" "$APF_DIR/deny_hosts.rules" | grep -o 'addedtime=[0-9]*' | head -1 | cut -d= -f2)
    [ -n "$epoch_val" ]
    # Verify it's a reasonable epoch (after year 2020)
    [ "$epoch_val" -gt 1577836800 ]
}

# =====================================================================
# Cron lifecycle tests (C-004)
# =====================================================================

@test "cron_refresh creates refresh.apf when SET_REFRESH enabled" {
    if [ ! -d "/etc/cron.d" ]; then
        skip "cron.d not available"
    fi
    rm -f /etc/cron.d/refresh.apf
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_REFRESH" "10"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    [ -f "/etc/cron.d/refresh.apf" ]
}

@test "cron_refresh removes refresh.apf when SET_REFRESH=0" {
    if [ ! -d "/etc/cron.d" ]; then
        skip "cron.d not available"
    fi
    # Create a stale refresh cron to verify cleanup
    echo "*/10 * * * * root /opt/apf/apf --refresh >> /dev/null 2>&1 &" > /etc/cron.d/refresh.apf
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_REFRESH" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    [ ! -f "/etc/cron.d/refresh.apf" ]
}

@test "flush removes refresh.apf" {
    if [ ! -d "/etc/cron.d" ]; then
        skip "cron.d not available"
    fi
    # Create refresh cron then flush
    echo "*/10 * * * * root /opt/apf/apf --refresh >> /dev/null 2>&1 &" > /etc/cron.d/refresh.apf
    "$APF" -f
    [ ! -f "/etc/cron.d/refresh.apf" ]
}
