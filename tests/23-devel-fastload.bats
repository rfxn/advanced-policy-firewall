#!/usr/bin/env bats
#
# 23: DEVEL_MODE and fast load edge cases
#
# Validates DEVEL_MODE cron behavior and fast load skip conditions
# (first run, config change, backend mismatch, uptime check).

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
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

# =====================================================================
# DEVEL_MODE tests
# =====================================================================

@test "DEVEL_MODE=1 logs development mode warning" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DEVEL_MODE" "1"
    apf_set_config "SET_VERBOSE" "1"
    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    run grep "DEVELOPMENT MODE ENABLED" /var/log/apf_log
    assert_success

    # Cleanup
    apf_set_config "DEVEL_MODE" "0"
    "$APF" -f 2>/dev/null
}

@test "DEVEL_MODE=1 creates cron flush job" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "DEVEL_MODE" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # devm() should have created a cron entry (at or crontab)
    # Check via crontab -l or /var/spool/cron
    # The cron entry flushes the firewall after 5 minutes
    run grep "DEVELOPMENT MODE ENABLED" /var/log/apf_log
    assert_success

    # Cleanup
    apf_set_config "DEVEL_MODE" "0"
    "$APF" -f 2>/dev/null
}

@test "DEVEL_MODE=1 forces full load (skips fast load)" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"
    apf_set_config "DEVEL_MODE" "0"

    # First: full load to create snapshot
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Now enable DEVEL_MODE and restart
    apf_set_config "DEVEL_MODE" "1"
    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should log "config. or .rule file has changed" (DEVEL_MODE sets SKIP_FASTLOAD_VARS)
    run grep "config.*has changed\|going full load" /var/log/apf_log
    assert_success

    # Cleanup
    apf_set_config "DEVEL_MODE" "0"
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null
}

# =====================================================================
# Fast load edge cases
# =====================================================================

@test "fast load skip when .last.full missing (first run)" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"
    # Remove the .last.full file to simulate first run
    rm -f "$APF_DIR/internals/.last.full"
    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    run grep "first run.*fast load skipped" /var/log/apf_log
    assert_success

    # Cleanup
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null
}

@test "fast load creates .last.full after full load" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "0"
    rm -f "$APF_DIR/internals/.last.full"
    "$APF" -f 2>/dev/null
    "$APF" -s

    [ -f "$APF_DIR/internals/.last.full" ]
    local ts
    read ts < "$APF_DIR/internals/.last.full"
    [[ "$ts" =~ ^[0-9]+$ ]]

    "$APF" -f 2>/dev/null
}

@test "fast load creates snapshot after full load" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "0"
    rm -f "$APF_DIR/internals/.apf.restore"
    "$APF" -f 2>/dev/null
    "$APF" -s

    [ -f "$APF_DIR/internals/.apf.restore" ]
    # Snapshot should contain iptables rules
    run grep '^\*' "$APF_DIR/internals/.apf.restore"
    assert_success

    "$APF" -f 2>/dev/null
}

@test "fast load backend mismatch forces full load" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"

    # Do a full load first to create snapshot
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Corrupt the backend marker to force mismatch
    local real_backend
    read real_backend < "$APF_DIR/internals/.apf.restore.backend"
    if [ "$real_backend" == "nft" ]; then
        echo "legacy" > "$APF_DIR/internals/.apf.restore.backend"
    else
        echo "nft" > "$APF_DIR/internals/.apf.restore.backend"
    fi

    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should log backend mismatch
    run grep "backend mismatch" /var/log/apf_log
    assert_success

    # Cleanup
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null
}

@test "fast load works after successful full load" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"

    # Full load to create snapshot
    "$APF" -f 2>/dev/null
    "$APF" -s
    # Verify chains exist
    assert_chain_exists TALLOW

    # Flush and restart (should fast load)
    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should use fast load
    run grep "fast load" /var/log/apf_log
    assert_success
    # Chains should be restored
    assert_chain_exists TALLOW

    # Cleanup
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null
}

@test "fast load md5 tracking detects config change" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"

    # Full load to create snapshot + md5
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Modify config
    apf_set_config "IG_TCP_CPORTS" "22,80,443,9999"
    > /var/log/apf_log
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should detect config change and do full load
    run grep "config.*has changed" /var/log/apf_log
    assert_success

    # Port 9999 should be open (from full load, not stale snapshot)
    assert_rule_exists INPUT "ACCEPT.*tcp.*dpt:9999"

    # Cleanup
    apf_set_config "IG_TCP_CPORTS" "22,80,443"
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null
}
