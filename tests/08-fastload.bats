#!/usr/bin/env bats
#
# 08: Fast load — snapshot creation, backend marker

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null || true
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "full load creates .apf.restore snapshot" {
    "$APF" -s
    [ -f "$APF_DIR/internals/.apf.restore" ]
}

@test "full load creates .last.full timestamp" {
    [ -f "$APF_DIR/internals/.last.full" ]
    # Content should be a unix timestamp
    local ts
    ts=$(cat "$APF_DIR/internals/.last.full")
    [[ "$ts" =~ ^[0-9]+$ ]]
}

@test "full load creates .apf.restore.backend marker" {
    [ -f "$APF_DIR/internals/.apf.restore.backend" ]
}

@test "backend marker is legacy or nft" {
    local marker
    marker=$(cat "$APF_DIR/internals/.apf.restore.backend")
    [[ "$marker" == "legacy" || "$marker" == "nft" ]]
}

@test "snapshot is valid iptables-restore format" {
    # iptables-restore format starts with * (table) or : (chain) lines
    run head -5 "$APF_DIR/internals/.apf.restore"
    assert_success
    # Should contain a table marker like *filter or *mangle
    run grep '^\*' "$APF_DIR/internals/.apf.restore"
    assert_success
}

@test "snapshot contains expected chains" {
    run grep "TALLOW" "$APF_DIR/internals/.apf.restore"
    assert_success
    run grep "TDENY" "$APF_DIR/internals/.apf.restore"
    assert_success
}

@test "USE_IPV6=1 full load creates valid .apf6.restore with expected chains" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Snapshot file exists
    [ -f "$APF_DIR/internals/.apf6.restore" ]

    # Valid ip6tables-restore format (contains table marker)
    run grep '^\*' "$APF_DIR/internals/.apf6.restore"
    assert_success

    # Contains expected chains
    run grep "TALLOW" "$APF_DIR/internals/.apf6.restore"
    assert_success

    apf_set_config "USE_IPV6" "0"
    "$APF" -f 2>/dev/null || true
}

@test "fast load restores rules from snapshot" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"
    # First: do a full load to create the snapshot
    "$APF" -f 2>/dev/null
    "$APF" -s
    # Verify chains exist after full load
    run iptables -L TALLOW -n
    assert_success
    # Flush all rules
    "$APF" -f 2>/dev/null
    # Verify chains are gone after flush
    run iptables -L TALLOW -n 2>/dev/null
    assert_failure
    # Restart — should take fast load path (snapshot exists, no config change)
    "$APF" -s
    # Verify chains are restored from snapshot
    run iptables -L TALLOW -n
    assert_success
    run iptables -L TDENY -n
    assert_success
    # Verify the log confirms fast load was used
    run grep "fast load" /var/log/apf_log
    assert_success
    # Cleanup
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null
}

@test "config change forces full load when fastload enabled" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Record the .last.full timestamp
    local ts1
    ts1=$(cat "$APF_DIR/internals/.last.full")

    # Change a config value
    sleep 1
    apf_set_config "IG_TCP_CPORTS" "22,80,443,8080"
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Should have a new timestamp (full load happened)
    local ts2
    ts2=$(cat "$APF_DIR/internals/.last.full")
    [ "$ts2" -ge "$ts1" ]

    # Cleanup
    apf_set_config "SET_FASTLOAD" "0"
    apf_set_config "IG_TCP_CPORTS" "22,80,443"
    "$APF" -f 2>/dev/null
}
