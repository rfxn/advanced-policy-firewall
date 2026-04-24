#!/usr/bin/env bats
#
# 08: Fast load — snapshot format, backend marker, IPv6 snapshot
#
# Fast load lifecycle tests (restore, config change detection, edge cases)
# are in 23-devel-fastload.bats. This file covers snapshot format validation
# and backend marker correctness.

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
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
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
    if ! ip6tables_available; then skip "ip6tables not available"; fi
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

@test "empty snapshot does not prevent firewall start" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"

    # Full load to create snapshot
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Flush, then truncate snapshot
    "$APF" -f 2>/dev/null || true
    : > "$APF_DIR/internals/.apf.restore"

    # Start — should fall back to full load despite empty snapshot
    "$APF" -s

    # Verify full load ran (chains should exist)
    assert_chain_exists TALLOW
    assert_chain_exists TDENY

    apf_set_config "SET_FASTLOAD" "0"
}

@test "garbage snapshot does not prevent firewall start" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"

    # Full load to create snapshot
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Flush, then corrupt snapshot with garbage
    "$APF" -f 2>/dev/null || true
    echo "garbage data without table markers" > "$APF_DIR/internals/.apf.restore"

    # Start — should fall back to full load despite corrupt snapshot
    "$APF" -s

    # Verify full load ran
    assert_chain_exists TALLOW
    assert_chain_exists TDENY

    apf_set_config "SET_FASTLOAD" "0"
}

@test "flush also saves backend marker via snapshot_save" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"

    # Remove existing marker
    rm -f "$APF_DIR/internals/.apf.restore.backend"

    # Full load + normal flush (not flush 1 / internal)
    "$APF" -s
    "$APF" -f

    # Flush should have called snapshot_save which writes the backend marker
    [ -f "$APF_DIR/internals/.apf.restore.backend" ]
    local marker
    marker=$(cat "$APF_DIR/internals/.apf.restore.backend")
    [[ "$marker" == "legacy" || "$marker" == "nft" ]]

    apf_set_config "SET_FASTLOAD" "0"
}

@test "empty IPv6 snapshot does not prevent firewall start" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    apf_set_config "SET_FASTLOAD" "1"

    # Full load to create snapshots
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Flush, then truncate IPv6 snapshot
    "$APF" -f 2>/dev/null || true
    : > "$APF_DIR/internals/.apf6.restore"

    # Start — should fall back to full load despite empty IPv6 snapshot
    "$APF" -s

    # Verify full load ran
    assert_chain_exists TALLOW

    apf_set_config "USE_IPV6" "0"
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null || true
}
