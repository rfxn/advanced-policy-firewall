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
