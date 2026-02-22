#!/usr/bin/env bats
#
# 17: ipset Block Lists — kernel-level hash sets for high-performance IP matching
#
# ipset requires kernel module support. Tests skip gracefully when unavailable.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

# Count members in an ipset set (portable across ipset versions).
# Old ipset (v6.x on CentOS 6, Ubuntu 12.04) lacks "Number of entries:" line.
assert_ipset_entry_count() {
    local name="$1" expected="$2"
    local count
    count=$(ipset list "$name" | awk '/^Members:/{f=1;next} f && /./' | wc -l)
    if [ "$count" -ne "$expected" ]; then
        echo "Expected $expected entries in ipset '$name', got $count" >&2
        return 1
    fi
}

# Check if ipset is usable (binary + kernel support)
ipset_available() {
    command -v ipset >/dev/null 2>&1 || return 1
    # Try to create and destroy a probe set to verify kernel module
    ipset create _apf_probe hash:ip 2>/dev/null || return 1
    ipset destroy _apf_probe 2>/dev/null
    return 0
}

# Create a test blocklist file with RFC 5737 test IPs
create_test_blocklist() {
    local listfile="$APF_DIR/test_blocklist.txt"
    cat > "$listfile" <<'BLEOF'
# Test blocklist for ipset tests
192.0.2.10
192.0.2.11
192.0.2.12
BLEOF
    echo "$listfile"
}

# Create a larger test blocklist for maxelem testing
create_test_blocklist_large() {
    local listfile="$APF_DIR/test_blocklist_large.txt"
    cat > "$listfile" <<'BLEOF'
192.0.2.10
192.0.2.11
192.0.2.12
192.0.2.13
192.0.2.14
192.0.2.15
192.0.2.16
192.0.2.17
192.0.2.18
192.0.2.19
BLEOF
    echo "$listfile"
}

# Create a CIDR test blocklist for hash:net
create_test_blocklist_cidr() {
    local listfile="$APF_DIR/test_blocklist_cidr.txt"
    cat > "$listfile" <<'BLEOF'
# Test CIDR blocklist
198.51.100.0/24
192.0.2.0/28
BLEOF
    echo "$listfile"
}

setup_file() {
    if ! ipset_available; then
        return 0
    fi
    # Pre-clean any leftover state from prior tests
    ip link del veth-pub 2>/dev/null || true
    ip link del veth-priv 2>/dev/null || true
    ip netns del client_ns 2>/dev/null || true
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""

    # Create test blocklists
    create_test_blocklist
    create_test_blocklist_cidr

    # Configure ipset with a local blocklist (7-field format)
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
## ipset test rules
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF

    apf_set_config "USE_IPSET" "1"
    apf_set_config "LOG_DROP" "1"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    # Clean up ipset sets
    ipset destroy test_block 2>/dev/null || true
    ipset destroy test_cidr 2>/dev/null || true
    ipset destroy test_maxelem 2>/dev/null || true
    # Remove test files
    rm -f "$APF_DIR/test_blocklist.txt" "$APF_DIR/test_blocklist_cidr.txt" \
          "$APF_DIR/test_blocklist_large.txt"
    source /opt/tests/helpers/teardown-netns.sh 2>/dev/null || true
}

@test "ipset set created with correct entry count" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    run ipset list test_block
    assert_success
    # Should contain 3 entries (count members for old ipset compatibility)
    assert_ipset_entry_count test_block 3
}

@test "IPSET_test_block iptables chain exists" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    assert_chain_exists IPSET_test_block
}

@test "IPSET_test_block chain has set match rule" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    assert_rule_exists_ips IPSET_test_block "match-set test_block src"
}

@test "ipset set contains test IPs" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    run ipset test test_block 192.0.2.10
    assert_success
    run ipset test test_block 192.0.2.11
    assert_success
    run ipset test test_block 192.0.2.12
    assert_success
}

@test "USE_IPSET=0 creates no ipset sets" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    # Flush, reconfigure with USE_IPSET=0, restart
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true

    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPSET" "0"
    "$APF" -s

    # No ipset set should exist
    run ipset list test_block 2>/dev/null
    assert_failure

    # Restore for remaining tests
    "$APF" -f 2>/dev/null || true
    apf_set_config "USE_IPSET" "1"
    "$APF" -s
}

@test "--ipset-update refreshes set contents" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    # Add new entry to blocklist
    echo "192.0.2.99" >> "$APF_DIR/test_blocklist.txt"

    # Reset timestamp so update is not skipped
    rm -f "$APF_DIR/internals/.ipset.timestamps"

    "$APF" --ipset-update

    run ipset test test_block 192.0.2.99
    assert_success

    # Restore original blocklist
    create_test_blocklist
}

@test "apf -f destroys ipset sets" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    "$APF" -f
    run ipset list test_block 2>/dev/null
    assert_failure

    # Restart for remaining tests
    "$APF" -s
}

@test "empty blocklist skipped without error" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true

    # Create empty blocklist entry
    local emptyfile="$APF_DIR/test_empty.txt"
    : > "$emptyfile"
    cat > "$APF_DIR/ipset.rules" <<ISEOF
test_empty:src:ip:0:0:0:$emptyfile
ISEOF

    "$APF" -s

    # No set should be created for empty file
    run ipset list test_empty 2>/dev/null
    assert_failure

    # Restore
    rm -f "$emptyfile"
    "$APF" -f 2>/dev/null || true
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF
    "$APF" -s
}

@test "per-rule log:1 with LOG_DROP=1 creates log rule" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    # test_block has log=1 and LOG_DROP=1 is set
    assert_rule_exists_ips IPSET_test_block "LOG.*IPSET_test_block"
}

@test "comment lines in blocklist ignored" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    # The test blocklist has a comment line — verify only 3 IPs loaded
    assert_ipset_entry_count test_block 3
}

@test "CIDR entries accepted in hash:net set" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true

    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_cidr:src:net:0:0:0:/opt/apf/test_blocklist_cidr.txt
ISEOF

    "$APF" -s

    run ipset list test_cidr
    assert_success
    assert_ipset_entry_count test_cidr 2

    # Test that an IP within the CIDR is matched
    run ipset test test_cidr 198.51.100.50
    assert_success

    # Restore
    "$APF" -f 2>/dev/null || true
    ipset destroy test_cidr 2>/dev/null || true
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF
    "$APF" -s
}

@test "IPSET_test_block chain attached to INPUT" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    assert_rule_exists_ips INPUT "IPSET_test_block"
}

# --- Legacy format migration tests ---

@test "legacy 4-field local path migrated to 7-field" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true

    # Write old 4-field format (no log/interval/maxelem fields)
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:/opt/apf/test_blocklist.txt
ISEOF

    "$APF" -s

    # Set should be created — migration inserted log=0:interval=0:maxelem=0
    run ipset list test_block
    assert_success
    assert_ipset_entry_count test_block 3

    # File should be rewritten in 7-field format
    run cat "$APF_DIR/ipset.rules"
    assert_output "test_block:src:ip:0:0:0:/opt/apf/test_blocklist.txt"

    # Restore
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF
    "$APF" -s
}

@test "legacy 4-field URL entry migrated to 7-field" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true

    # Write old 4-field format with URL (colon in https://)
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_url:src:net:https://example.com/blocklist.txt
ISEOF

    # Start will fail to download (fake URL) but migration should still rewrite
    "$APF" -s 2>/dev/null || true

    # File should be rewritten with log=0:interval=0:maxelem=0 inserted, URL intact
    run cat "$APF_DIR/ipset.rules"
    assert_output "test_url:src:net:0:0:0:https://example.com/blocklist.txt"

    # Restore
    "$APF" -f 2>/dev/null || true
    ipset destroy test_url 2>/dev/null || true
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF
    "$APF" -s
}

@test "7-field entry not modified by migration" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true

    # Write correct 7-field format
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
# comment line
test_block:src:ip:1:3600:5000:/opt/apf/test_blocklist.txt
ISEOF

    "$APF" -s

    # File should be unchanged
    run cat "$APF_DIR/ipset.rules"
    assert_line --index 0 "# comment line"
    assert_line --index 1 "test_block:src:ip:1:3600:5000:/opt/apf/test_blocklist.txt"

    # Restore
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF
    "$APF" -s
}

# --- maxelem tests ---

@test "maxelem limits entries loaded into ipset" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    "$APF" -f 2>/dev/null || true
    ipset destroy test_block 2>/dev/null || true
    ipset destroy test_maxelem 2>/dev/null || true

    # Create a 10-entry blocklist
    create_test_blocklist_large

    # Set maxelem=3 — only first 3 entries should be loaded
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_maxelem:src:ip:0:0:3:/opt/apf/test_blocklist_large.txt
ISEOF

    "$APF" -s

    run ipset list test_maxelem
    assert_success
    assert_ipset_entry_count test_maxelem 3

    # Restore
    "$APF" -f 2>/dev/null || true
    ipset destroy test_maxelem 2>/dev/null || true
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF
    "$APF" -s
}

# --- timestamp tests ---

@test "timestamp file created during ipset_load" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    # Timestamp file should exist after setup_file started the firewall
    [ -f "$APF_DIR/internals/.ipset.timestamps" ]
    run grep "^test_block:" "$APF_DIR/internals/.ipset.timestamps"
    assert_success
}

@test "ipset flush removes timestamp file" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    "$APF" -f
    [ ! -f "$APF_DIR/internals/.ipset.timestamps" ]

    # Restart for remaining tests
    "$APF" -s
}

@test "per-list interval skips recent updates" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    # Set a long interval so update is skipped
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:86400:0:/opt/apf/test_blocklist.txt
ISEOF

    # Write a recent timestamp
    echo "test_block:$(date +%s)" > "$APF_DIR/internals/.ipset.timestamps"

    # Add a new entry — update should skip due to interval
    echo "192.0.2.99" >> "$APF_DIR/test_blocklist.txt"
    "$APF" --ipset-update

    # Entry should NOT be present (update was skipped)
    run ipset test test_block 192.0.2.99
    assert_failure

    # Restore
    create_test_blocklist
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF
}

@test "per-list interval triggers update after elapsed" {
    if ! ipset_available; then
        skip "ipset not available"
    fi
    # Set a short interval
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:1:0:/opt/apf/test_blocklist.txt
ISEOF

    # Write an old timestamp (epoch 0)
    echo "test_block:0" > "$APF_DIR/internals/.ipset.timestamps"

    # Add a new entry — update should proceed (interval elapsed)
    echo "192.0.2.99" >> "$APF_DIR/test_blocklist.txt"
    "$APF" --ipset-update

    # Entry should be present (update ran)
    run ipset test test_block 192.0.2.99
    assert_success

    # Restore
    create_test_blocklist
    "$APF" -f 2>/dev/null || true
    cat > "$APF_DIR/ipset.rules" <<'ISEOF'
test_block:src:ip:1:0:0:/opt/apf/test_blocklist.txt
ISEOF
    "$APF" -s
}
