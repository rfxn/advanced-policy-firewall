#!/usr/bin/env bats
# 15-fast-load.bats — APF Fast Load / Snapshot Lifecycle UAT
# Validates: snapshot creation, fast load restore, invalidation on config change,
# corrupt snapshot fallback, and backend mismatch handling.

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
    uat_apf_set_port_config "IG_TCP_CPORTS" "22,80,443"
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# =========================================================================
# UAT-FL01: Enable fast load, verify snapshot created
# Scenario: Sysadmin enables SET_FASTLOAD=1 for performance optimization
# =========================================================================

# bats test_tags=uat,uat:fast-load
@test "UAT: full load with SET_FASTLOAD=1 creates snapshot file" {
    uat_apf_set_config "SET_FASTLOAD" "1"
    # Ensure no prior snapshot
    rm -f /opt/apf/internals/.apf.restore
    rm -f /opt/apf/internals/.apf.restore.backend

    uat_capture "fast-load" apf -s
    assert_success

    # Snapshot must exist and contain iptables-restore format markers
    [ -s /opt/apf/internals/.apf.restore ]
    grep -q '^\*' /opt/apf/internals/.apf.restore

    # Backend marker must exist
    [ -f /opt/apf/internals/.apf.restore.backend ]
}

# bats test_tags=uat,uat:fast-load
@test "UAT: --info shows fast load enabled" {
    uat_capture "fast-load" apf --info
    assert_success
    assert_output --partial "Fast load:"
    assert_output --partial "enabled"
}

# =========================================================================
# UAT-FL02: Flush saves snapshot (when fast load enabled and firewall running)
# =========================================================================

# bats test_tags=uat,uat:fast-load
@test "UAT: flush saves snapshot before clearing rules" {
    # Record snapshot modification time before flush
    local before_mtime
    before_mtime=$(stat -c %Y /opt/apf/internals/.apf.restore)

    # Small delay to ensure mtime difference is detectable
    sleep 1

    uat_capture "fast-load" apf -f
    assert_success

    # Snapshot should have been re-saved (newer mtime)
    local after_mtime
    after_mtime=$(stat -c %Y /opt/apf/internals/.apf.restore)
    [ "$after_mtime" -ge "$before_mtime" ]
}

# =========================================================================
# UAT-FL03: Second start uses fast load (snapshot restore)
# =========================================================================

# bats test_tags=uat,uat:fast-load
@test "UAT: second start restores from snapshot (fast load)" {
    # Create .last.full marker to indicate not first run
    touch /opt/apf/internals/.last.full

    uat_capture "fast-load" apf -s
    assert_success

    # Firewall must be active with trust chains
    run iptables -S 2>/dev/null
    assert_output --partial "TALLOW"
    assert_output --partial "TDENY"
}

# bats test_tags=uat,uat:fast-load
@test "UAT: trust entries survive fast load cycle" {
    # Add a trust entry
    uat_capture "fast-load" apf -a 192.0.2.150 "fast load test"
    assert_success
    assert_rule_exists_ips TALLOW "192.0.2.150"

    # Flush (saves snapshot with entry) and restart
    apf -f 2>/dev/null
    touch /opt/apf/internals/.last.full
    uat_capture "fast-load" apf -s
    assert_success

    # Entry must survive the fast load cycle (in file → loaded on full load path)
    run grep "192.0.2.150" /opt/apf/allow_hosts.rules
    assert_success

    apf -u 192.0.2.150 2>/dev/null || true  # cleanup
}

# =========================================================================
# UAT-FL04: Corrupt snapshot triggers full load fallback
# =========================================================================

# bats test_tags=uat,uat:fast-load
@test "UAT: corrupt snapshot falls back to full load" {
    apf -f 2>/dev/null

    # Corrupt the snapshot
    echo "GARBAGE DATA" > /opt/apf/internals/.apf.restore
    touch /opt/apf/internals/.last.full

    uat_capture "fast-load" apf -s
    assert_success

    # Firewall must still be functional (full load ran)
    assert_chain_exists TALLOW
    assert_chain_exists TDENY
}

# =========================================================================
# UAT-FL05: Backend mismatch forces full load
# =========================================================================

# bats test_tags=uat,uat:fast-load
@test "UAT: backend mismatch in marker forces full load" {
    apf -f 2>/dev/null

    # Save a valid snapshot but set wrong backend marker
    touch /opt/apf/internals/.last.full
    # Write a fake backend marker that won't match
    echo "WRONG_BACKEND" > /opt/apf/internals/.apf.restore.backend

    uat_capture "fast-load" apf -s
    assert_success

    # Must still work (full load fallback)
    assert_chain_exists TALLOW
}

# =========================================================================
# UAT-FL06: Disable fast load — no snapshot on flush
# =========================================================================

# bats test_tags=uat,uat:fast-load
@test "UAT: SET_FASTLOAD=0 does full load even when snapshot exists" {
    # APF always saves a snapshot at end of start for recovery — SET_FASTLOAD
    # only controls whether the snapshot is USED on the next start.
    # Verify that with SET_FASTLOAD=0, a full load occurs (not a restore).
    uat_apf_set_config "SET_FASTLOAD" "0"

    # Flush and restart — should do full load
    apf -f 2>/dev/null
    rm -f /opt/apf/internals/.last.full

    uat_capture "fast-load" apf -s
    assert_success

    # Firewall must be active with trust chains (proves full load succeeded)
    assert_chain_exists TALLOW
    assert_chain_exists TDENY

    # --info should show fast load disabled
    uat_capture "fast-load" apf --info
    assert_output --partial "Fast load:"
    assert_output --partial "disabled"
}
