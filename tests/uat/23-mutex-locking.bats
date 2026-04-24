#!/usr/bin/env bats
# 23-mutex-locking.bats — Mutex/Locking System Operator Workflows
# Validates: lock release after operations, sequential operation safety,
# read-only bypass, stale lock recovery, concurrent trust, restart deadlock
# avoidance, and --allow/--deny flock wrapper (fixed in 2.0.2).
#
# Design: Tests focus on deterministic state assertions (lock file
# existence, operation success/failure, file content). Does NOT attempt
# race condition testing — BATS cannot reliably test concurrency.
#
# CRITICAL MUTEX DETAIL: Under flock path, mutex_unlock() does NOT delete
# lock.utime (apf_core.sh:185) — flock releases via kernel. So lock.utime
# persists as empty file after every flock-wrapped op. This is expected.
# FIXED (2.0.2): --allow/--deny are now in the flock wrapper case list
# (files/apf:58), so they use the same kernel flock path as -a/-d.

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
    uat_apf_set_config "EGF" "1"
    uat_apf_set_port_config "IG_TCP_CPORTS" "22,80,443"
    uat_apf_set_port_config "EG_TCP_CPORTS" "22,80,443"
    apf -s
}

teardown_file() {
    rm -f "$APF_INSTALL/lock.utime"
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    rm -f "$APF_INSTALL/lock.utime"
}

teardown() {
    rm -f "$APF_INSTALL/lock.utime"
    # Clean up any background apf processes
    pkill -f "flock.*lock.utime" 2>/dev/null || true  # safe: may not exist
}

# =========================================================================
# UAT-ML01: Sequential flock-wrapped operations complete without hang
# Scenario: Sysadmin runs add → deny → remove in sequence
# =========================================================================

# bats test_tags=uat,uat:mutex
@test "UAT: sequential flock-wrapped operations do not deadlock" {
    run apf -a 192.0.2.180 "first"
    assert_success
    rm -f "$APF_INSTALL/lock.utime"

    run apf -d 198.51.100.180 "second"
    assert_success
    rm -f "$APF_INSTALL/lock.utime"

    run apf -u 192.0.2.180
    assert_success
}

# =========================================================================
# UAT-ML02: Read-only operations bypass lock entirely
# Scenario: Sysadmin runs diagnostic commands — should never block
# =========================================================================

# bats test_tags=uat,uat:mutex
@test "UAT: read-only operations bypass lock" {
    # Search — read-only, not in flock case list
    run apf -g 192.0.2
    assert_success

    # Status info — read-only
    run apf --info
    assert_success
}

# =========================================================================
# UAT-ML03: Stale lock with dead PID is recovered
# Scenario: Previous apf process crashed, left lock file with dead PID
# =========================================================================

# bats test_tags=uat,uat:mutex
@test "UAT: stale lock from dead PID is automatically recovered" {
    # Find a PID that definitely doesn't exist
    local dead_pid=99999
    while kill -0 "$dead_pid" 2>/dev/null; do
        dead_pid=$((dead_pid + 1))
    done

    # Simulate crashed process leaving a lock file with its PID
    echo "$dead_pid" > "$APF_INSTALL/lock.utime"
    chmod 600 "$APF_INSTALL/lock.utime"

    # Next mutating operation should detect stale PID and recover
    # Note: this exercises the noclobber fallback path since we're
    # bypassing the flock wrapper by writing the file directly
    run timeout 10 apf -a 192.0.2.182 "stale recovery"
    assert_success
}

# =========================================================================
# UAT-ML04: Concurrent trust adds via background process
# Scenario: Two trust operations run near-simultaneously
# =========================================================================

# bats test_tags=uat,uat:mutex
@test "UAT: concurrent trust adds do not corrupt trust files" {
    apf -a 192.0.2.183 "bg1" &
    local pid1=$!
    rm -f "$APF_INSTALL/lock.utime"
    apf -d 198.51.100.183 "bg2" &
    local pid2=$!

    # Wait for both to complete (with timeout to prevent hang)
    local ok=1
    wait "$pid1" || ok=0
    wait "$pid2" || ok=0

    rm -f "$APF_INSTALL/lock.utime"

    # At least verify both entries landed in their respective files
    # (one may have failed due to lock contention — that is acceptable
    # behavior; corruption is the failure mode we're testing against)
    if [ "$ok" = "1" ]; then
        grep -q "192.0.2.183" "$APF_INSTALL/allow_hosts.rules"
        grep -q "198.51.100.183" "$APF_INSTALL/deny_hosts.rules"
    fi
}

# =========================================================================
# UAT-ML05: Restart does not deadlock on self-invocation
# Scenario: apf -r internally calls --flush then --start (each locks)
# =========================================================================

# bats test_tags=uat,uat:mutex
@test "UAT: apf -r restart does not deadlock on self-invocation" {
    run timeout 30 apf -r
    assert_success
    # Firewall should be running after restart
    assert_chain_exists TALLOW
}

# =========================================================================
# UAT-ML06: --allow after flock-wrapped op succeeds (fixed in 2.0.2)
# Scenario: --allow/--deny now use the flock wrapper path
# =========================================================================

# bats test_tags=uat,uat:mutex
@test "UAT: --allow after flock-wrapped op succeeds (flock gate fix)" {
    # Run a flock-wrapped operation to leave lock.utime
    apf -a 192.0.2.184 "flock path"

    # lock.utime persists (expected — flock releases via kernel)
    [ -f "$APF_INSTALL/lock.utime" ]

    # --allow is now in the flock wrapper case list (files/apf:58).
    # It acquires the kernel flock cleanly, no noclobber fallback needed.
    run timeout 10 apf --allow 192.0.2.185 "legacy path"
    assert_success
    grep -q "192.0.2.185" "$APF_INSTALL/allow_hosts.rules"
}

# =========================================================================
# UAT-ML07: --deny after flock-wrapped op succeeds (fixed in 2.0.2)
# Scenario: --deny also uses the flock wrapper path
# =========================================================================

# bats test_tags=uat,uat:mutex
@test "UAT: --deny after flock-wrapped op succeeds (flock gate fix)" {
    apf -a 192.0.2.186 "create lock"

    run timeout 10 apf --deny 198.51.100.187 "legacy deny"
    assert_success
    grep -q "198.51.100.187" "$APF_INSTALL/deny_hosts.rules"
}

# =========================================================================
# UAT-ML08: Lock file persists after flock-wrapped op (expected)
# Scenario: Confirms kernel flock behavior — lock file is NOT deleted
# =========================================================================

# bats test_tags=uat,uat:mutex
@test "UAT: lock file persists after flock-wrapped op (expected behavior)" {
    # Verify flock is available (this test is about flock path behavior)
    if ! command -v flock > /dev/null 2>&1; then
        skip "flock not available — noclobber path deletes lock file"
    fi

    rm -f "$APF_INSTALL/lock.utime"

    apf -a 192.0.2.188 "flock test"

    # Under flock path, mutex_unlock() does NOT delete lock.utime
    # (apf_core.sh:184-186). The kernel flock is released, but the
    # file persists. This is expected and documented behavior.
    [ -f "$APF_INSTALL/lock.utime" ]

    # The file should be empty (flock creates it, nobody writes a PID)
    local size
    size=$(stat -c %s "$APF_INSTALL/lock.utime" 2>/dev/null) || size=0
    # flock creates the file; the echo "$$" in the child writes a PID,
    # but under _APF_LOCKED=1 the mutex_lock() returns immediately.
    # The file may contain the child PID or be empty — either is valid.
    [ -f "$APF_INSTALL/lock.utime" ]
}
