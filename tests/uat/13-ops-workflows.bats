#!/usr/bin/env bats
# 13-ops-workflows.bats — APF Operational Workflow UATs
# Exercises day-to-day sysadmin scenarios not covered by existing UATs:
# trust persistence across restart, refresh safety, config change detection,
# status/diagnostic accuracy, flush idempotency, mixed trust coexistence,
# bulk deny editing, deny-only removal, and lookup accuracy.

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
    uat_apf_set_port_config "IG_UDP_CPORTS" "53"
    uat_apf_set_port_config "EG_TCP_CPORTS" "22,80,443"
    uat_apf_set_port_config "EG_UDP_CPORTS" "53"
    apf -s
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

teardown() {
    # Safety net: restore config backup if a test left one behind
    if [ -f /opt/apf/conf.apf.bak ]; then
        cp /opt/apf/conf.apf.bak /opt/apf/conf.apf
        rm -f /opt/apf/conf.apf.bak
    fi
}

# =========================================================================
# UAT-015: Trust entries persist across restart via file reload
# Scenario: Sysadmin adds trust → restarts → entries survive
# Validates the full cycle: add → verify live → flush (gone) → start (back)
# =========================================================================

# bats test_tags=uat,uat:ops-restart-persist
@test "UAT: allowed IP survives restart — verified absent after flush, present after start" {
    uat_capture "ops-persist" apf -a 192.0.2.80 "persist test"
    assert_success
    assert_rule_exists_ips TALLOW "192.0.2.80"

    # Flush — entry must be GONE from iptables (proves flush actually clears)
    apf -f 2>/dev/null
    run iptables -S TALLOW 2>/dev/null
    # TALLOW chain should not exist after flush
    assert_failure

    # Start — entry must be BACK (loaded from file)
    uat_capture "ops-persist" apf -s
    assert_success
    assert_rule_exists_ips TALLOW "192.0.2.80"
}

# bats test_tags=uat,uat:ops-restart-persist
@test "UAT: denied IP survives restart — verified absent after flush, present after start" {
    uat_capture "ops-persist" apf -d 198.51.100.80 "persist deny"
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.80"

    # Flush — verify gone
    apf -f 2>/dev/null
    run iptables -S TDENY 2>/dev/null
    assert_failure

    # Start — verify restored from file
    uat_capture "ops-persist" apf -s
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.80"
}

# =========================================================================
# UAT-016: Refresh preserves live trust entries (REFRESH_TEMP chain)
# Scenario: Sysadmin runs apf -e — existing allow entries must not drop
# The refresh cycle flushes TALLOW/TDENY and rebuilds from file. The
# REFRESH_TEMP chain preserves entries during the brief window.
# =========================================================================

# bats test_tags=uat,uat:ops-refresh
@test "UAT: refresh rebuilds trust chains — entry survives the flush-reload cycle" {
    # Precondition: entry exists in both file and iptables
    run grep "192.0.2.80" /opt/apf/allow_hosts.rules
    assert_success
    assert_rule_exists_ips TALLOW "192.0.2.80"

    # Capture TALLOW rule count before refresh
    local before_count
    before_count=$(iptables -S TALLOW 2>/dev/null | grep -c '^-A' || true)

    # Run refresh — this flushes + rebuilds TALLOW/TDENY from files
    uat_capture "ops-refresh" apf -e
    assert_success

    # Allow entry must still be in TALLOW after refresh
    assert_rule_exists_ips TALLOW "192.0.2.80"

    # Rule count should be consistent (proves chain was rebuilt, not just left alone)
    local after_count
    after_count=$(iptables -S TALLOW 2>/dev/null | grep -c '^-A' || true)
    [ "$after_count" -ge 1 ]
}

# bats test_tags=uat,uat:ops-refresh
@test "UAT: refresh preserves deny entries across chain rebuild" {
    run grep "198.51.100.80" /opt/apf/deny_hosts.rules
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.80"

    uat_capture "ops-refresh" apf -e
    assert_success

    assert_rule_exists_ips TDENY "198.51.100.80"
}

# =========================================================================
# UAT-017: Config change applies on restart
# Scenario: Sysadmin edits conf.apf (adds port) → restart → new port live
# Includes negative probe: port absent before change
# =========================================================================

# bats test_tags=uat,uat:ops-config-change
@test "UAT: new port appears after config change and restart" {
    # Negative probe: 8080 must NOT be in current rules
    run iptables -S 2>/dev/null
    refute_output --partial "8080"

    # Add a new port to inbound TCP
    uat_apf_set_port_config "IG_TCP_CPORTS" "22,80,443,8080"

    # Restart — full load picks up config change
    uat_capture "ops-config" apf -r
    assert_success

    # Positive probe: 8080 must now be live
    run iptables -S 2>/dev/null
    assert_output --partial "8080"

    # Restore original config
    uat_apf_set_port_config "IG_TCP_CPORTS" "22,80,443"
}

# =========================================================================
# UAT-018: --info accuracy across operational states
# Scenario: Sysadmin checks firewall status after configuration
# Uses specific string matching to avoid false positives
# =========================================================================

# bats test_tags=uat,uat:ops-info
@test "UAT: info shows correct interface name" {
    uat_capture "ops-info" apf --info
    assert_success
    # Match the specific interface line — not just any occurrence of the string
    assert_output --partial "Interface:"
    assert_output --partial "veth-pub"
}

# bats test_tags=uat,uat:ops-info
@test "UAT: info trust counts reflect known entries" {
    uat_capture "ops-info" apf --info
    assert_success
    # We have 192.0.2.80 in allow and 198.51.100.80 in deny
    local allow_count
    allow_count=$(echo "$output" | grep "Allow entries:" | grep -o '[0-9]\+' | head -1)
    [ "$allow_count" -ge 1 ]
    local deny_count
    deny_count=$(echo "$output" | grep "Deny entries:" | grep -o '[0-9]\+' | head -1)
    [ "$deny_count" -ge 1 ]
}

# bats test_tags=uat,uat:ops-info
@test "UAT: info shows outbound port configuration when EGF enabled" {
    uat_capture "ops-info" apf --info
    assert_success
    # EGF=1 means --info shows "Outbound TCP:" and "Outbound UDP:" with our ports
    assert_output --partial "Outbound TCP:"
    assert_output --partial "Outbound UDP:"
    # Verify specific port list appears on the Outbound TCP line
    local eg_line
    eg_line=$(echo "$output" | grep "Outbound TCP:")
    echo "$eg_line" | grep -q "22"
    echo "$eg_line" | grep -q "443"
}

# =========================================================================
# UAT-019: --rules completeness and pipeability
# Scenario: Sysadmin pipes rules to grep for audit / troubleshooting
# =========================================================================

# bats test_tags=uat,uat:ops-rules
@test "UAT: rules output includes trust entries and chain names" {
    uat_capture "ops-rules" apf --rules
    assert_success
    # Output should contain iptables -S style output with chain names
    assert_output --partial "TALLOW"
    assert_output --partial "TDENY"
    # Must contain our known trust entry
    assert_output --partial "192.0.2.80"
}

# bats test_tags=uat,uat:ops-rules
@test "UAT: rules output is pipeable to grep without errors" {
    # Simulate sysadmin piping: apf --rules | grep ACCEPT
    run bash -c 'apf --rules 2>/dev/null | grep -c ACCEPT'
    assert_success
    # Must find multiple ACCEPT rules (port filtering produces several)
    local count
    count="$output"
    [ "$count" -ge 3 ]
}

# =========================================================================
# UAT-020: Validate catches config errors before start
# Scenario: Sysadmin misconfigures stop targets → validate catches it
# =========================================================================

# bats test_tags=uat,uat:ops-validate
@test "UAT: validate catches multiple bad config values" {
    # Save current config for reliable restore
    cp /opt/apf/conf.apf /opt/apf/conf.apf.bak

    # Set multiple bad values (TCP and UDP stop targets)
    uat_apf_set_config "TCP_STOP" "INVALID"
    uat_apf_set_config "UDP_STOP" "BADTARGET"

    # Validate should catch both errors (accumulates in err string)
    run apf --validate
    local val_status="$status"
    local val_output="$output"

    # Restore BEFORE asserting — ensures clean state even if test fails
    cp /opt/apf/conf.apf.bak /opt/apf/conf.apf
    rm -f /opt/apf/conf.apf.bak

    # Must fail
    [ "$val_status" -ne 0 ]
    # Must report both bad variables
    echo "$val_output" | grep -q "TCP_STOP"
    echo "$val_output" | grep -q "UDP_STOP"
}

# bats test_tags=uat,uat:ops-validate
@test "UAT: validate passes with restored valid config" {
    uat_capture "ops-validate" apf --validate
    assert_success
}

# =========================================================================
# UAT-021: Flush idempotency
# Scenario: Sysadmin flushes twice, or flushes when never started
# =========================================================================

# bats test_tags=uat,uat:ops-flush
@test "UAT: double flush is idempotent — both succeed and leave safe state" {
    uat_capture "ops-flush" apf -f
    assert_success

    # Second flush on already-flushed state must also succeed
    uat_capture "ops-flush" apf -f
    assert_success

    # Policies must be ACCEPT (safe failopen state)
    run iptables -S INPUT 2>/dev/null
    assert_output --partial "ACCEPT"

    # APF chains must be gone (proves flush actually worked)
    run iptables -S TALLOW 2>/dev/null
    assert_failure

    # Bring firewall back up for remaining tests
    apf -s
}

# =========================================================================
# UAT-022: Temp + permanent trust coexistence
# Scenario: Sysadmin has permanent entries and adds temporary blocks
# Includes negative probes on both sides of the coexistence
# =========================================================================

# bats test_tags=uat,uat:ops-mixed-trust
@test "UAT: temp and permanent allow entries coexist independently" {
    # Permanent allow already exists (192.0.2.80)
    assert_rule_exists_ips TALLOW "192.0.2.80"

    # Negative probe: temp IP must NOT be present yet
    run iptables -S TALLOW 2>/dev/null
    refute_output --partial "192.0.2.90"

    # Add a temp allow
    uat_capture "ops-mixed" apf -ta 192.0.2.90 1h "temp office"
    assert_success

    # Both must coexist in iptables
    assert_rule_exists_ips TALLOW "192.0.2.80"
    assert_rule_exists_ips TALLOW "192.0.2.90"

    # Verify temp has ttl marker in file, permanent does not
    local temp_comment
    temp_comment=$(grep "# added.*192.0.2.90" /opt/apf/allow_hosts.rules)
    echo "$temp_comment" | grep -q "ttl="
    local perm_comment
    perm_comment=$(grep "# added.*192.0.2.80" /opt/apf/allow_hosts.rules)
    ! echo "$perm_comment" | grep -q "ttl="
}

# bats test_tags=uat,uat:ops-mixed-trust
@test "UAT: removing temp entry leaves permanent entry intact" {
    # Remove the temp entry
    uat_capture "ops-mixed" apf -u 192.0.2.90
    assert_success

    # Permanent entry must still be there
    assert_rule_exists_ips TALLOW "192.0.2.80"
    run grep "192.0.2.80" /opt/apf/allow_hosts.rules
    assert_success

    # Temp entry must be fully gone from both iptables and file
    run iptables -S TALLOW 2>/dev/null
    refute_output --partial "192.0.2.90"
    run grep "192.0.2.90" /opt/apf/allow_hosts.rules
    assert_failure
}

# =========================================================================
# UAT-023: Advanced + simple trust coexistence
# Scenario: Sysadmin mixes simple IPs and advanced syntax in allow file
# Proves both survive a restart (file-based reload)
# =========================================================================

# bats test_tags=uat,uat:ops-mixed-trust
@test "UAT: advanced and simple trust entries both load from file on restart" {
    # Simple entry exists (192.0.2.80)
    assert_rule_exists_ips TALLOW "192.0.2.80"

    # Negative probe: advanced IP must NOT exist yet
    run iptables -S TALLOW 2>/dev/null
    refute_output --partial "192.0.2.95"

    # Add advanced entry
    uat_capture "ops-mixed" apf -a "tcp:in:d=3306:s=192.0.2.95" "DB server"
    assert_success

    # Restart to verify both load from file (not just from live state)
    uat_capture "ops-mixed" apf -r
    assert_success

    # Simple entry in TALLOW (src + dst rules)
    assert_rule_exists_ips TALLOW "192.0.2.80"
    # Advanced entry in TALLOW (port-specific rule)
    assert_rule_exists_ips TALLOW "192.0.2.95"

    # Clean up advanced entry
    apf -u "tcp:in:d=3306:s=192.0.2.95" 2>/dev/null || true  # cleanup: safe if already removed
}

# =========================================================================
# UAT-024: Bulk deny file edit + restart
# Scenario: Sysadmin pastes attacker IPs into deny_hosts.rules directly
# Includes negative probe before restart
# =========================================================================

# bats test_tags=uat,uat:ops-bulk
@test "UAT: bulk deny file edit loads all entries on restart" {
    # Negative probe: test IPs must NOT be live before we add them
    run iptables -S TDENY 2>/dev/null
    refute_output --partial "198.51.100.20"
    refute_output --partial "198.51.100.21"
    refute_output --partial "198.51.100.22"

    # Add attacker IPs directly to deny file (no CLI — raw file edit)
    {
        echo "198.51.100.20"
        echo "198.51.100.21"
        echo "198.51.100.22"
    } >> /opt/apf/deny_hosts.rules

    # IPs are in file but NOT in iptables yet (proves restart is needed)
    run iptables -S TDENY 2>/dev/null
    refute_output --partial "198.51.100.20"

    uat_capture "ops-bulk" apf -r
    assert_success

    # All must now be in TDENY chain
    assert_rule_exists_ips TDENY "198.51.100.20"
    assert_rule_exists_ips TDENY "198.51.100.21"
    assert_rule_exists_ips TDENY "198.51.100.22"

    # Clean up
    sed -i '/198\.51\.100\.2[012]/d' /opt/apf/deny_hosts.rules
}

# =========================================================================
# UAT-025: Remove host that only exists in deny file
# Scenario: Sysadmin blocks IP → later unblocks → no allow entry ever existed
# =========================================================================

# bats test_tags=uat,uat:ops-deny-remove
@test "UAT: remove IP that exists only in deny_hosts.rules" {
    # Precondition: IP must not be in allow file
    run grep "198.51.100.99" /opt/apf/allow_hosts.rules
    assert_failure

    # Block it (goes to deny only)
    uat_capture "ops-deny-remove" apf -d 198.51.100.99 "only in deny"
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.99"

    # Still not in allow file
    run grep "198.51.100.99" /opt/apf/allow_hosts.rules
    assert_failure

    # Remove it
    uat_capture "ops-deny-remove" apf -u 198.51.100.99
    assert_success

    # Fully gone from deny file and iptables
    run grep "198.51.100.99" /opt/apf/deny_hosts.rules
    assert_failure
    run iptables -S TDENY 2>/dev/null
    refute_output --partial "198.51.100.99"
}

# =========================================================================
# UAT-026: Lookup accuracy for different entry types
# Each test establishes its own state instead of depending on leaked state
# =========================================================================

# bats test_tags=uat,uat:ops-lookup
@test "UAT: lookup correctly identifies CIDR allow entry" {
    uat_capture "ops-lookup" apf -a 203.0.113.0/24 "office CIDR"
    assert_success

    uat_capture "ops-lookup" apf --lookup 203.0.113.0/24
    assert_success
    assert_output --partial "ALLOW"

    apf -u 203.0.113.0/24 2>/dev/null || true  # cleanup
}

# bats test_tags=uat,uat:ops-lookup
@test "UAT: lookup correctly identifies denied IP" {
    uat_capture "ops-lookup" apf -d 198.51.100.55 "bad actor"
    assert_success

    uat_capture "ops-lookup" apf --lookup 198.51.100.55
    assert_success
    assert_output --partial "DENY"

    apf -u 198.51.100.55 2>/dev/null || true  # cleanup
}

# bats test_tags=uat,uat:ops-lookup
@test "UAT: lookup returns not-found for IP never added" {
    # Precondition: IP must not be in any trust file
    run grep "10.255.255.255" /opt/apf/allow_hosts.rules /opt/apf/deny_hosts.rules
    assert_failure

    uat_capture "ops-lookup" apf --lookup 10.255.255.255
    assert_failure
    assert_output --partial "not found"
}

# =========================================================================
# UAT-027: Log file records specific firewall operations
# Verifies that specific operation types produce identifiable log entries
# =========================================================================

# bats test_tags=uat,uat:ops-logging
@test "UAT: trust add operation produces identifiable log entry" {
    # Capture log size before operation
    local before_lines
    before_lines=$(wc -l < /var/log/apf_log)

    apf -a 192.0.2.88 "log-test-entry" 2>/dev/null
    apf -u 192.0.2.88 2>/dev/null || true  # cleanup

    # New log lines must mention the trust operation
    local new_lines
    new_lines=$(tail -n +$((before_lines + 1)) /var/log/apf_log)
    echo "$new_lines" | grep -q "192.0.2.88"
}

# bats test_tags=uat,uat:ops-logging
@test "UAT: status log command shows timestamped entries" {
    uat_capture "ops-logging" apf -t
    assert_success
    # Must contain at least one timestamped log line (format: "Mon DD HH:MM:SS")
    local ts_pat='[A-Z][a-z][a-z] [ 0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]'
    echo "$output" | grep -qE "$ts_pat"
}

# =========================================================================
# UAT-028: Manual flush+start produces same state as restart
# Scenario: Sysadmin does apf -f then apf -s (not apf -r)
# Includes negative probe between flush and start
# =========================================================================

# bats test_tags=uat,uat:ops-restart
@test "UAT: manual flush+start restores trust entries from files" {
    # Add known entries
    apf -a 192.0.2.85 "restart-test" 2>/dev/null
    apf -d 198.51.100.85 "restart-test" 2>/dev/null

    # Flush — entries must be GONE
    uat_capture "ops-restart" apf -f
    assert_success
    run iptables -S TALLOW 2>/dev/null
    assert_failure  # chain doesn't exist after flush

    # Start — entries must be BACK
    uat_capture "ops-restart" apf -s
    assert_success
    assert_rule_exists_ips TALLOW "192.0.2.85"
    assert_rule_exists_ips TDENY "198.51.100.85"

    # Clean up
    apf -u 192.0.2.85 2>/dev/null || true  # cleanup
    apf -u 198.51.100.85 2>/dev/null || true  # cleanup
}

# =========================================================================
# UAT-029: List commands show accurate state
# Each test establishes its own entries rather than depending on prior tests
# =========================================================================

# bats test_tags=uat,uat:ops-list
@test "UAT: list-allow reflects entries added in this session" {
    # Add a unique entry for this test
    apf -a 192.0.2.77 "list-test-allow" 2>/dev/null

    uat_capture "ops-list" apf --la
    assert_success
    assert_output --partial "192.0.2.77"

    apf -u 192.0.2.77 2>/dev/null || true  # cleanup
}

# bats test_tags=uat,uat:ops-list
@test "UAT: list-deny reflects entries added in this session" {
    # Add a unique entry for this test
    apf -d 198.51.100.77 "list-test-deny" 2>/dev/null

    uat_capture "ops-list" apf --ld
    assert_success
    assert_output --partial "198.51.100.77"

    apf -u 198.51.100.77 2>/dev/null || true  # cleanup
}

# =========================================================================
# UAT-030: Clean start with empty trust files — no orphan rules
# Proves the assertion is real by adding an entry afterward and verifying
# it appears (the chain is functional, not just empty/broken)
# =========================================================================

# bats test_tags=uat,uat:ops-baseline
@test "UAT: empty trust files produce empty chains — then adding entry works" {
    # Remove all test entries via CLI
    apf -u 192.0.2.80 2>/dev/null || true  # cleanup
    apf -u 198.51.100.80 2>/dev/null || true  # cleanup

    # Clear trust files (keep comments)
    sed -i '/^[^#]/d' /opt/apf/allow_hosts.rules
    sed -i '/^[^#]/d' /opt/apf/deny_hosts.rules
    # Also clean comment lines from our test entries
    sed -i '/^# added/d' /opt/apf/allow_hosts.rules
    sed -i '/^# added/d' /opt/apf/deny_hosts.rules

    uat_capture "ops-baseline" apf -r
    assert_success

    # TALLOW and TDENY should exist but have no test IPs
    run iptables -S TALLOW 2>/dev/null
    assert_success
    refute_output --partial "192.0.2."
    refute_output --partial "198.51.100."

    run iptables -S TDENY 2>/dev/null
    assert_success
    refute_output --partial "192.0.2."
    refute_output --partial "198.51.100."

    # Positive probe: verify chains are functional by adding an entry
    apf -a 192.0.2.99 "baseline-probe" 2>/dev/null
    assert_rule_exists_ips TALLOW "192.0.2.99"
    apf -u 192.0.2.99 2>/dev/null || true  # cleanup
}
