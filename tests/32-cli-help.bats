#!/usr/bin/env bats
#
# 32: CLI help, diagnostics, and trust listing options

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

teardown() {
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

# --- help and version ---

@test "apf -h exits 0 and shows usage" {
    run "$APF" -h
    assert_success
    assert_output --partial "usage: apf"
}

@test "unknown option exits 1" {
    run "$APF" --badopt
    assert_failure
}

@test "apf --help shows section headers" {
    run "$APF" --help
    assert_success
    assert_output --partial "Firewall Control:"
    assert_output --partial "Trust Management:"
    assert_output --partial "Temporary Trust:"
    assert_output --partial "Diagnostics:"
    assert_output --partial "Subsystems:"
}

@test "apf -h includes new options in output" {
    run "$APF" -h
    assert_success
    assert_output --partial "--validate"
    assert_output --partial "--list-allow"
    assert_output --partial "--list-deny"
    assert_output --partial "--dump-config"
    assert_output --partial "--rules"
    assert_output --partial "--info"
    assert_output --partial "--lookup"
}

# --- --dump-config ---

@test "apf --dump-config outputs config variables" {
    run "$APF" --dump-config
    assert_success
    assert_output --partial "INSTALL_PATH"
}

# --- --validate / --check ---

@test "apf --validate succeeds with valid config" {
    run "$APF" --validate
    assert_success
    assert_output --partial "Configuration validated successfully"
}
@test "apf --validate fails with invalid TCP_STOP value" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "TCP_STOP" "INVALID"
    run "$APF" --validate
    assert_failure
    assert_output --partial "TCP_STOP"
    # Restore valid value
    apf_set_config "TCP_STOP" "DROP"
}

@test "apf --validate fails with invalid SYNFLOOD_RATE" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    apf_set_config "SYNFLOOD_RATE" "bad"
    run "$APF" --validate
    assert_failure
    assert_output --partial "SYNFLOOD_RATE"
    # Restore valid values
    apf_set_config "SYNFLOOD" "0"
    apf_set_config_safe "SYNFLOOD_RATE" "5/s"
}

@test "apf --validate passes RAB_PSCAN_LEVEL=0 (disabled)" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "RAB" "1"
    apf_set_config "RAB_PSCAN_LEVEL" "0"
    run "$APF" --validate
    assert_success
    # Restore
    apf_set_config "RAB_PSCAN_LEVEL" "1"
    apf_set_config "RAB" "0"
}

@test "apf --validate passes RAB_HITCOUNT=0 (auto-promoted)" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "RAB" "1"
    apf_set_config "RAB_HITCOUNT" "0"
    run "$APF" --validate
    assert_success
    # Restore
    apf_set_config "RAB_HITCOUNT" "1"
    apf_set_config "RAB" "0"
}

# --- --list-allow / --list-deny ---

@test "apf --la with empty file shows no entries" {
    # Ensure allow_hosts.rules exists but is empty (or comments only)
    echo "# comment line" > "$APF_DIR/allow_hosts.rules"
    run "$APF" --la
    assert_success
    assert_output --partial "No entries"
}

@test "apf --la shows allow_hosts entries after adding a host" {
    "$APF" -s 2>/dev/null || true
    "$APF" -a 192.0.2.50 "test entry" 2>/dev/null || true
    run "$APF" --la
    assert_success
    assert_output --partial "192.0.2.50"
    # Clean up
    "$APF" -u 192.0.2.50 2>/dev/null || true
}

@test "apf --ld shows deny_hosts entries after adding a host" {
    "$APF" -s 2>/dev/null || true
    "$APF" -d 198.51.100.50 "test deny" 2>/dev/null || true
    run "$APF" --ld
    assert_success
    assert_output --partial "198.51.100.50"
    # Clean up
    "$APF" -u 198.51.100.50 2>/dev/null || true
}

@test "apf --list-allow is alias for --la" {
    echo "# comment line" > "$APF_DIR/allow_hosts.rules"
    run "$APF" --list-allow
    assert_success
    assert_output --partial "No entries"
}

# --- --rules ---

@test "apf --rules outputs rules to stdout" {
    "$APF" -s 2>/dev/null || true
    run "$APF" --rules
    assert_success
    # Output should contain iptables -S format lines (policies or appended rules)
    assert_output --partial "-P"
}

@test "apf --rules is pipeable (contains -A rules after start)" {
    "$APF" -s 2>/dev/null || true
    local count
    count=$("$APF" --rules | grep -c '^-A' || echo 0)
    [ "$count" -gt 0 ]
}

@test "apf --rules includes IPv6 separator when USE_IPV6=1" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    "$APF" -s 2>/dev/null || true
    run "$APF" --rules
    assert_success
    assert_output --partial "# === IPv6 ==="
    apf_set_config "USE_IPV6" "0"
}

# --- --info ---

@test "apf --info shows status header and trust/config sections" {
    "$APF" -s 2>/dev/null || true
    run "$APF" --info
    assert_success
    # Status header
    assert_output --partial "Firewall Status"
    assert_output --partial "Active:"
    assert_output --partial "Interface:"
    assert_output --partial "IPv6:"
    assert_output --partial "DEVEL_MODE:"
    # Trust section
    assert_output --partial "Trust System:"
    assert_output --partial "Allow entries:"
    assert_output --partial "Deny entries:"
    assert_output --partial "Temp entries:"
    assert_output --partial "FQDN resolution:"
    # Filtering section
    assert_output --partial "Filtering:"
    assert_output --partial "TCP stop:"
    assert_output --partial "Inbound TCP:"
    assert_output --partial "Packet sanity:"
    assert_output --partial "SYN flood:"
    assert_output --partial "SMTP blocking:"
}

@test "apf --info shows subsystems and logging sections" {
    "$APF" -s 2>/dev/null || true
    run "$APF" --info
    assert_success
    # Subsystems section
    assert_output --partial "Subsystems:"
    assert_output --partial "Fast load:"
    assert_output --partial "RAB:"
    assert_output --partial "VNET:"
    assert_output --partial "ipset:"
    assert_output --partial "Remote lists:"
    # Logging section
    assert_output --partial "Logging:"
    assert_output --partial "Log file:"
    assert_output --partial "Log drops:"
    assert_output --partial "Recent log:"
}

# --- --lookup ---

@test "apf --lookup with allowed host shows ALLOW" {
    "$APF" -s 2>/dev/null || true
    "$APF" -a 192.0.2.80 "lookup test" 2>/dev/null || true
    run "$APF" --lookup 192.0.2.80
    assert_success
    assert_output --partial "ALLOW"
    assert_output --partial "192.0.2.80"
    "$APF" -u 192.0.2.80 2>/dev/null || true
}

@test "apf --lookup with denied host shows DENY" {
    "$APF" -s 2>/dev/null || true
    "$APF" -d 198.51.100.80 "lookup deny test" 2>/dev/null || true
    run "$APF" --lookup 198.51.100.80
    assert_success
    assert_output --partial "DENY"
    assert_output --partial "198.51.100.80"
    "$APF" -u 198.51.100.80 2>/dev/null || true
}

@test "apf --lookup with unknown host exits 1" {
    run "$APF" --lookup 203.0.113.254
    assert_failure
    assert_output --partial "not found"
}

@test "apf --lookup with no argument shows usage" {
    run "$APF" --lookup
    assert_failure
    assert_output --partial "usage:"
}

@test "apf --lookup IP finds FQDN entry via resolved metadata" {
    "$APF" -s 2>/dev/null || true
    local allow_file="/opt/apf/allow_hosts.rules"
    # Add an FQDN entry with resolved= metadata (simulates prior add)
    echo "# added test.example.com on 03/28/26 14:00:00 addedtime=1774900800 resolved=192.0.2.99" >> "$allow_file"
    echo "test.example.com" >> "$allow_file"

    run "$APF" --lookup 192.0.2.99
    assert_success
    assert_output --partial "FQDN: test.example.com"

    # Cleanup
    sed -i '/test\.example\.com/d' "$allow_file"
}

# --- hidden alias regression ---

@test "apf -st still works (exits 0)" {
    run "$APF" -st
    assert_success
    assert_output --partial "apf"
}


@test "apf --help does not show Internal section" {
    run "$APF" --help
    assert_success
    refute_output --partial "Internal:"
}

@test "apf --help hides -st alias" {
    run "$APF" --help
    assert_success
    refute_output --partial "-st,"
    refute_output --partial "-st "
}

@test "apf --help hides --temp-expire" {
    run "$APF" --help
    assert_success
    refute_output --partial "--temp-expire"
}

# --- validate_config: SYNCOOKIES/OVERFLOW mutual exclusion (F-047) ---

@test "apf --validate rejects SYSCTL_SYNCOOKIES + SYSCTL_OVERFLOW both enabled" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYSCTL_SYNCOOKIES" "1"
    apf_set_config "SYSCTL_OVERFLOW" "1"
    run "$APF" --validate
    assert_failure
    assert_output --partial "SYSCTL_SYNCOOKIES"
    assert_output --partial "SYSCTL_OVERFLOW"
}

@test "apf --validate passes with only SYSCTL_SYNCOOKIES enabled" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYSCTL_SYNCOOKIES" "1"
    apf_set_config "SYSCTL_OVERFLOW" "0"
    run "$APF" --validate
    assert_success
}

# --- firewall failure propagation ---
# NOTE: The original F-052 test injected `exit 42` into the separate
# files/firewall script. That script is now absorbed as firewall_full_load()
# in apf_core.sh (runs in-process). Fatal exit from _verify_iface_route()
# terminates APF directly; the EXIT trap ensures cleanup. Interface failure
# cannot be tested with VF_ROUTE=0 (Docker default). The start success path
# is covered by tests/01-install-cli.bats and numerous other test files.
