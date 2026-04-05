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

@test "unknown option exits 1" {
    run "$APF" --badopt
    assert_failure
}

@test "apf --help shows section headers" {
    run "$APF" --help
    assert_success
    assert_output --partial "COMMANDS:"
    assert_output --partial "SUBCOMMANDS:"
    assert_output --partial "UTILITIES:"
}

@test "apf -h includes subcommand groups in output" {
    run "$APF" -h
    assert_success
    assert_output --partial "trust"
    assert_output --partial "cc"
    assert_output --partial "config"
    assert_output --partial "status"
    assert_output --partial "gre"
    assert_output --partial "ipset"
    assert_output --partial "ct"
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

# --- subcommand dispatch (G1) ---

@test "apf trust add routes to cli_trust" {
    "$APF" -s >/dev/null 2>&1 || true
    run "$APF" trust add 192.0.2.1 "test add"
    assert_success
    assert_output --partial "192.0.2.1"
}

@test "apf trust deny routes to cli_trust" {
    "$APF" -s >/dev/null 2>&1 || true
    run "$APF" trust deny 192.0.2.1 "test deny"
    assert_success
    assert_output --partial "192.0.2.1"
}

@test "apf trust remove routes to trust remove" {
    "$APF" -s >/dev/null 2>&1 || true
    "$APF" trust add 192.0.2.50 "remove test" >/dev/null 2>&1 || true
    run "$APF" trust remove 192.0.2.50
    assert_success
    assert_output --partial "192.0.2.50"
}

# "apf config validate succeeds" — PRUNED (covered by uat/14-subcommand-dispatch.bats:140
# and legacy form at line 67 above with output assertion)

@test "apf config dump outputs config variables" {
    run "$APF" config dump
    assert_success
    assert_output --partial "INSTALL_PATH"
}

@test "apf status shows firewall status summary" {
    "$APF" -s >/dev/null 2>&1 || true
    run "$APF" status
    assert_success
    assert_output --partial "Firewall Status"
}

@test "apf status rules outputs iptables rules" {
    "$APF" -s >/dev/null 2>&1 || true
    run "$APF" status rules
    assert_success
    assert_output --partial "-A"
}

@test "apf status log exits 0" {
    PAGER=cat run "$APF" status log
    assert_success
}

# --- per-group help (G3) ---

@test "apf trust --help shows trust verbs" {
    run "$APF" trust --help
    assert_success
    assert_output --partial "add HOST"
    assert_output --partial "deny HOST"
    assert_output --partial "remove HOST"
    assert_output --partial "lookup HOST"
}

@test "apf trust (bare) shows help" {
    run "$APF" trust
    assert_success
    assert_output --partial "usage: apf trust"
}

@test "apf config --help shows config verbs" {
    run "$APF" config --help
    assert_success
    assert_output --partial "dump"
    assert_output --partial "validate"
}

@test "apf status --help shows status verbs" {
    run "$APF" status --help
    assert_success
    assert_output --partial "rules"
    assert_output --partial "log"
}

# --- Tier 1 vs Tier 2 equivalence (G4) ---

@test "Tier 1 -o matches Tier 2 config dump output" {
    run "$APF" -o
    # Strip volatile TIME= line to avoid race across second boundary
    local tier1_output
    tier1_output=$(echo "$output" | grep -v '^TIME=')
    run "$APF" config dump
    local tier2_output
    tier2_output=$(echo "$output" | grep -v '^TIME=')
    assert_equal "$tier2_output" "$tier1_output"
}

@test "Tier 1 -a matches Tier 2 trust add behavior" {
    "$APF" -s >/dev/null 2>&1 || true
    run "$APF" -a 192.0.2.70 "tier1 test"
    assert_success
    assert_output --partial "192.0.2.70"
    "$APF" -u 192.0.2.70 >/dev/null 2>&1 || true
    run "$APF" trust add 192.0.2.70 "tier2 test"
    assert_success
    assert_output --partial "192.0.2.70"
}

@test "Tier 1 -u matches Tier 2 trust remove behavior" {
    "$APF" -s >/dev/null 2>&1 || true
    "$APF" -a 192.0.2.71 "equiv test" >/dev/null 2>&1 || true
    run "$APF" -u 192.0.2.71
    assert_success
    assert_output --partial "192.0.2.71"
    "$APF" trust add 192.0.2.72 "equiv test" >/dev/null 2>&1 || true
    run "$APF" trust remove 192.0.2.72
    assert_success
    assert_output --partial "192.0.2.72"
}

# --- CSF compat (G5) ---

@test "apf -ar routes to trust remove" {
    "$APF" -s >/dev/null 2>&1 || true
    "$APF" trust add 192.0.2.60 "csf test" >/dev/null 2>&1 || true
    run "$APF" -ar 192.0.2.60
    assert_success
    assert_output --partial "192.0.2.60"
}

@test "apf -dr routes to trust remove" {
    "$APF" -s >/dev/null 2>&1 || true
    "$APF" trust deny 192.0.2.61 "csf test" >/dev/null 2>&1 || true
    run "$APF" -dr 192.0.2.61
    assert_success
    assert_output --partial "192.0.2.61"
}

@test "apf --csf-help shows mapping table" {
    run "$APF" --csf-help
    assert_success
    assert_output --partial "CSF-to-APF"
    assert_output --partial "csf -a"
    assert_output --partial "csf -d"
}

# --- completion (G6) ---

@test "completion script sources without error" {
    local comp_file
    if [ -f /etc/bash_completion.d/apf ]; then
        comp_file="/etc/bash_completion.d/apf"
    elif [ -f /opt/tests/apf.bash-completion ]; then
        comp_file="/opt/tests/apf.bash-completion"
    else
        skip "completion script not found"
    fi
    run bash -n "$comp_file"
    assert_success
}

# --- unknown verb / edge cases (G7, E9) ---

@test "apf trust flush without target exits 1 with error" {
    run "$APF" trust flush
    assert_failure
    assert_output --partial "expected --temp"
}

# --- color infrastructure (Phase 1) ---

@test "apf -h piped output contains no ANSI escape codes" {
    local output_text
    output_text=$("$APF" -h 2>&1)
    # ANSI escapes use ESC (0x1b) character — portable detection without grep -P
    if printf '%s' "$output_text" | grep -q $'\x1b\['; then
        echo "Found ANSI escapes in piped output" >&2
        return 1
    fi
}

@test "apf -h still shows section headers" {
    run "$APF" -h
    assert_success
    assert_output --partial "COMMANDS:"
    assert_output --partial "SUBCOMMANDS:"
    assert_output --partial "UTILITIES:"
}

# --- Levenshtein / did-you-mean unit tests (Phase 2) ---

@test "_cli_did_you_mean finds closest match for typo" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _cli_did_you_mean trsut 'trust cc config status gre ipset ct'"
    assert_success
    assert_output "trust"
}

@test "_cli_did_you_mean returns empty for unrelated input" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _cli_did_you_mean zzzzzzz 'trust cc config status gre ipset ct'"
    assert_success
    assert_output ""
}

@test "_cli_did_you_mean returns empty for exact match (distance 0)" {
    run bash -c "source $APF_DIR/conf.apf; source $APF_DIR/internals/internals.conf; source $APF_DIR/internals/apf.lib.sh; _cli_did_you_mean trust 'trust cc config status gre ipset ct'"
    assert_success
    assert_output ""
}

# --- progressive disclosure (Phase 3) ---

@test "apf -h shows brief help (usage line)" {
    run "$APF" -h
    assert_success
    assert_output --partial "usage: apf"
    assert_output --partial "COMMANDS:"
}

@test "apf --help falls back to brief help when man page unavailable" {
    # In Docker test containers, man page may not be installed
    if man -w apf >/dev/null 2>&1; then
        skip "man page is installed — cannot test fallback"
    fi
    run "$APF" --help
    assert_success
    assert_output --partial "usage: apf"
}

@test "apf -h shows --help opens manual hint" {
    run "$APF" -h
    assert_success
    assert_output --partial "open full manual page"
}

# --- examples in help (Phase 4) ---

@test "apf trust --help includes examples" {
    run "$APF" trust --help
    assert_success
    assert_output --partial "Examples:"
}

@test "apf config --help includes examples" {
    run "$APF" config --help
    assert_success
    assert_output --partial "Examples:"
}

@test "apf status --help includes examples" {
    run "$APF" status --help
    assert_success
    assert_output --partial "Examples:"
}

# --- help subcommand (Phase 5) ---

@test "apf help shows brief help" {
    run "$APF" help
    assert_success
    assert_output --partial "usage: apf"
}

@test "apf help trust shows trust help" {
    run "$APF" help trust
    assert_success
    assert_output --partial "usage: apf trust"
}

@test "apf help cc shows cc help" {
    run "$APF" help cc
    assert_success
    assert_output --partial "usage: apf cc"
}

@test "apf help config shows config help" {
    run "$APF" help config
    assert_success
    assert_output --partial "usage: apf config"
}

@test "apf help status shows status help" {
    run "$APF" help status
    assert_success
    assert_output --partial "usage: apf status"
}

@test "apf help badnoun exits 1 with error" {
    run "$APF" help badnoun
    assert_failure
    assert_output --partial "unknown topic"
}

@test "apf trust add --help shows trust help (not host error)" {
    run "$APF" trust add --help
    assert_success
    assert_output --partial "usage: apf trust"
}

@test "apf trust temp add --help shows temp help" {
    run "$APF" trust temp add --help
    assert_success
    assert_output --partial "usage: apf trust temp"
}

# --- targeted error messages (Phase 6) ---

@test "apf unknown command shows targeted error" {
    run "$APF" badcmd
    assert_failure
    assert_output --partial "unknown command 'badcmd'"
}

@test "apf typo suggests closest command" {
    run "$APF" trsut
    assert_failure
    assert_output --partial "Did you mean"
    assert_output --partial "trust"
}

@test "apf trust unknown verb shows targeted error" {
    run "$APF" trust badverb
    assert_failure
    assert_output --partial "unknown verb 'badverb'"
}

@test "apf trust typo suggests closest verb" {
    run "$APF" trust addd
    assert_failure
    assert_output --partial "Did you mean"
    assert_output --partial "add"
}

@test "apf config typo suggests closest verb" {
    run "$APF" config valdate
    assert_failure
    assert_output --partial "Did you mean"
    assert_output --partial "validate"
}

@test "apf completely wrong command shows See hint (no suggestion)" {
    run "$APF" zzzzzzz
    assert_failure
    assert_output --partial "See 'apf --help'"
}
