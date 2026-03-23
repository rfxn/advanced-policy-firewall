#!/usr/bin/env bats
#
# 35: GeoIP Country Code Filtering — country-level IP blocking via ipset
#
# Tests use pre-populated CC data fixtures with RFC 5737 (192.0.2.0/24,
# 198.51.100.0/24) and RFC 3849 (2001:db8::/32) addresses to avoid
# network dependencies in CI.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash
source /opt/tests/helpers/capability-detect.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup() {
    if ! ipset_available; then skip "ipset not available"; fi
}

# --- Fixture helpers ---

# Create pre-populated IPv4 GeoIP cache for test country "ZZ"
create_cc_fixture_v4() {
    local cc="${1:-ZZ}"
    mkdir -p "$APF_DIR/geoip"
    cat > "$APF_DIR/geoip/${cc}.4" <<'EOF'
192.0.2.0/24
198.51.100.0/24
EOF
    chmod 640 "$APF_DIR/geoip/${cc}.4"
}

# Create pre-populated IPv6 GeoIP cache for test country "ZZ"
create_cc_fixture_v6() {
    local cc="${1:-ZZ}"
    mkdir -p "$APF_DIR/geoip"
    cat > "$APF_DIR/geoip/${cc}.6" <<'EOF'
2001:db8::/32
EOF
    chmod 640 "$APF_DIR/geoip/${cc}.6"
}

# Create a second test country "YY" for multi-country tests
create_cc_fixture_v4_yy() {
    mkdir -p "$APF_DIR/geoip"
    cat > "$APF_DIR/geoip/YY.4" <<'EOF'
203.0.113.0/24
EOF
    chmod 640 "$APF_DIR/geoip/YY.4"
}

# Clean CC state (rules files, cache, ipsets)
clean_cc_state() {
    # Reset rules files to empty (comments only)
    sed -i '/^[^#]/d' "$APF_DIR/cc_deny.rules" 2>/dev/null || true
    sed -i '/^# added /d' "$APF_DIR/cc_deny.rules" 2>/dev/null || true
    sed -i '/^[^#]/d' "$APF_DIR/cc_allow.rules" 2>/dev/null || true
    sed -i '/^# added /d' "$APF_DIR/cc_allow.rules" 2>/dev/null || true
    # Destroy test ipsets
    ipset destroy apf_cc4_ZZ 2>/dev/null || true
    ipset destroy apf_cc6_ZZ 2>/dev/null || true
    ipset destroy apf_cc4_YY 2>/dev/null || true
    ipset destroy apf_cc6_YY 2>/dev/null || true
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
    apf_set_config "USE_IPSET" "1"
    apf_set_config "LOG_DROP" "1"
    apf_set_config "CC_LOG" "1"
    apf_set_config "CC_LOG_ONLY" "0"
    apf_set_config "CC_SRC" "auto"
    apf_set_config "CC_IPV6" "1"

    # Disable geoip_lib network downloads so test fixtures are preserved.
    # geoip_lib.sh discovers curl/wget at source time via GEOIP_CURL_BIN/WGET_BIN;
    # pointing them at /bin/false forces _geoip_download_cmd() to fail, leaving
    # the pre-populated fixture data in $CC_DATA_DIR intact. Must be non-empty
    # because geoip_lib uses :- (empty triggers default discovery).
    export GEOIP_CURL_BIN="/bin/false"
    export GEOIP_WGET_BIN="/bin/false"

    # Create test data fixtures
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v6 "ZZ"
    create_cc_fixture_v4_yy

    # Start with empty CC rules (firewall runs without GeoIP)
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    clean_cc_state
    rm -rf "$APF_DIR/geoip"
    source /opt/tests/helpers/teardown-netns.sh 2>/dev/null || true
}

# ============================================================
# Validation tests — apf.lib.sh detection helpers
# ============================================================

# Source apf.lib.sh for lightweight unit tests (internals.conf does
# network detection that fails without full interface setup)
_source_funcs='source '"$APF_DIR"'/internals/apf.lib.sh; CC_DENY_HOSTS='"$APF_DIR"'/cc_deny.rules; CC_ALLOW_HOSTS='"$APF_DIR"'/cc_allow.rules'

@test "valid_cc accepts 2-letter uppercase country code" {
    run bash -c "$_source_funcs; valid_cc CN && echo \$_VCC_TYPE"
    assert_success
    assert_output "country"
}

@test "valid_cc rejects lowercase country code" {
    run bash -c "$_source_funcs; valid_cc cn"
    assert_failure
}

@test "valid_cc rejects 3-letter input" {
    run bash -c "$_source_funcs; valid_cc USA"
    assert_failure
}

@test "valid_cc rejects single letter" {
    run bash -c "$_source_funcs; valid_cc A"
    assert_failure
}

@test "valid_cc accepts continent shorthand @EU" {
    run bash -c "$_source_funcs; valid_cc @EU && echo \$_VCC_TYPE"
    assert_success
    assert_output "continent"
}

@test "valid_cc rejects invalid continent @XX" {
    run bash -c "$_source_funcs; valid_cc @XX"
    assert_failure
}

@test "cc_enabled returns false when rules files are empty" {
    clean_cc_state
    run bash -c "$_source_funcs; cc_enabled"
    assert_failure
}

@test "cc_enabled returns true when cc_deny.rules has entry" {
    clean_cc_state
    echo "ZZ" >> "$APF_DIR/cc_deny.rules"
    run bash -c "$_source_funcs; cc_enabled"
    assert_success
    # Clean up
    sed -i '/^ZZ$/d' "$APF_DIR/cc_deny.rules"
}

@test "geoip_expand_codes expands @SA to South American countries" {
    run bash -c "$_source_funcs; geoip_expand_codes @SA && echo \$_VCC_CODES"
    assert_success
    assert_output --partial "BR"
    assert_output --partial "AR"
    assert_output --partial "CL"
}

@test "geoip_expand_codes rejects unknown @XX" {
    run bash -c "$_source_funcs; geoip_expand_codes @XX"
    assert_failure
}

@test "geoip_cc_name maps CN to China" {
    run bash -c "$_source_funcs; geoip_cc_name CN"
    assert_output "China"
}

@test "geoip_cc_name returns bare code for unknown CC" {
    run bash -c "$_source_funcs; geoip_cc_name ZZ"
    assert_output "ZZ"
}

# ============================================================
# geoip_lib integration regression — verify library-backed functions
# ============================================================

@test "geoip_lib is sourced by apf.lib.sh" {
    run bash -c "$_source_funcs; [[ -n \$_GEOIP_LIB_LOADED ]]"
    assert_success
}

@test "valid_cc bridges _GEOIP_VCC_CODES to _VCC_CODES for country" {
    run bash -c "$_source_funcs; valid_cc CN && echo \$_VCC_CODES"
    assert_success
    assert_output "CN"
}

@test "valid_cc bridges _GEOIP_VCC_CODES to _VCC_CODES for continent" {
    run bash -c "$_source_funcs; valid_cc @AF && echo \$_VCC_CODES"
    assert_success
    # Verify @AF expands to include some known African countries
    assert_output --partial "ZA"
    assert_output --partial "NG"
}

@test "geoip_expand_codes uses geoip_lib module-level continent lists" {
    run bash -c "$_source_funcs; geoip_expand_codes @AF && echo \$_VCC_CODES"
    assert_success
    # Count CCs — Africa has 57 countries in the list
    local cc_count
    cc_count=$(echo "$output" | tr ',' '\n' | wc -l)
    [ "$cc_count" -ge 50 ]
}

@test "geoip_cc_continent available via geoip_lib" {
    run bash -c "$_source_funcs; geoip_cc_continent CN"
    assert_success
    assert_output "@AS"
}

@test "geoip_continent_name available via geoip_lib" {
    run bash -c "$_source_funcs; geoip_continent_name @EU"
    assert_success
    assert_output "Europe"
}

# ============================================================
# Chain architecture — CC chains with ipset match-set rules
# ============================================================

@test "apf -d ZZ creates CC_DENY chain with ipset match" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "test block"

    assert_chain_exists CC_DENY
    assert_rule_exists_ips CC_DENY "match-set apf_cc4_ZZ src"
    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "apf -d ZZ populates ipset apf_cc4_ZZ" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "test block"

    run ipset list apf_cc4_ZZ
    assert_success
    assert_output --partial "192.0.2.0/24"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "apf -a ZZ creates CC_ALLOW chain" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -a ZZ "test allow"

    assert_chain_exists CC_ALLOW
    assert_rule_exists_ips CC_ALLOW "match-set apf_cc4_ZZ src"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "CC_DENY has LOG rule when CC_LOG=1" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CC_LOG" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "test log"

    assert_rule_exists_ips CC_DENY "LOG.*CC_DENY:ZZ"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "CC entry persisted to cc_deny.rules" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "persist test"

    run grep -Fx "ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "CC entry persisted to cc_allow.rules for allow" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -a ZZ "persist test"

    run grep -Fx "ZZ" "$APF_DIR/cc_allow.rules"
    assert_success

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

# ============================================================
# CLI trust — add, remove, duplicate detection
# ============================================================

@test "apf -u ZZ removes CC from rules file and destroys ipset" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "remove test"

    # Verify it exists first
    run grep -Fx "ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    "$APF" -u ZZ

    # Should be removed from rules file
    run grep -Fx "ZZ" "$APF_DIR/cc_deny.rules"
    assert_failure

    # ipset should be destroyed
    run ipset list apf_cc4_ZZ 2>/dev/null
    assert_failure

    clean_cc_state
}

@test "duplicate CC entry is rejected" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "first"

    # Second add should report duplicate
    run "$APF" -d ZZ "second"
    assert_output --partial "already exists"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "multiple CCs can be blocked independently" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v4_yy
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "block ZZ"
    "$APF" -d YY "block YY"

    run ipset list apf_cc4_ZZ
    assert_success
    run ipset list apf_cc4_YY
    assert_success
    assert_rule_exists_ips CC_DENY "match-set apf_cc4_ZZ src"
    assert_rule_exists_ips CC_DENY "match-set apf_cc4_YY src"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    "$APF" -u YY 2>/dev/null || true
    clean_cc_state
}

# ============================================================
# Temp trust — temporary CC entries with TTL
# ============================================================

@test "apf -td ZZ 1h creates temp CC deny entry" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -td ZZ 1h "temp test"

    # Entry should be in cc_deny.rules
    run grep -Fx "ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Comment should have ttl= marker
    run grep "ttl=" "$APF_DIR/cc_deny.rules"
    assert_success

    # ipset should exist
    run ipset list apf_cc4_ZZ
    assert_success

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "temp CC entry appears in --templ output" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -td ZZ 1h "temp list test"

    run "$APF" --templ
    assert_output --partial "ZZ"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

# ============================================================
# Audit mode — CC_LOG_ONLY=1
# ============================================================

@test "CC_LOG_ONLY=1 creates LOG rules without DROP" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CC_LOG_ONLY" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "audit test"

    # Should have LOG with CC_AUDIT prefix
    assert_rule_exists_ips CC_DENY "LOG.*CC_AUDIT:ZZ"

    # Should NOT have DROP/REJECT action rule for this CC
    run bash -c "iptables -S CC_DENY 2>/dev/null | grep 'apf_cc4_ZZ' | grep -E '(DROP|REJECT)'"
    assert_failure

    # Restore
    apf_set_config "CC_LOG_ONLY" "0"
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

# ============================================================
# IPv6 support
# ============================================================

@test "CC deny creates IPv6 ipset when USE_IPV6=1 and CC_IPV6=1" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v6 "ZZ"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    apf_set_config "CC_IPV6" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "ipv6 test"

    run ipset list apf_cc6_ZZ
    assert_success
    assert_output --partial "2001:db8::/32"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

# ============================================================
# ipset lifecycle — create, populate, flush
# ============================================================

@test "ipset apf_cc4_ZZ uses hash:net type" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "type test"

    run ipset list apf_cc4_ZZ
    assert_success
    assert_output --partial "hash:net"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "apf -f destroys all CC ipsets" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "flush test"

    # Verify ipset exists
    run ipset list apf_cc4_ZZ
    assert_success

    # Flush
    "$APF" -f

    # ipset should be gone
    run ipset list apf_cc4_ZZ 2>/dev/null
    assert_failure

    # CC chains should be gone
    run iptables -L CC_DENY -n 2>/dev/null
    assert_failure

    clean_cc_state
}

@test "CC ipset contains correct CIDR entries" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "content test"

    # Test that IPs within the CIDR ranges are matched
    run ipset test apf_cc4_ZZ 192.0.2.50
    assert_success
    run ipset test apf_cc4_ZZ 198.51.100.1
    assert_success

    # An IP outside the ranges should NOT match
    run ipset test apf_cc4_ZZ 10.0.0.1
    assert_failure

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

# ============================================================
# Full load with CC rules in rules files
# ============================================================

@test "firewall start with cc_deny.rules entry creates chains and ipsets" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    echo "ZZ" >> "$APF_DIR/cc_deny.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    assert_chain_exists CC_DENY
    assert_rule_exists_ips INPUT "CC_DENY"
    run ipset list apf_cc4_ZZ
    assert_success

    # Clean up
    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
}

@test "firewall start without CC entries does not create CC chains" {
    clean_cc_state
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # CC chains should not exist
    run iptables -L CC_DENY -n 2>/dev/null
    assert_failure
    run iptables -L CC_ALLOW -n 2>/dev/null
    assert_failure
}

# ============================================================
# --cc info command
# ============================================================

@test "apf --cc shows inactive when no rules" {
    clean_cc_state
    run "$APF" --cc
    assert_success
    assert_output --partial "inactive"
}

@test "apf --cc shows status when CC rules active" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "info test"

    run "$APF" --cc
    assert_success
    assert_output --partial "Country Code Filtering Status"
    assert_output --partial "Data source"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

# ============================================================
# geoip_validate_config prerequisites
# ============================================================

@test "geoip_validate_config fails when USE_IPSET=0" {
    run bash -c 'source '"$APF_DIR"'/internals/internals.conf; USE_IPSET=0; IPSET=""; source '"$APF_DIR"'/internals/apf_geoip.sh; geoip_validate_config'
    assert_failure
    assert_output --partial "requires ipset"
}

# ============================================================
# Advanced syntax CC entries
# ============================================================

@test "advanced CC entry tcp:in:d=22:s=ZZ creates CC_DENYP chain" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    echo "tcp:in:d=22:s=ZZ" >> "$APF_DIR/cc_deny.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    assert_chain_exists CC_DENYP
    assert_rule_exists_ips CC_DENYP "match-set apf_cc4_ZZ"

    # Clean up
    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
}

# ============================================================
# search and lookup integration
# ============================================================

@test "apf -g ZZ searches CC rules files" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "search test"

    run "$APF" -g ZZ
    assert_success
    assert_output --partial "ZZ"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

# ============================================================
# IPv6 chain rules
# ============================================================

@test "CC deny creates IPv6 chain rules when USE_IPV6=1" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v6 "ZZ"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    apf_set_config "CC_IPV6" "1"
    echo "ZZ" >> "$APF_DIR/cc_deny.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # IPv6 CC_DENY chain should exist with match-set rule
    assert_rule_exists_ip6s CC_DENY "match-set apf_cc6_ZZ"

    # Clean up
    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
}

# ============================================================
# Wildcard expansion in advanced entries
# ============================================================

@test "apf -u removes advanced CC entry added via apf -d" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Add advanced CC entry via CLI
    run "$APF" -d "tcp:in:d=22:s=ZZ" "roundtrip test"
    assert_success

    # Verify it was persisted and loaded
    run grep -c "^tcp:in:d=22:s=ZZ$" "$APF_DIR/cc_deny.rules"
    assert_output "1"
    assert_chain_exists CC_DENYP

    # Remove via -u — this is the regression path (UAT-001)
    run "$APF" -u "tcp:in:d=22:s=ZZ"
    assert_success

    # Verify removed from rules file
    run grep -c "^tcp:in:d=22:s=ZZ$" "$APF_DIR/cc_deny.rules"
    assert_output "0"

    # Clean up
    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
}

@test "wildcard * in advanced entry expands to all simple CCs" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v4_yy
    # Two simple deny entries + one wildcard advanced entry
    printf '%s\n' "ZZ" "YY" "tcp:in:d=22:s=*" >> "$APF_DIR/cc_deny.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # CC_DENYP should have rules for both ZZ and YY (expanded from *)
    assert_chain_exists CC_DENYP
    assert_rule_exists_ips CC_DENYP "match-set apf_cc4_ZZ"
    assert_rule_exists_ips CC_DENYP "match-set apf_cc4_YY"

    # Clean up
    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
}

# --- CC_CACHE_TTL tests ---

@test "CC_CACHE_TTL: fresh cache skips download" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v6 "ZZ"
    : > /var/log/apf_log 2>/dev/null || true

    "$APF" -d ZZ "cache hit test"

    # Cache hit: no download failure logged (download never attempted)
    local dl_failed=0
    grep -q "download failed for ZZ" /var/log/apf_log && dl_failed=1

    clean_cc_state
    [ "$dl_failed" -eq 0 ]
}

@test "CC_CACHE_TTL: stale cache triggers download attempt" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v6 "ZZ"
    # Backdate fixtures to well beyond CC_CACHE_TTL (24h default)
    touch -t 202001011200.00 "$APF_DIR/geoip/ZZ.4"
    touch -t 202001011200.00 "$APF_DIR/geoip/ZZ.6"
    : > /var/log/apf_log 2>/dev/null || true

    "$APF" -d ZZ "stale cache test"

    # Download was attempted (failed with /bin/false mock)
    local dl_attempted=0
    grep -q "download failed for ZZ" /var/log/apf_log && dl_attempted=1

    clean_cc_state
    [ "$dl_attempted" -eq 1 ]
}

@test "CC_CACHE_TTL=0 always attempts download" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v6 "ZZ"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CC_CACHE_TTL" "0"
    : > /var/log/apf_log 2>/dev/null || true

    "$APF" -d ZZ "bypass test"

    # Even with fresh fixture, TTL=0 bypasses cache
    local dl_attempted=0
    grep -q "download failed for ZZ" /var/log/apf_log && dl_attempted=1

    # Restore default before asserting
    apf_set_config "CC_CACHE_TTL" "24"
    clean_cc_state
    [ "$dl_attempted" -eq 1 ]
}

@test "continent expansion shows per-CC progress" {
    clean_cc_state
    : > /var/log/apf_log 2>/dev/null || true

    # @OC expands to ~20 CCs; downloads fail but progress is logged first
    "$APF" -d @OC "progress test" 2>/dev/null || true

    local has_progress=0
    grep -q "(1/" /var/log/apf_log && has_progress=1

    clean_cc_state
    [ "$has_progress" -eq 1 ]
}

@test "geoip_download_all shows download summary for multi-CC" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v4_yy
    echo "ZZ" >> "$APF_DIR/cc_deny.rules"
    echo "YY" >> "$APF_DIR/cc_deny.rules"

    : > /var/log/apf_log 2>/dev/null || true

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    local has_summary=0
    grep -q "IPv4 download summary:" /var/log/apf_log && has_summary=1

    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
    [ "$has_summary" -eq 1 ]
}

# ============================================================
# P3: High-risk gap coverage — IFS/LEXT, implicit deny, fast
# load, temp allow, remove roundtrip, IPv6 exclusion, not-found
# ============================================================

@test "CC_ALLOW implicit deny-all: tail rule blocks unlisted countries" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    echo "ZZ" >> "$APF_DIR/cc_allow.rules"

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    assert_chain_exists CC_ALLOW
    # CC_ALLOW must end with a DROP or REJECT tail rule (implicit deny-all)
    # Default ALL_STOP is DROP in conf.apf
    assert_rule_exists_ips CC_ALLOW "DROP"

    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
}

@test "fast load restores CC ipsets from cache" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    echo "ZZ" >> "$APF_DIR/cc_deny.rules"

    # Full load to create snapshot + ipsets
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Verify ipset exists after full load
    run ipset list apf_cc4_ZZ
    assert_success

    # Enable fast load
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_FASTLOAD" "1"

    # Flush then restart — should use fast load path
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # ipset must exist after fast load (snapshot references it)
    run ipset list apf_cc4_ZZ
    assert_success
    assert_output --partial "192.0.2.0/24"

    # Restore
    apf_set_config "SET_FASTLOAD" "0"
    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
}

@test "LEXT regression: LOG rule contains --log-tcp-options (S-004 fix)" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CC_LOG" "1"
    apf_set_config "LOG_DROP" "1"
    apf_set_config "CC_LOG_ONLY" "0"
    # LOG_EXT=1 enables LEXT="--log-tcp-options --log-ip-options";
    # if IFS=',' leaks into _geoip_add_simple_rules, these two tokens
    # become one mangled argument and iptables silently drops them
    apf_set_config "LOG_EXT" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "lext test"

    # LOG rule must contain individual LEXT tokens (not mangled by IFS=',')
    run iptables -S CC_DENY 2>/dev/null
    assert_success
    assert_output --partial "log-tcp-options"

    # Clean up
    apf_set_config "LOG_EXT" "0"
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "apf -ta ZZ 1h creates CC_ALLOW chain + ipset + TTL markers" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -ta ZZ 1h "temp allow test"

    # CC_ALLOW chain should exist with match-set rule
    assert_chain_exists CC_ALLOW
    assert_rule_exists_ips CC_ALLOW "match-set apf_cc4_ZZ src"

    # ipset should be populated
    run ipset list apf_cc4_ZZ
    assert_success
    assert_output --partial "192.0.2.0/24"

    # TTL markers in cc_allow.rules
    run grep "ttl=" "$APF_DIR/cc_allow.rules"
    assert_success
    run grep "expire=" "$APF_DIR/cc_allow.rules"
    assert_success

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "apf -u ZZ removes both simple and advanced entries" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Add simple deny
    "$APF" -d ZZ "simple"
    # Add advanced deny
    "$APF" -d "tcp:in:d=22:s=ZZ" "advanced"

    # Verify both persisted
    run grep -Fx "ZZ" "$APF_DIR/cc_deny.rules"
    assert_success
    run grep -Fx "tcp:in:d=22:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Remove via -u ZZ — should remove both
    "$APF" -u ZZ

    # Both should be gone from rules file
    run grep -Fx "ZZ" "$APF_DIR/cc_deny.rules"
    assert_failure
    run grep -Fx "tcp:in:d=22:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_failure

    # ipset should be destroyed
    run ipset list apf_cc4_ZZ 2>/dev/null
    assert_failure

    clean_cc_state
}

# ============================================================
# Granular CC advanced trust entry removal (2.0.2)
# ============================================================

@test "apf -u advanced CC entry preserves bare CC entry" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Add both simple and advanced deny entries
    "$APF" -d ZZ "simple block"
    "$APF" -d "tcp:in:d=22:s=ZZ" "advanced ssh block"

    # Verify both are in rules file
    run grep -Fx "ZZ" "$APF_DIR/cc_deny.rules"
    assert_success
    run grep -Fx "tcp:in:d=22:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Remove only the advanced entry
    run "$APF" -u "tcp:in:d=22:s=ZZ"
    assert_success

    # Bare ZZ must still be present in rules file
    run grep -Fx "ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Advanced entry must be gone from rules file
    run grep -Fx "tcp:in:d=22:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_failure

    # ipset must still exist (bare entry still active)
    run ipset list apf_cc4_ZZ
    assert_success

    # CC_DENY chain must still have match-set rule for ZZ (bare entry loaded)
    assert_rule_exists_ips CC_DENY "match-set apf_cc4_ZZ src"

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "apf -u advanced CC entry removes only its iptables rules" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Add two advanced deny entries for different ports
    "$APF" -d "tcp:in:d=22:s=ZZ" "advanced ssh block"
    "$APF" -d "tcp:in:d=443:s=ZZ" "advanced https block"

    # Both entries in rules file
    run grep -Fx "tcp:in:d=22:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_success
    run grep -Fx "tcp:in:d=443:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Remove only the port 22 entry
    run "$APF" -u "tcp:in:d=22:s=ZZ"
    assert_success

    # Port 22 rule must be gone from CC_DENYP
    run bash -c "iptables -S CC_DENYP 2>/dev/null | grep 'apf_cc4_ZZ' | grep -- '--dport 22'"
    assert_failure

    # Port 443 rule must still be in CC_DENYP
    assert_rule_exists_ips CC_DENYP "match-set apf_cc4_ZZ.*dport 443|dport 443.*match-set apf_cc4_ZZ"

    # Port 443 entry must still be in rules file
    run grep -Fx "tcp:in:d=443:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Clean up
    "$APF" -u "tcp:in:d=443:s=ZZ" 2>/dev/null || true
    clean_cc_state
}

@test "targeted CC removal destroys ipset when last entry removed" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Add only an advanced entry (no bare CC)
    "$APF" -d "tcp:in:d=22:s=ZZ" "only rule"

    # Verify entry persisted
    run grep -Fx "tcp:in:d=22:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Remove it — no other ZZ entries remain
    run "$APF" -u "tcp:in:d=22:s=ZZ"
    assert_success

    # ipset must be destroyed (no entries remain for ZZ)
    run ipset list apf_cc4_ZZ 2>/dev/null
    assert_failure

    # No ZZ references in rules file
    run grep "ZZ" "$APF_DIR/cc_deny.rules"
    assert_failure

    clean_cc_state
}

@test "targeted CC removal preserves cache when other entries remain" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Add simple + advanced entries
    "$APF" -d ZZ "simple block"
    "$APF" -d "tcp:in:d=22:s=ZZ" "advanced ssh block"

    # Verify cache exists before removal
    [ -f "$APF_DIR/geoip/ZZ.4" ]

    # Remove only the advanced entry
    run "$APF" -u "tcp:in:d=22:s=ZZ"
    assert_success

    # Cache file must still exist (bare entry still active)
    run test -f "$APF_DIR/geoip/ZZ.4"
    assert_success

    # Clean up
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "targeted CC removal under CC_LOG_ONLY removes LOG rule" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "CC_LOG_ONLY" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Add advanced entry — only LOG rules created, no DROP
    "$APF" -d "tcp:in:d=22:s=ZZ" "audit ssh block"

    # Verify entry in rules file
    run grep -Fx "tcp:in:d=22:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_success

    # Remove the advanced entry
    run "$APF" -u "tcp:in:d=22:s=ZZ"
    assert_success

    # No rules in CC_DENYP matching apf_cc4_ZZ and port 22
    run bash -c "iptables -S CC_DENYP 2>/dev/null | grep 'apf_cc4_ZZ' | grep -- '--dport 22'"
    assert_failure

    # Entry must be gone from rules file
    run grep -Fx "tcp:in:d=22:s=ZZ" "$APF_DIR/cc_deny.rules"
    assert_failure

    # Restore
    apf_set_config "CC_LOG_ONLY" "0"
    clean_cc_state
}

@test "CC_IPV6=0 excludes IPv6 ipset creation" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v6 "ZZ"
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    apf_set_config "CC_IPV6" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
    "$APF" -d ZZ "ipv6 off test"

    # IPv4 ipset should exist
    run ipset list apf_cc4_ZZ
    assert_success

    # IPv6 ipset should NOT exist
    run ipset list apf_cc6_ZZ 2>/dev/null
    assert_failure

    # Clean up
    apf_set_config "CC_IPV6" "1"
    "$APF" -u ZZ 2>/dev/null || true
    clean_cc_state
}

@test "cli_cc_remove reports not-found for never-added CC" {
    clean_cc_state
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    run "$APF" -u XX
    # apf -u does not exit non-zero on not-found, but prints message
    assert_output --partial "not found"

    clean_cc_state
}

@test "mixed deny+allow: both CC_DENY and CC_ALLOW chains populated" {
    clean_cc_state
    create_cc_fixture_v4 "ZZ"
    create_cc_fixture_v4_yy
    echo "ZZ" >> "$APF_DIR/cc_deny.rules"
    echo "YY" >> "$APF_DIR/cc_allow.rules"
    # YY needs v4 fixture too
    mkdir -p "$APF_DIR/geoip"
    cp "$APF_DIR/geoip/YY.4" "$APF_DIR/geoip/YY.4" 2>/dev/null || true

    "$APF" -f 2>/dev/null || true
    "$APF" -s

    # Both chains should exist
    assert_chain_exists CC_DENY
    assert_chain_exists CC_ALLOW
    # Each chain should have its respective match-set rule
    assert_rule_exists_ips CC_DENY "match-set apf_cc4_ZZ src"
    assert_rule_exists_ips CC_ALLOW "match-set apf_cc4_YY src"

    "$APF" -f 2>/dev/null || true
    clean_cc_state
    "$APF" -s
}
