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
# Validation tests — functions.apf detection helpers
# ============================================================

# Source just functions.apf for lightweight unit tests (internals.conf does
# network detection that fails without full interface setup)
_source_funcs='source '"$APF_DIR"'/internals/functions.apf; CC_DENY_HOSTS='"$APF_DIR"'/cc_deny.rules; CC_ALLOW_HOSTS='"$APF_DIR"'/cc_allow.rules'

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

@test "geoip_cc_name maps US to United States" {
    run bash -c "$_source_funcs; geoip_cc_name US"
    assert_output "United States"
}

@test "geoip_cc_name returns bare code for unknown CC" {
    run bash -c "$_source_funcs; geoip_cc_name ZZ"
    assert_output "ZZ"
}

# ============================================================
# geoip_lib integration regression — verify library-backed functions
# ============================================================

@test "geoip_lib is sourced by functions.apf" {
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
    run bash -c 'source '"$APF_DIR"'/internals/internals.conf; USE_IPSET=0; IPSET=""; source '"$APF_DIR"'/internals/geoip.apf; geoip_validate_config'
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
