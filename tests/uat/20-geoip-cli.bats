#!/usr/bin/env bats
# 20-geoip-cli.bats — GeoIP Country Code CLI Operator Workflows
# Validates: apf -d/-a/-u CC lifecycle, apf --cc info/detail, apf cc noun
# subcommand dispatch, CC persistence across restart, error messages.
#
# Does NOT duplicate tests/35-geoip.bats (64 unit/integration tests covering
# internal functions, ipset mechanics, chain architecture, cache TTL, LEXT
# regression, wildcard expansion, continent progress). This file tests the
# operator-facing CLI workflows end-to-end.
#
# Fixtures: RFC 5737 (192.0.2.0/24, 198.51.100.0/24) and RFC 3849
# (2001:db8::/32) pre-populated cache. Downloads disabled via /bin/false.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../helpers/assert-iptables'
load '../infra/lib/uat-helpers'

# --- Fixture helpers (adapted from 35-geoip.bats) ---

create_cc_fixtures() {
    mkdir -p "$APF_INSTALL/geoip"
    cat > "$APF_INSTALL/geoip/ZZ.4" <<'FIXTURE'
192.0.2.0/24
198.51.100.0/24
FIXTURE
    cat > "$APF_INSTALL/geoip/ZZ.6" <<'FIXTURE'
2001:db8::/32
FIXTURE
    cat > "$APF_INSTALL/geoip/YY.4" <<'FIXTURE'
203.0.113.0/24
FIXTURE
    chmod 640 "$APF_INSTALL/geoip/ZZ.4" "$APF_INSTALL/geoip/ZZ.6" "$APF_INSTALL/geoip/YY.4"
}

clean_cc_state() {
    # Reset CC rules files to comments-only
    sed -i '/^[^#]/d' "$APF_INSTALL/cc_deny.rules" 2>/dev/null || true
    sed -i '/^# added /d' "$APF_INSTALL/cc_deny.rules" 2>/dev/null || true
    sed -i '/^[^#]/d' "$APF_INSTALL/cc_allow.rules" 2>/dev/null || true
    sed -i '/^# added /d' "$APF_INSTALL/cc_allow.rules" 2>/dev/null || true
    # Destroy test ipsets
    ipset destroy apf_cc4_ZZ 2>/dev/null || true  # safe: may not exist
    ipset destroy apf_cc6_ZZ 2>/dev/null || true  # safe: may not exist
    ipset destroy apf_cc4_YY 2>/dev/null || true  # safe: may not exist
    ipset destroy apf_cc6_YY 2>/dev/null || true  # safe: may not exist
    # Remove lock file (workaround for known flock wrapper gap)
    rm -f "$APF_INSTALL/lock.utime"
}

setup_file() {
    source /opt/tests/helpers/capability-detect.bash
    if ! ipset_available; then return 0; fi

    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
    uat_apf_set_config "USE_IPSET" "1"
    uat_apf_set_config "CC_LOG" "1"
    uat_apf_set_config "LOG_DROP" "1"
    uat_apf_set_config "EGF" "1"
    uat_apf_set_port_config "IG_TCP_CPORTS" "22,80,443"
    uat_apf_set_port_config "EG_TCP_CPORTS" "22,80,443"

    # Disable real downloads — force use of pre-populated fixtures
    export GEOIP_CURL_BIN="/bin/false"
    export GEOIP_WGET_BIN="/bin/false"

    create_cc_fixtures
    apf -s
}

teardown_file() {
    source /opt/tests/helpers/capability-detect.bash
    if ! ipset_available; then return 0; fi
    clean_cc_state
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    source /opt/tests/helpers/capability-detect.bash
    if ! ipset_available; then skip "ipset not available"; fi
    clean_cc_state
    create_cc_fixtures
}

# =========================================================================
# UAT-GC01: Block country via CLI
# Scenario: Sysadmin blocks a country and sees confirmation
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf -d ZZ blocks country and shows confirmation" {
    run apf -d ZZ "block test"
    assert_success
    # Output shows geoip chain and trust summary (not "added" — CC path differs from IP path)
    assert_output --partial "DENY ZZ"
    # Verify CC is in rules file
    grep -Fxq "ZZ" "$APF_INSTALL/cc_deny.rules"
    # Verify ipset was created
    ipset list apf_cc4_ZZ > /dev/null 2>&1
}

# =========================================================================
# UAT-GC02: Allow country via CLI
# Scenario: Sysadmin adds a country to allow list
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf -a ZZ allows country and shows confirmation" {
    run apf -a ZZ "allow test"
    assert_success
    # CC allow output shows chain and trust summary
    assert_output --partial "ALLOW ZZ"
    grep -Fxq "ZZ" "$APF_INSTALL/cc_allow.rules"
}

# =========================================================================
# UAT-GC03: Remove country (full lifecycle)
# Scenario: Sysadmin blocks then unblocks a country
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf -u ZZ removes country after add" {
    apf -d ZZ "to remove"
    grep -Fxq "ZZ" "$APF_INSTALL/cc_deny.rules"

    run apf -u ZZ
    assert_success
    # ZZ should be gone from rules file
    ! grep -Fxq "ZZ" "$APF_INSTALL/cc_deny.rules"
    # Ipset should be destroyed
    ! ipset list apf_cc4_ZZ > /dev/null 2>&1
}

# =========================================================================
# UAT-GC04/GC05: --cc overview/inactive — PRUNED (covered by 35-geoip.bats:617,624)
# =========================================================================

# =========================================================================
# UAT-GC06: --cc with unknown CC shows error
# Scenario: Sysadmin queries detail for a non-existent country code
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf --cc ZZ shows unknown country code error" {
    # ZZ is format-valid but not a known ISO CC — geoip_cc_known() rejects it
    run apf --cc ZZ
    assert_failure
    assert_output --partial "Unknown country code"
}

# =========================================================================
# UAT-GC07: apf cc info noun subcommand
# Scenario: Sysadmin uses 2.0.2 noun subcommand style
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf cc info routes to overview (noun subcommand)" {
    apf -d ZZ "noun test"

    run apf cc info
    assert_success
    assert_output --partial "Country Code Filtering Status"
}

# =========================================================================
# UAT-GC08: apf cc info with unknown CC
# Scenario: Sysadmin uses noun subcommand with non-existent CC
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf cc info ZZ shows unknown error (noun subcommand)" {
    # ZZ passes valid_cc() format check but fails geoip_cc_known()
    run apf cc info ZZ
    assert_failure
    assert_output --partial "Unknown country code"
}

# =========================================================================
# UAT-GC09: apf cc update noun subcommand
# Scenario: Sysadmin triggers GeoIP data refresh
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf cc update completes without error" {
    apf -d ZZ "update test"
    rm -f "$APF_INSTALL/lock.utime"

    run apf cc update
    # Update may report data is fresh (CC_INTERVAL gate) — that is still success
    assert_success
}

# =========================================================================
# UAT-GC10: help cc discoverability
# Scenario: Sysadmin discovers GeoIP commands via help
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf help cc shows GeoIP help text" {
    run apf help cc
    assert_success
    assert_output --partial "apf cc"
    assert_output --partial "info"
    assert_output --partial "lookup"
    assert_output --partial "update"
}

# =========================================================================
# UAT-GC11: Invalid CC input rejection
# Scenario: Sysadmin types an invalid country code
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: apf -d XX99 rejects invalid input with error" {
    run apf -d XX99 "bad"
    assert_failure
}

# =========================================================================
# UAT-GC12: CC deny persists across restart
# Scenario: Sysadmin blocks a country, restarts firewall, verifies rules
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: CC deny persists across restart" {
    apf -d ZZ "persist test"
    # Verify chain exists before restart
    assert_chain_exists CC_DENY

    apf -f
    rm -f "$APF_INSTALL/lock.utime"
    apf -s

    # After restart, CC_DENY chain and ipset should be rebuilt from rules file
    assert_chain_exists CC_DENY
    ipset list apf_cc4_ZZ > /dev/null 2>&1
}

# =========================================================================
# UAT-GC13: CC allow implicit deny survives restart
# Scenario: Sysadmin sets up strict allowlist, restarts, verifies
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: CC allow with implicit deny-all survives restart" {
    apf -a ZZ "allowlist test"
    assert_chain_exists CC_ALLOW

    apf -f
    rm -f "$APF_INSTALL/lock.utime"
    apf -s

    # CC_ALLOW chain should be rebuilt with tail DROP rule
    assert_chain_exists CC_ALLOW
    # The implicit deny-all tail rule uses ALL_STOP (DROP by default)
    assert_rule_exists_ips CC_ALLOW "DROP"
}

# =========================================================================
# UAT-GC14: Mixed IP trust and CC trust coexist
# Scenario: Sysadmin blocks a country AND an individual IP
# =========================================================================

# bats test_tags=uat,uat:geoip
@test "UAT: mixed IP trust and CC trust coexist independently" {
    apf -d 198.51.100.50 "ip block"
    rm -f "$APF_INSTALL/lock.utime"
    apf -d ZZ "cc block"

    # Both should exist independently
    assert_rule_exists_ips TDENY "198.51.100.50"
    assert_chain_exists CC_DENY

    # Remove CC, IP trust should remain
    rm -f "$APF_INSTALL/lock.utime"
    apf -u ZZ
    assert_rule_exists_ips TDENY "198.51.100.50"
}

# UAT-GC15: Duplicate CC — PRUNED (covered by 35-geoip.bats:356)
