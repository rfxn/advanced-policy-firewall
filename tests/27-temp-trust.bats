#!/usr/bin/env bats
#
# 27: Temporary allow/deny with per-entry TTL
#
# Validates -ta/--temp-allow, -td/--temp-deny, --templ/--temp-list,
# --tempf/--temp-flush, --temp-expire, TTL parsing, and expirebans
# interaction with ttl= entries.

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
    if ip6tables_available; then
        apf_set_config "USE_IPV6" "1"
    fi
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    # Clean up test IPs from trust files and iptables
    for host in 192.0.2.50 192.0.2.51 192.0.2.52 192.0.2.53 192.0.2.54 "2001:db8::50"; do
        local escaped
        escaped=$(echo "$host" | sed 's/[.\/\:]/\\&/g')
        sed -i "/${escaped}/d" "$APF_DIR/allow_hosts.rules" 2>/dev/null || true
        sed -i "/${escaped}/d" "$APF_DIR/deny_hosts.rules" 2>/dev/null || true
    done
    iptables -F TALLOW 2>/dev/null || true
    iptables -F TDENY 2>/dev/null || true
    ip6tables -F TALLOW 2>/dev/null || true
    ip6tables -F TDENY 2>/dev/null || true
}

# =====================================================================
# Temp allow (-ta)
# =====================================================================

@test "-ta adds host to allow_hosts.rules with ttl= marker" {
    run "$APF" -ta 192.0.2.50 300 "temp test"
    assert_success
    run grep "ttl=300 expire=" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "^192.0.2.50$" "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "-ta adds host to TALLOW chain" {
    "$APF" -ta 192.0.2.50 300
    assert_rule_exists_ips TALLOW "-s 192.0.2.50.*-j ACCEPT"
    assert_rule_exists_ips TALLOW "-d 192.0.2.50.*-j ACCEPT"
}

@test "-ta with comment records comment in file" {
    "$APF" -ta 192.0.2.50 300 "my temp comment"
    run grep "with comment: my temp comment" "$APF_DIR/allow_hosts.rules"
    assert_success
}

# =====================================================================
# Temp deny (-td)
# =====================================================================

@test "-td adds host to deny_hosts.rules with ttl= marker" {
    run "$APF" -td 192.0.2.51 600 "temp deny"
    assert_success
    run grep "ttl=600 expire=" "$APF_DIR/deny_hosts.rules"
    assert_success
    run grep "^192.0.2.51$" "$APF_DIR/deny_hosts.rules"
    assert_success
}

@test "-td adds host to TDENY chain" {
    "$APF" -td 192.0.2.51 600
    assert_rule_exists_ips TDENY "192.0.2.51"
}

# =====================================================================
# Validation
# =====================================================================

@test "-ta rejects duplicate host" {
    "$APF" -ta 192.0.2.50 300 "first"
    run "$APF" -ta 192.0.2.50 300 "second"
    assert_success
    assert_output --partial "already exists"
}

@test "-ta rejects invalid host" {
    run "$APF" -ta "not-valid" 300
    assert_output --partial "Invalid host"
}

@test "-ta rejects invalid TTL" {
    run "$APF" -ta 192.0.2.50 "abc"
    assert_output --partial "Invalid TTL"
}

@test "-ta rejects zero TTL" {
    run "$APF" -ta 192.0.2.50 "0"
    assert_output --partial "Invalid TTL"
}

@test "-ta rejects missing TTL" {
    run "$APF" -ta 192.0.2.50
    assert_output --partial "TTL value is required"
}

@test "-ta with no host shows error" {
    run "$APF" -ta
    assert_output --partial "FQDN or IP address is required"
}

# =====================================================================
# TTL parsing
# =====================================================================

@test "parse_ttl parses bare seconds (300)" {
    "$APF" -ta 192.0.2.50 300
    run grep "ttl=300 " "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "parse_ttl parses minutes suffix (5m)" {
    "$APF" -ta 192.0.2.50 5m
    run grep "ttl=300 " "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "parse_ttl parses hours suffix (1h)" {
    "$APF" -ta 192.0.2.50 1h
    run grep "ttl=3600 " "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "parse_ttl parses days suffix (7d)" {
    "$APF" -ta 192.0.2.50 7d
    run grep "ttl=604800 " "$APF_DIR/allow_hosts.rules"
    assert_success
}

@test "parse_ttl rejects non-numeric" {
    run "$APF" -ta 192.0.2.50 "fivem"
    assert_output --partial "Invalid TTL"
}

# =====================================================================
# Expiry (--temp-expire)
# =====================================================================

@test "--temp-expire removes expired entry" {
    # Inject an entry with past expiry epoch
    local past_epoch=$(($(date +%s) - 100))
    echo "# added 192.0.2.52 on 01/01/26 00:00:00 ttl=60 expire=$past_epoch with comment: expired" >> "$APF_DIR/allow_hosts.rules"
    echo "192.0.2.52" >> "$APF_DIR/allow_hosts.rules"
    # Add to iptables so removal works
    iptables -I TALLOW -s 192.0.2.52 -j ACCEPT 2>/dev/null || true
    iptables -I TALLOW -d 192.0.2.52 -j ACCEPT 2>/dev/null || true

    "$APF" --temp-expire

    # Entry should be gone from file
    run grep "192.0.2.52" "$APF_DIR/allow_hosts.rules"
    assert_failure
}

@test "--temp-expire preserves non-expired entry" {
    # Inject an entry with future expiry epoch
    local future_epoch=$(($(date +%s) + 9999))
    echo "# added 192.0.2.53 on 01/01/26 00:00:00 ttl=9999 expire=$future_epoch" >> "$APF_DIR/allow_hosts.rules"
    echo "192.0.2.53" >> "$APF_DIR/allow_hosts.rules"

    "$APF" --temp-expire

    # Entry should still be there
    run grep "192.0.2.53" "$APF_DIR/allow_hosts.rules"
    assert_success
}

# =====================================================================
# Listing (--templ)
# =====================================================================

@test "--templ lists temp entries with remaining TTL" {
    local future_epoch=$(($(date +%s) + 3600))
    echo "# added 192.0.2.50 on 01/01/26 00:00:00 ttl=3600 expire=$future_epoch with comment: test list" >> "$APF_DIR/allow_hosts.rules"
    echo "192.0.2.50" >> "$APF_DIR/allow_hosts.rules"

    run "$APF" --templ
    assert_success
    assert_output --partial "ALLOW"
    assert_output --partial "192.0.2.50"
    assert_output --partial "ttl=3600s"
    assert_output --partial "remains="
    assert_output --partial "test list"
}

@test "--templ shows empty message when no temp entries" {
    # Ensure no ttl= entries exist
    sed -i '/ttl=/d' "$APF_DIR/allow_hosts.rules"
    sed -i '/ttl=/d' "$APF_DIR/deny_hosts.rules"

    run "$APF" --templ
    assert_success
    assert_output --partial "No temporary entries."
}

# =====================================================================
# Flushing (--tempf)
# =====================================================================

@test "--tempf removes all temp entries from files and chains" {
    "$APF" -ta 192.0.2.50 1h "flush test 1"
    "$APF" -td 192.0.2.51 1h "flush test 2"

    # Verify they exist
    run grep "ttl=" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "ttl=" "$APF_DIR/deny_hosts.rules"
    assert_success

    run "$APF" --tempf
    assert_success
    assert_output --partial "2 temporary trust entries"

    # Entries should be gone from files
    run grep "192.0.2.50" "$APF_DIR/allow_hosts.rules"
    assert_failure
    run grep "192.0.2.51" "$APF_DIR/deny_hosts.rules"
    assert_failure
}

# =====================================================================
# expirebans interaction
# =====================================================================

@test "expirebans skips ttl= entries" {
    # Set up expiry so expirebans would run during refresh
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_EXPIRE" "60"
    apf_set_config "SET_REFRESH" "1"

    # Inject a ttl= entry with old date — expirebans should skip it
    echo "# added 192.0.2.54 on 01/01/20 00:00:00 ttl=999999 expire=9999999999" >> "$APF_DIR/deny_hosts.rules"
    echo "192.0.2.54" >> "$APF_DIR/deny_hosts.rules"

    # Restart firewall with new config, then run refresh which calls expirebans
    "$APF" -f 2>/dev/null
    "$APF" -s
    "$APF" -e 2>/dev/null || true

    # ttl= entry should still be there (not expired by expirebans)
    run grep "192.0.2.54" "$APF_DIR/deny_hosts.rules"
    assert_success
}

# =====================================================================
# apf -u interaction
# =====================================================================

@test "apf -u removes temp entry" {
    "$APF" -ta 192.0.2.50 1h "remove test"

    # Verify it exists
    run grep "192.0.2.50" "$APF_DIR/allow_hosts.rules"
    assert_success

    # Remove it
    run "$APF" -u 192.0.2.50
    assert_success

    # IP line should be gone
    run grep "^192.0.2.50$" "$APF_DIR/allow_hosts.rules"
    assert_failure
}

# =====================================================================
# IPv6
# =====================================================================

@test "-ta with IPv6 host" {
    if ! ip6tables_available; then skip "ip6tables not available"; fi
    run "$APF" -ta 2001:db8::50 1h "ipv6 temp"
    assert_success
    run grep "2001:db8::50" "$APF_DIR/allow_hosts.rules"
    assert_success
    assert_rule_exists_ip6s TALLOW "-s 2001:db8::50"
    assert_rule_exists_ip6s TALLOW "-d 2001:db8::50"
}
