#!/usr/bin/env bats
#
# 19: DLIST Chain Loading — blocklist chain creation and download resilience
#
# Tests pre-populate rules files with RFC 5737 test IPs, then set
# DLIST URLs to unreachable targets to force download failure. The
# backup/restore pattern preserves pre-populated entries, which then
# get loaded into iptables chains.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

# Set a DLIST URL config variable (uses % delimiter to avoid sed / conflicts)
apf_set_url() {
    local var="$1" val="$2"
    sed -i "s%^${var}=.*%${var}=\"${val}\"%" "$APF_DIR/conf.apf"
}

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""

    # Pre-populate dlist rules files with RFC 5737 test IPs
    cat > "$APF_DIR/ds_hosts.rules" <<'EOF'
# DShield test entries
192.0.2.30
192.0.2.31
EOF
    chmod 600 "$APF_DIR/ds_hosts.rules"

    cat > "$APF_DIR/php_hosts.rules" <<'EOF'
# PHP test entries
198.51.100.40
198.51.100.41
EOF
    chmod 600 "$APF_DIR/php_hosts.rules"

    cat > "$APF_DIR/sdrop_hosts.rules" <<'EOF'
# SDROP test entries
192.0.2.50/24
198.51.100.0/24
EOF
    chmod 600 "$APF_DIR/sdrop_hosts.rules"

    # Enable all three dlist features with unreachable URLs to force
    # download failure and exercise the backup/restore code path
    apf_set_config "DLIST_DSHIELD" "1"
    apf_set_url "DLIST_DSHIELD_URL" "https://127.0.0.1:1/nonexistent"
    apf_set_config "DLIST_PHP" "1"
    apf_set_url "DLIST_PHP_URL" "https://127.0.0.1:1/nonexistent"
    apf_set_config "DLIST_SPAMHAUS" "1"
    apf_set_url "DLIST_SPAMHAUS_URL" "https://127.0.0.1:1/nonexistent"

    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

# --- DSHIELD ---

@test "DSHIELD chain exists when DLIST_DSHIELD=1 with pre-populated entries" {
    assert_chain_exists DSHIELD
}

@test "DSHIELD chain has DROP rules for test IPs" {
    assert_rule_exists_ips DSHIELD "192.0.2.30"
    assert_rule_exists_ips DSHIELD "192.0.2.31"
}

@test "DSHIELD chain attached to INPUT" {
    assert_rule_exists_ips INPUT "DSHIELD"
}

# --- PHP ---

@test "PHP chain exists when DLIST_PHP=1 with pre-populated entries" {
    assert_chain_exists PHP
}

@test "PHP chain has DROP rules for test IPs" {
    assert_rule_exists_ips PHP "198.51.100.40"
    assert_rule_exists_ips PHP "198.51.100.41"
}

@test "PHP chain attached to INPUT" {
    assert_rule_exists_ips INPUT "PHP"
}

# --- SDROP ---

@test "SDROP chain exists when DLIST_SPAMHAUS=1 with pre-populated entries" {
    assert_chain_exists SDROP
}

@test "SDROP chain has DROP rules for test CIDRs" {
    assert_rule_exists_ips SDROP "192.0.2.0/24"
    assert_rule_exists_ips SDROP "198.51.100.0/24"
}

@test "SDROP chain attached to INPUT" {
    assert_rule_exists_ips INPUT "SDROP"
}

# --- Resilience ---

@test "download failure preserves existing entries via backup/restore" {
    # Verify backup files were created
    [ -f "$APF_DIR/ds_hosts.rules.bk" ]
    [ -f "$APF_DIR/php_hosts.rules.bk" ]
    [ -f "$APF_DIR/sdrop_hosts.rules.bk" ]

    # Verify rules files still have content (not wiped by failed download)
    local ds_count php_count drop_count
    ds_count=$(grep -c -v '^#' "$APF_DIR/ds_hosts.rules")
    php_count=$(grep -c -v '^#' "$APF_DIR/php_hosts.rules")
    drop_count=$(grep -c -v '^#' "$APF_DIR/sdrop_hosts.rules")
    [ "$ds_count" -ge 2 ]
    [ "$php_count" -ge 2 ]
    [ "$drop_count" -ge 2 ]
}

@test "invalid entries in rules file are skipped during chain loading" {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/apf-config.sh

    cat > "$APF_DIR/ds_hosts.rules" <<'EOF'
# DShield with invalid entries
192.0.2.30
not-an-ip
999.999.999.999
192.0.2.31
EOF
    chmod 600 "$APF_DIR/ds_hosts.rules"

    apf_set_config "DLIST_DSHIELD" "1"
    apf_set_url "DLIST_DSHIELD_URL" "https://127.0.0.1:1/nonexistent"
    apf_set_config "DLIST_PHP" "0"
    apf_set_config "DLIST_SPAMHAUS" "0"

    "$APF" -s

    # Valid entries loaded
    assert_rule_exists_ips DSHIELD "192.0.2.30"
    assert_rule_exists_ips DSHIELD "192.0.2.31"

    # Invalid entries should NOT appear in chain
    run iptables -S DSHIELD
    refute_output --partial "999.999.999.999"
}
