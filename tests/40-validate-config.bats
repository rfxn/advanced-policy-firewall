#!/usr/bin/env bats
#
# 40: validate_config(), trim(), and download_url() unit tests
#
# Extracted from 21-refactor-regression.bats for performance: these tests
# only call $APF --validate or source functions.apf directly — they never
# start the firewall, so they don't need the expensive per-test iptables
# flush that 21-refactor-regression's teardown() performs.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
}

teardown() {
    source /opt/tests/helpers/reset-apf.sh
}

# =====================================================================
# validate_config() coverage (C-002)
# =====================================================================

@test "validate_config rejects invalid ICMP_LIM format" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config_safe "ICMP_LIM" "badvalue"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"ICMP_LIM"*"invalid"* ]]

    apf_set_config_safe "ICMP_LIM" "30/s"
}

@test "validate_config accepts ICMP_LIM=0 (unlimited)" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config_safe "ICMP_LIM" "0"

    run "$APF" --validate
    assert_success

    apf_set_config_safe "ICMP_LIM" "30/s"
}

@test "validate_config rejects invalid LOG_LEVEL" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "LOG_DROP" "1"
    apf_set_config "LOG_LEVEL" "badlevel"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"LOG_LEVEL"*"invalid"* ]]

    apf_set_config "LOG_LEVEL" "info"
    apf_set_config "LOG_DROP" "0"
}

@test "validate_config rejects invalid LOG_TARGET" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "LOG_DROP" "1"
    apf_set_config "LOG_TARGET" "BADTARGET"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"LOG_TARGET"*"invalid"* ]]

    apf_set_config "LOG_TARGET" "LOG"
    apf_set_config "LOG_DROP" "0"
}

@test "validate_config rejects non-numeric LOG_RATE" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "LOG_DROP" "1"
    apf_set_config "LOG_RATE" "abc"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"LOG_RATE"*"invalid"* ]]

    apf_set_config "LOG_RATE" "30"
    apf_set_config "LOG_DROP" "0"
}

@test "validate_config rejects non-numeric SYSCTL_CONNTRACK" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYSCTL_CONNTRACK" "notanum"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"SYSCTL_CONNTRACK"*"invalid"* ]]

    apf_set_config "SYSCTL_CONNTRACK" "65536"
}

@test "validate_config rejects non-numeric PERMBLOCK_COUNT" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "PERMBLOCK_COUNT" "abc"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"PERMBLOCK_COUNT"*"invalid"* ]]

    apf_set_config "PERMBLOCK_COUNT" "0"
}

@test "validate_config rejects non-numeric PERMBLOCK_INTERVAL" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "PERMBLOCK_COUNT" "3"
    apf_set_config "PERMBLOCK_INTERVAL" "xyz"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"PERMBLOCK_INTERVAL"*"invalid"* ]]

    apf_set_config "PERMBLOCK_COUNT" "0"
    apf_set_config "PERMBLOCK_INTERVAL" "86400"
}

@test "validate_config rejects invalid RAB_PSCAN_LEVEL" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "RAB" "1"
    apf_set_config "RAB_PSCAN_LEVEL" "5"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"RAB_PSCAN_LEVEL"*"invalid"* ]]

    apf_set_config "RAB_PSCAN_LEVEL" "1"
    apf_set_config "RAB" "0"
}

@test "validate_config rejects SYNFLOOD_BURST=0" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYNFLOOD" "1"
    apf_set_config_safe "SYNFLOOD_RATE" "100/s"
    apf_set_config "SYNFLOOD_BURST" "0"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"SYNFLOOD_BURST"*"greater than 0"* ]]

    apf_set_config "SYNFLOOD_BURST" "150"
    apf_set_config "SYNFLOOD" "0"
}

@test "validate_config rejects LOG_RATE=0" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "LOG_DROP" "1"
    apf_set_config "LOG_RATE" "0"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"LOG_RATE"*"greater than 0"* ]]

    apf_set_config "LOG_RATE" "30"
    apf_set_config "LOG_DROP" "0"
}

@test "validate_config rejects non-numeric RAB_HITCOUNT" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "RAB" "1"
    apf_set_config "RAB_HITCOUNT" "abc"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"RAB_HITCOUNT"*"invalid"* ]]

    apf_set_config "RAB_HITCOUNT" "1"
    apf_set_config "RAB" "0"
}

@test "validate_config rejects non-numeric RAB_TIMER" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "RAB" "1"
    apf_set_config "RAB_TIMER" "abc"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"RAB_TIMER"*"invalid"* ]]

    apf_set_config "RAB_TIMER" "300"
    apf_set_config "RAB" "0"
}

@test "validate_config rejects RAB_TIMER=0" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "RAB" "1"
    apf_set_config "RAB_TIMER" "0"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"RAB_TIMER"*"greater than 0"* ]]

    apf_set_config "RAB_TIMER" "300"
    apf_set_config "RAB" "0"
}

@test "validate_config rejects empty IFACE_UNTRUSTED" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IFACE_UNTRUSTED" ""

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"IFACE_UNTRUSTED"*"not set"* ]]

    apf_set_config "IFACE_UNTRUSTED" "veth-pub"
}

@test "validate_config rejects invalid connlimit entry" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_TCP_CLIMIT" "badentry"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"IG_TCP_CLIMIT"*"invalid"* ]]

    apf_set_config "IG_TCP_CLIMIT" ""
}

@test "validate_config accepts valid connlimit entry" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_TCP_CLIMIT" "80:50,443:100"

    run "$APF" --validate
    assert_success

    apf_set_config "IG_TCP_CLIMIT" ""
}

@test "validate_config rejects connlimit entry missing colon" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_UDP_CLIMIT" "80-50"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"IG_UDP_CLIMIT"*"invalid"* ]]

    apf_set_config "IG_UDP_CLIMIT" ""
}

@test "validate_config rejects non-numeric SET_EXPIRE" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_EXPIRE" "abc"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"SET_EXPIRE"*"invalid"* ]]

    apf_set_config "SET_EXPIRE" "0"
}

@test "validate_config accepts SET_EXPIRE=0 (disabled)" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_EXPIRE" "0"

    run "$APF" --validate
    assert_success

    apf_set_config "SET_EXPIRE" "0"
}

@test "validate_config rejects non-numeric FQDN_TIMEOUT" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "FQDN_TIMEOUT" "abc"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"FQDN_TIMEOUT"*"invalid"* ]]

    apf_set_config "FQDN_TIMEOUT" "5"
}

@test "validate_config rejects FQDN_TIMEOUT=0" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "FQDN_TIMEOUT" "0"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"FQDN_TIMEOUT"*"greater than 0"* ]]

    apf_set_config "FQDN_TIMEOUT" "5"
}

@test "validate_config rejects non-numeric SET_REFRESH" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_REFRESH" "abc"

    run "$APF" --validate
    assert_failure
    [[ "$output" == *"SET_REFRESH"*"non-negative integer"* ]]

    apf_set_config "SET_REFRESH" "10"
}

@test "validate_config accepts SET_REFRESH=0 (disabled)" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SET_REFRESH" "0"

    run "$APF" --validate
    assert_success

    apf_set_config "SET_REFRESH" "10"
}

# =====================================================================
# trim() inode preservation (C-003)
# =====================================================================

@test "trim() preserves file inode after truncation" {
    local tmpfile
    tmpfile=$(mktemp /tmp/trim-test-XXXXXX)

    # Write enough lines to trigger trimming (MAXLINES default is 2048)
    seq 1 3000 > "$tmpfile"

    local inode_before
    inode_before=$(stat -c %i "$tmpfile")

    # Source and call trim in subshell to avoid set -e issues with internals.conf
    run bash -c "
        source '$APF_DIR/conf.apf'
        source '$APF_DIR/internals/functions.apf'
        trim '$tmpfile'
    "
    assert_success

    local inode_after
    inode_after=$(stat -c %i "$tmpfile")

    [ "$inode_before" = "$inode_after" ]

    rm -f "$tmpfile"
}

# =====================================================================
# download_url() test coverage (F-053)
# =====================================================================

# Helper: start a one-shot HTTP server that serves content then exits.
# Uses portable nc syntax (positional port, no -p/-q) + timeout for auto-cleanup.
# Works across: netcat-openbsd (Debian/Ubuntu), nmap-ncat (Rocky/RHEL), nc-1.84 (CentOS 6).
_dl_serve() {
    local port="$1" content="$2"
    local response="HTTP/1.0 200 OK\r\nContent-Length: ${#content}\r\n\r\n${content}"
    printf '%b' "$response" | timeout 5 nc -l "$port" >/dev/null 2>&1 &
}

@test "download_url succeeds with wget" {
    local dst port=18901
    dst=$(mktemp /tmp/dl-dst-XXXXXX)

    _dl_serve "$port" "test-content-wget"
    sleep 0.5

    # Source only conf.apf + functions.apf; set CURL/WGET directly to avoid
    # internals.conf side effects (network probing, file sourcing) that fail
    # on deep legacy OSes
    run bash -c "
        source '$APF_DIR/conf.apf'
        source '$APF_DIR/internals/functions.apf'
        CURL=\$(command -v curl 2>/dev/null)
        WGET=\$(command -v wget 2>/dev/null)
        download_url 'http://127.0.0.1:$port/test' '$dst'
    "
    assert_success

    run cat "$dst"
    assert_output "test-content-wget"

    rm -f "$dst"
}

@test "download_url fails when both curl and wget missing" {
    run bash -c "
        source '$APF_DIR/conf.apf'
        source '$APF_DIR/internals/functions.apf'
        CURL=''
        WGET=''
        download_url 'http://127.0.0.1:1/nonexistent' '/tmp/dl-none'
    "
    assert_failure
}

@test "download_url fails on unreachable URL" {
    local dst
    dst=$(mktemp /tmp/dl-dst-XXXXXX)

    run bash -c "
        source '$APF_DIR/conf.apf'
        source '$APF_DIR/internals/functions.apf'
        CURL=\$(command -v curl 2>/dev/null)
        WGET=\$(command -v wget 2>/dev/null)
        download_url 'http://127.0.0.1:1/nonexistent' '$dst'
    "
    assert_failure

    rm -f "$dst"
}

@test "download_url skips curl when CURL empty and falls back to wget" {
    local dst port=18902
    dst=$(mktemp /tmp/dl-dst-XXXXXX)

    _dl_serve "$port" "fallback-content"
    sleep 0.5

    run bash -c "
        source '$APF_DIR/conf.apf'
        source '$APF_DIR/internals/functions.apf'
        CURL=''
        WGET=\$(command -v wget 2>/dev/null)
        download_url 'http://127.0.0.1:$port/test' '$dst'
    "
    assert_success

    run cat "$dst"
    assert_output "fallback-content"

    rm -f "$dst"
}
