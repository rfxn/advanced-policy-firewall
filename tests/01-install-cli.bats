#!/usr/bin/env bats
#
# 01: Installation & CLI commands

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    # Setup network namespace and install APF
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    # Flush any prior state
    "$APF" -f 2>/dev/null || true
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "apf --version outputs version" {
    run "$APF" --version
    assert_success
    assert_output "2.0.2"
}

@test "apf -v outputs version (alias)" {
    run "$APF" -v
    assert_success
}

@test "apf with no args shows help and exits 1" {
    run "$APF"
    assert_failure
    assert_output --partial "usage"
}

@test "apf -s starts firewall" {
    run "$APF" -s
    assert_success
    # Verify rules were loaded
    run iptables -L INPUT -n
    assert_success
    assert_output --partial "TALLOW"
}

@test "apf -t shows status log" {
    run "$APF" -t
    assert_success
}

@test "apf -o dumps config variables" {
    run "$APF" -o
    assert_success
    assert_output --partial "INSTALL_PATH="
    assert_output --partial "IFACE_UNTRUSTED="
}

@test "apf -f flushes firewall" {
    "$APF" -s 2>/dev/null
    run "$APF" -f
    assert_success
    # Verify policies reset to ACCEPT (not filtering)
    local policy
    policy=$(iptables -L INPUT -n | head -1)
    echo "$policy" | grep -q "ACCEPT"
}

@test "apf -r restarts firewall" {
    run "$APF" -r
    assert_success
    # Verify rules are loaded after restart
    run iptables -L INPUT -n
    assert_success
    assert_output --partial "TALLOW"
    "$APF" -f 2>/dev/null
}
