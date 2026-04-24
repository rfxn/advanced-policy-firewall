#!/usr/bin/env bats
# 14-subcommand-dispatch.bats — APF Subcommand Dispatch UAT
# Validates the 2.0.2 gh-style CLI subcommand routing: trust, config, status, help.
# Each subcommand noun dispatches to the correct handler and produces expected output.

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
    uat_apf_set_port_config "EG_TCP_CPORTS" "22,80,443"
    apf -s
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# =========================================================================
# UAT-SC01: trust subcommand — add/remove/list/lookup
# Scenario: Sysadmin uses gh-style trust subcommand for full lifecycle
# =========================================================================

# bats test_tags=uat,uat:subcommand-trust
@test "UAT: 'apf trust add' allows IP same as 'apf -a'" {
    uat_capture "subcmd-trust" apf trust add 192.0.2.110 "subcmd add"
    assert_success
    assert_rule_exists_ips TALLOW "192.0.2.110"
    run grep "192.0.2.110" /opt/apf/allow_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:subcommand-trust
@test "UAT: 'apf trust deny' blocks IP same as 'apf -d'" {
    uat_capture "subcmd-trust" apf trust deny 198.51.100.110 "subcmd deny"
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.110"
    run grep "198.51.100.110" /opt/apf/deny_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:subcommand-trust
@test "UAT: 'apf trust remove' unblocks IP same as 'apf -u'" {
    uat_capture "subcmd-trust" apf trust remove 198.51.100.110
    assert_success
    run iptables -S TDENY 2>/dev/null
    refute_output --partial "198.51.100.110"
    run grep "198.51.100.110" /opt/apf/deny_hosts.rules
    assert_failure
}

# bats test_tags=uat,uat:subcommand-trust
@test "UAT: 'apf trust list --allow' shows allowed entries" {
    uat_capture "subcmd-trust" apf trust list --allow
    assert_success
    assert_output --partial "192.0.2.110"
}

# bats test_tags=uat,uat:subcommand-trust
@test "UAT: 'apf trust list --deny' shows denied entries" {
    apf -d 198.51.100.111 "for list" 2>/dev/null
    uat_capture "subcmd-trust" apf trust list --deny
    assert_success
    assert_output --partial "198.51.100.111"
    apf -u 198.51.100.111 2>/dev/null || true  # cleanup
}

# bats test_tags=uat,uat:subcommand-trust
@test "UAT: 'apf trust lookup' resolves trust status" {
    uat_capture "subcmd-trust" apf trust lookup 192.0.2.110
    assert_success
    assert_output --partial "ALLOW"
}

# bats test_tags=uat,uat:subcommand-trust
@test "UAT: 'apf trust lookup' not-found for unknown IP" {
    uat_capture "subcmd-trust" apf trust lookup 10.255.255.1
    assert_failure
    assert_output --partial "not found"
}

# =========================================================================
# UAT-SC02: trust temp subcommand
# Scenario: Sysadmin uses temp trust via subcommand syntax
# =========================================================================

# bats test_tags=uat,uat:subcommand-trust-temp
@test "UAT: 'apf trust temp add' creates temporary allow" {
    uat_capture "subcmd-temp" apf trust temp add 192.0.2.120 1h "subcmd temp"
    assert_success
    assert_rule_exists_ips TALLOW "192.0.2.120"
    run grep "192.0.2.120" /opt/apf/allow_hosts.rules
    assert_success
    # Verify ttl marker
    run grep "ttl=" /opt/apf/allow_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:subcommand-trust-temp
@test "UAT: 'apf trust temp deny' creates temporary deny" {
    uat_capture "subcmd-temp" apf trust temp deny 198.51.100.120 30m "subcmd temp deny"
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.120"
}

# bats test_tags=uat,uat:subcommand-trust-temp
@test "UAT: 'apf trust temp list' shows active temp entries" {
    uat_capture "subcmd-temp" apf trust temp list
    assert_success
    assert_output --partial "192.0.2.120"
    assert_output --partial "198.51.100.120"
}

# bats test_tags=uat,uat:subcommand-trust-temp
@test "UAT: 'apf trust temp flush' removes all temp entries" {
    uat_capture "subcmd-temp" apf trust temp flush
    assert_success
    # Verify entries removed
    run iptables -S TALLOW 2>/dev/null
    refute_output --partial "192.0.2.120"
    run iptables -S TDENY 2>/dev/null
    refute_output --partial "198.51.100.120"
}

# =========================================================================
# UAT-SC03: config subcommand
# Scenario: Sysadmin uses config validate and config dump
# =========================================================================

# bats test_tags=uat,uat:subcommand-config
@test "UAT: 'apf config validate' passes with valid config" {
    uat_capture "subcmd-config" apf config validate
    assert_success
}

# bats test_tags=uat,uat:subcommand-config
@test "UAT: 'apf config dump' shows configuration variables" {
    uat_capture "subcmd-config" apf config dump
    assert_success
    assert_output --partial "IFACE_UNTRUSTED"
    assert_output --partial "DEVEL_MODE"
}

# =========================================================================
# UAT-SC04: status subcommand
# Scenario: Sysadmin uses status for firewall info and rules dump
# =========================================================================

# bats test_tags=uat,uat:subcommand-status
@test "UAT: 'apf status' shows firewall info with active status" {
    uat_capture "subcmd-status" apf status
    assert_success
    assert_output --partial "Active:"
    assert_output --partial "yes"
}

# bats test_tags=uat,uat:subcommand-status
@test "UAT: 'apf status rules' dumps iptables rules" {
    uat_capture "subcmd-status" apf status rules
    assert_success
    assert_output --partial "TALLOW"
    assert_output --partial "TDENY"
}

# =========================================================================
# UAT-SC05: help subcommand
# Scenario: Sysadmin discovers subcommand-specific help
# =========================================================================

# bats test_tags=uat,uat:subcommand-help
@test "UAT: 'apf help trust' shows trust-specific help" {
    uat_capture "subcmd-help" apf help trust
    assert_success
    assert_output --partial "trust"
}

# bats test_tags=uat,uat:subcommand-help
@test "UAT: 'apf help config' shows config-specific help" {
    uat_capture "subcmd-help" apf help config
    assert_success
    assert_output --partial "config"
}

# bats test_tags=uat,uat:subcommand-help
@test "UAT: 'apf help status' shows status-specific help" {
    uat_capture "subcmd-help" apf help status
    assert_success
    assert_output --partial "status"
}

# =========================================================================
# UAT-SC06: cleanup
# =========================================================================

# bats test_tags=uat,uat:subcommand-trust
@test "UAT: subcommand trust cleanup — remove test entry" {
    apf -u 192.0.2.110 2>/dev/null || true  # cleanup
    run grep "192.0.2.110" /opt/apf/allow_hosts.rules
    assert_failure
}
