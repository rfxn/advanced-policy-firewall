#!/usr/bin/env bats
# 19-legacy-compat.bats — APF Legacy Alias & CSF Compatibility UAT
# Validates: --allow/--deny/--remove/--unban legacy aliases, --la/--ld/--lookup
# list aliases, --validate/--rules/--info/--dump-config diagnostic aliases,
# and CSF compatibility aliases (-ar, -dr).
#
# FIXED (2.0.2): --allow and --deny are now in the flock wrapper list
# (files/apf:58), so they use the same kernel flock path as -a/-d.

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

setup() {
    rm -f /opt/apf/lock.utime
}

# =========================================================================
# UAT-LC01: --allow / --deny / --remove legacy trust aliases
# Scenario: Sysadmin uses pre-2.0.2 long-form flags for trust ops
# =========================================================================

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --allow adds IP to allow list (legacy alias for -a)" {
    uat_capture "legacy" apf --allow 192.0.2.160 "legacy allow"
    assert_success
    assert_rule_exists_ips TALLOW "192.0.2.160"
    run grep "192.0.2.160" /opt/apf/allow_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --deny adds IP to deny list (legacy alias for -d)" {
    uat_capture "legacy" apf --deny 198.51.100.160 "legacy deny"
    assert_success
    assert_rule_exists_ips TDENY "198.51.100.160"
    run grep "198.51.100.160" /opt/apf/deny_hosts.rules
    assert_success
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --remove removes IP from all trust (legacy alias for -u)" {
    uat_capture "legacy" apf --remove 198.51.100.160
    assert_success
    run iptables -S TDENY 2>/dev/null
    refute_output --partial "198.51.100.160"
    run grep "198.51.100.160" /opt/apf/deny_hosts.rules
    assert_failure
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --unban removes IP same as --remove" {
    apf -d 198.51.100.161 "for unban test" 2>/dev/null
    uat_capture "legacy" apf --unban 198.51.100.161
    assert_success
    run iptables -S TDENY 2>/dev/null
    refute_output --partial "198.51.100.161"
}

# =========================================================================
# UAT-LC02: --la / --ld list aliases
# Scenario: Sysadmin checks trust lists with legacy flags
# =========================================================================

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --la (--list-allow) shows allowed entries" {
    uat_capture "legacy" apf --la
    assert_success
    assert_output --partial "192.0.2.160"
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --ld (--list-deny) shows denied entries" {
    apf -d 198.51.100.162 "ld test" 2>/dev/null
    uat_capture "legacy" apf --ld
    assert_success
    assert_output --partial "198.51.100.162"
    apf -u 198.51.100.162 2>/dev/null || true  # cleanup
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --list-allow is accepted as full form" {
    uat_capture "legacy" apf --list-allow
    assert_success
    assert_output --partial "192.0.2.160"
}

# =========================================================================
# UAT-LC03: --lookup legacy alias
# =========================================================================

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --lookup finds trust status (legacy alias)" {
    uat_capture "legacy" apf --lookup 192.0.2.160
    assert_success
    assert_output --partial "ALLOW"
}

# =========================================================================
# UAT-LC04: Diagnostic legacy aliases
# =========================================================================

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --validate checks config (legacy alias for config validate)" {
    uat_capture "legacy" apf --validate
    assert_success
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --check is accepted same as --validate" {
    uat_capture "legacy" apf --check
    assert_success
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --rules dumps iptables rules (legacy alias for status rules)" {
    uat_capture "legacy" apf --rules
    assert_success
    assert_output --partial "TALLOW"
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --info shows firewall status (legacy alias for status)" {
    uat_capture "legacy" apf --info
    assert_success
    assert_output --partial "Active:"
    assert_output --partial "yes"
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --dump-config shows config variables (legacy alias for config dump)" {
    uat_capture "legacy" apf --dump-config
    assert_success
    assert_output --partial "IFACE_UNTRUSTED"
}

# bats test_tags=uat,uat:legacy-compat
@test "UAT: --ovars is accepted same as --dump-config" {
    uat_capture "legacy" apf --ovars
    assert_success
    assert_output --partial "IFACE_UNTRUSTED"
}

# =========================================================================
# UAT-LC05: CSF compatibility aliases
# Scenario: Sysadmin migrating from CSF uses familiar flags
# =========================================================================

# bats test_tags=uat,uat:csf-compat
@test "UAT: -ar removes from allow (CSF alias)" {
    # Add entry via standard path (not dependent on --allow test)
    apf -a 192.0.2.170 "ar test" 2>/dev/null

    # Precondition: entry exists in allow
    run grep "192.0.2.170" /opt/apf/allow_hosts.rules
    assert_success

    uat_capture "csf-compat" apf -ar 192.0.2.170
    assert_success

    # Entry must be removed
    run grep "192.0.2.170" /opt/apf/allow_hosts.rules
    assert_failure
}

# bats test_tags=uat,uat:csf-compat
@test "UAT: -dr removes from deny (CSF alias)" {
    apf -d 198.51.100.163 "dr test" 2>/dev/null

    uat_capture "csf-compat" apf -dr 198.51.100.163
    assert_success

    run grep "198.51.100.163" /opt/apf/deny_hosts.rules
    assert_failure
}

# =========================================================================
# UAT-LC06: --csf-help shows migration reference
# =========================================================================

# bats test_tags=uat,uat:csf-compat
@test "UAT: --csf-help shows CSF-to-APF command mapping" {
    uat_capture "csf-compat" apf --csf-help
    assert_success
    # Should contain CSF → APF equivalence info
    assert_output --partial "CSF"
}
