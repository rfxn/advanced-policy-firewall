#!/usr/bin/env bats
# 08-advanced-trust.bats -- APF Advanced Trust Syntax UAT
# Verifies: proto:flow:port:ip syntax, CIDR trust rules, multiple entries,
# trust removal cleanup; checks BOTH file content AND live iptables rules.

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
    apf -s
}

teardown_file() {
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

# bats test_tags=uat,uat:advanced-trust
@test "UAT: advanced trust tcp:in:d=port:s=ip adds to allow file and iptables" {
    uat_capture "adv-trust" apf -a "tcp:in:d=8443:s=192.0.2.70" "UAT adv allow"
    assert_success
    # Verify in trust file
    run grep -c "tcp:in:d=8443:s=192.0.2.70" /opt/apf/allow_hosts.rules
    assert_success
    # Verify live iptables rule — use -S format for cross-backend consistency
    assert_rule_exists_ips TALLOW "192\.0\.2\.70.*dports 8443"
}

# bats test_tags=uat,uat:advanced-trust
@test "UAT: advanced trust with CIDR source in allow" {
    uat_capture "adv-trust" apf -a "tcp:in:d=9090:s=198.51.100.0/24" "UAT CIDR adv"
    assert_success
    run grep -c "tcp:in:d=9090:s=198.51.100.0/24" /opt/apf/allow_hosts.rules
    assert_success
    assert_rule_exists_ips TALLOW "198\.51\.100\.0/24.*dports 9090"
}

# bats test_tags=uat,uat:advanced-trust
@test "UAT: multiple advanced trust entries on same protocol coexist" {
    # Second TCP entry on a different port
    uat_capture "adv-trust" apf -a "tcp:in:d=7777:s=203.0.113.10" "UAT multi entry"
    assert_success
    # Both original and new entry should be live
    assert_rule_exists_ips TALLOW "192\.0\.2\.70.*dports 8443"
    assert_rule_exists_ips TALLOW "203\.0\.113\.10.*dports 7777"
}

# bats test_tags=uat,uat:advanced-trust
@test "UAT: advanced trust deny adds to deny file and TDENY chain" {
    uat_capture "adv-trust" apf -d "tcp:in:d=2222:s=192.0.2.80" "UAT adv deny"
    assert_success
    run grep -c "tcp:in:d=2222:s=192.0.2.80" /opt/apf/deny_hosts.rules
    assert_success
    assert_rule_exists_ips TDENY "192\.0\.2\.80.*dports 2222"
}

# bats test_tags=uat,uat:advanced-trust
@test "UAT: remove advanced trust entry cleans file and iptables" {
    uat_capture "adv-trust" apf -u "tcp:in:d=8443:s=192.0.2.70"
    assert_success
    # Verify removed from file
    run grep -c "tcp:in:d=8443:s=192.0.2.70" /opt/apf/allow_hosts.rules
    assert_failure
    # Verify removed from iptables
    run iptables -S TALLOW 2>/dev/null
    refute_output --partial "192.0.2.70"
}

# bats test_tags=uat,uat:advanced-trust
@test "UAT: duplicate advanced trust entry reports already exists" {
    uat_capture "adv-trust" apf -a "tcp:in:d=9090:s=198.51.100.0/24" "dup"
    assert_success
    assert_output --partial "already exists"
}
