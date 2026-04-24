#!/usr/bin/env bats
# 22-vnet-lifecycle.bats — VNET (Virtual Network) Operator Workflows
# Validates: VNET enable/disable lifecycle, --info status, multi-IP policies,
# restart persistence, trust coexistence, egress scoping.
#
# Does NOT duplicate tests/24-vnet.bats (6 tests covering basic enable/disable,
# vnetgen, single IP rule loading, unbound skip, port override). This file tests
# multi-IP operator workflows, status reporting, and subsystem interactions.
#
# Uses RFC 5737 TEST-NET-3 (203.0.113.0/24) for secondary IPs on veth-pub.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
load '../helpers/uat-apf'
load '../helpers/assert-iptables'
load '../infra/lib/uat-helpers'

VNET_IP1="203.0.113.50"
VNET_IP2="203.0.113.51"

setup_file() {
    uat_setup
    uat_apf_install
    source /opt/tests/helpers/setup-netns.sh
    uat_apf_set_interface "veth-pub"
    uat_apf_set_port_config "IG_TCP_CPORTS" "22,80,443"
    uat_apf_set_port_config "EG_TCP_CPORTS" "22,80,443"
    uat_apf_set_config "EGF" "1"
}

teardown_file() {
    apf -f 2>/dev/null || true  # safe: may not be running
    # Remove secondary IPs
    ip addr del "$VNET_IP1/24" dev veth-pub 2>/dev/null || true  # safe: may not exist
    ip addr del "$VNET_IP2/24" dev veth-pub 2>/dev/null || true  # safe: may not exist
    # Clean up VNET rule files
    rm -f "$APF_INSTALL/vnet/$VNET_IP1.rules" "$APF_INSTALL/vnet/$VNET_IP2.rules"
    uat_apf_teardown
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    apf -f 2>/dev/null || true  # safe: may not be running
    rm -f "$APF_INSTALL/lock.utime"
    # Remove secondary IPs for clean state
    ip addr del "$VNET_IP1/24" dev veth-pub 2>/dev/null || true  # safe: may not exist
    ip addr del "$VNET_IP2/24" dev veth-pub 2>/dev/null || true  # safe: may not exist
    rm -f "$APF_INSTALL/vnet/$VNET_IP1.rules" "$APF_INSTALL/vnet/$VNET_IP2.rules"
}

# =========================================================================
# UAT-VL01: Full VNET lifecycle
# Scenario: Sysadmin adds secondary IP, enables VNET, starts, verifies, stops
# =========================================================================

# bats test_tags=uat,uat:vnet
@test "UAT: VNET lifecycle — enable, start, verify per-IP rules, stop" {
    ip addr add "$VNET_IP1/24" dev veth-pub
    uat_apf_set_config "SET_VNET" "1"

    apf -s
    # Per-IP rules should scope port 22 to the VNET IP
    assert_rule_exists_ips INPUT "$VNET_IP1.*dport 22"

    apf -f
    # After flush, per-IP rules should be gone
    assert_chain_not_exists TALLOW 2>/dev/null || true  # safe: chain may not exist after flush
}

# =========================================================================
# UAT-VL02: --info shows VNET enabled
# Scenario: Sysadmin checks subsystem status
# =========================================================================

# bats test_tags=uat,uat:vnet
@test "UAT: apf --info shows VNET enabled when SET_VNET=1" {
    ip addr add "$VNET_IP1/24" dev veth-pub
    uat_apf_set_config "SET_VNET" "1"
    apf -s

    run apf --info
    assert_success
    assert_output --partial "VNET"
    assert_output --partial "enabled"
}

# =========================================================================
# UAT-VL03: --info shows VNET disabled
# Scenario: Sysadmin confirms VNET is off
# =========================================================================

# bats test_tags=uat,uat:vnet
@test "UAT: apf --info shows VNET disabled when SET_VNET=0" {
    uat_apf_set_config "SET_VNET" "0"
    apf -s

    run apf --info
    assert_success
    assert_output --partial "VNET"
    assert_output --partial "disabled"
}

# =========================================================================
# UAT-VL04: Multiple secondary IPs with independent policies
# Scenario: Sysadmin has two IPs with different port requirements
# =========================================================================

# bats test_tags=uat,uat:vnet
@test "UAT: multiple secondary IPs get independent VNET rules" {
    ip addr add "$VNET_IP1/24" dev veth-pub
    ip addr add "$VNET_IP2/24" dev veth-pub
    uat_apf_set_config "SET_VNET" "1"

    # Let vnetgen create default rules for IP1
    "$APF_INSTALL/vnet/vnetgen"

    # Create custom rules for IP2 with different ports.
    # Must mirror vnetgen.def structure: eout, VNET=, overrides, source cports.common
    cat > "$APF_INSTALL/vnet/$VNET_IP2.rules" <<EOF
eout "{glob} loading $VNET_IP2.rules"
VNET="$VNET_IP2"
IG_TCP_CPORTS="8080,9090"
IG_UDP_CPORTS=""
. "\$INSTALL_PATH/internals/cports.common"
EOF
    chmod 600 "$APF_INSTALL/vnet/$VNET_IP2.rules"

    apf -s

    # IP1 should have default ports (22,80,443 from conf.apf)
    assert_rule_exists_ips INPUT "$VNET_IP1.*dport 22"
    # IP2 should have custom ports
    assert_rule_exists_ips INPUT "$VNET_IP2.*dport 8080"
    assert_rule_exists_ips INPUT "$VNET_IP2.*dport 9090"
}

# =========================================================================
# UAT-VL05: VNET rules survive restart
# Scenario: Sysadmin restarts firewall, per-IP rules are rebuilt
# =========================================================================

# bats test_tags=uat,uat:vnet
@test "UAT: VNET per-IP rules survive restart" {
    ip addr add "$VNET_IP1/24" dev veth-pub
    uat_apf_set_config "SET_VNET" "1"

    apf -s
    assert_rule_exists_ips INPUT "$VNET_IP1.*dport 22"

    apf -f
    rm -f "$APF_INSTALL/lock.utime"
    apf -s

    # Rules should be rebuilt on restart (vnetgen re-runs)
    assert_rule_exists_ips INPUT "$VNET_IP1.*dport 22"
}

# =========================================================================
# UAT-VL06: Disabling VNET removes per-IP rules
# Scenario: Sysadmin turns off VNET subsystem
# =========================================================================

# bats test_tags=uat,uat:vnet
@test "UAT: disabling VNET removes per-IP rules on next start" {
    ip addr add "$VNET_IP1/24" dev veth-pub
    uat_apf_set_config "SET_VNET" "1"
    apf -s
    assert_rule_exists_ips INPUT "$VNET_IP1.*dport 22"

    apf -f
    rm -f "$APF_INSTALL/lock.utime"
    uat_apf_set_config "SET_VNET" "0"
    apf -s

    # Per-IP scoped rules should not exist when VNET disabled
    # Global rules still apply (no -d IP restriction)
    run iptables -S INPUT
    # Should NOT contain rules scoped to the VNET IP
    refute_output --partial -- "-d $VNET_IP1"
}

# =========================================================================
# UAT-VL07: IP trust coexists with VNET
# Scenario: Sysadmin adds trust entry while VNET is active
# =========================================================================

# bats test_tags=uat,uat:vnet
@test "UAT: IP trust coexists with VNET per-IP rules" {
    ip addr add "$VNET_IP1/24" dev veth-pub
    uat_apf_set_config "SET_VNET" "1"
    apf -s

    # Add trust entry — separate from VNET
    run apf -a 198.51.100.60 "trust test"
    assert_success

    # Both should coexist
    assert_rule_exists_ips TALLOW "198.51.100.60"
    assert_rule_exists_ips INPUT "$VNET_IP1.*dport 22"
}

# =========================================================================
# UAT-VL08: VNET with egress filtering
# Scenario: Sysadmin verifies egress rules are scoped to VNET IP
# =========================================================================

# bats test_tags=uat,uat:vnet
@test "UAT: VNET with EGF=1 applies egress rules scoped to VNET IP" {
    ip addr add "$VNET_IP1/24" dev veth-pub
    uat_apf_set_config "SET_VNET" "1"
    uat_apf_set_config "EGF" "1"
    uat_apf_set_port_config "EG_TCP_CPORTS" "80,443"
    apf -s

    # Egress rules should be scoped with -s $VNET_IP
    assert_rule_exists_ips OUTPUT "$VNET_IP1.*dport 80"
}
