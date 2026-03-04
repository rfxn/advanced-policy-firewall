#!/usr/bin/env bats
#
# 18: GRE Tunnels -- encapsulated point-to-point links with dedicated chains
#
# GRE requires kernel module support and ip tunnel capability.
# Tests skip gracefully when unavailable.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash
source /opt/tests/helpers/capability-detect.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"

setup_file() {
    if ! gre_available; then
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

    # Enable GRE
    apf_set_config "USE_GRE" "1"

    # Create test IP file for routing
    cat > "$APF_DIR/gre.ips.test" <<'EOF'
198.51.100.10
198.51.100.11
198.51.100.12
EOF

    # Create gre.rules with a source tunnel
    # local=203.0.113.2 (veth-pub address), remote=192.0.2.1 (TEST-NET, unreachable but tunnel created)
    cat > "$APF_DIR/gre.rules" <<'GRECONF'
#!/bin/bash
role="source"
create_gretun 1 203.0.113.2 192.0.2.1 /opt/apf/gre.ips.test
GRECONF

    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    # Clean up GRE tunnel interfaces
    ip tunnel del gre1 2>/dev/null || true
    rm -f "$APF_DIR/gre.ips.test"
    source /opt/tests/helpers/teardown-netns.sh
}

setup() {
    if ! gre_available; then
        skip "GRE tunnel support not available"
    fi
}

# --- Tunnel Interface Tests ---

@test "USE_GRE=1 source tunnel gre1 created" {
    run ip link show gre1
    assert_success
}

@test "GRE_IN chain exists" {
    assert_chain_exists GRE_IN
}

@test "GRE_OUT chain exists" {
    assert_chain_exists GRE_OUT
}

@test "Protocol 47 inbound rule for remote endpoint" {
    # Modern iptables normalizes -p 47 to -p gre; old legacy keeps -p 47
    assert_rule_exists_ips GRE_IN "-s 192.0.2.1.*-p (gre|47) -j ACCEPT"
}

@test "Protocol 47 outbound rule for remote endpoint" {
    assert_rule_exists_ips GRE_OUT "-d 192.0.2.1.*-p (gre|47) -j ACCEPT"
}

@test "Interface accept rule in GRE_IN" {
    assert_rule_exists_ips GRE_IN "-i gre1 -j ACCEPT"
}

@test "Interface accept rule in GRE_OUT" {
    assert_rule_exists_ips GRE_OUT "-o gre1 -j ACCEPT"
}

@test "Tunnel has correct source address 192.168.1.1" {
    run ip addr show gre1
    assert_success
    assert_output --partial "192.168.1.1"
}

@test "Tunnel MTU is set" {
    run ip link show gre1
    assert_success
    # MTU should be present (auto-calculated or default)
    assert_output --regexp "mtu [0-9]+"
}

@test "IP routes from ipfile exist" {
    run ip route show
    assert_output --partial "198.51.100.10"
    assert_output --partial "198.51.100.11"
    assert_output --partial "198.51.100.12"
}

# --- Status Tests ---

@test "--gre-status shows tunnel section headers" {
    run "$APF" --gre-status
    assert_success
    assert_output --partial "GRE Tunnel Interfaces"
    assert_output --partial "GRE Routes"
    assert_output --partial "GRE Firewall Rules"
}

# --- Disable / Flush Tests ---

@test "USE_GRE=0 creates no tunnels or chains" {
    # Flush and restart with GRE disabled
    "$APF" -f
    ip tunnel del gre1 2>/dev/null || true

    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_GRE" "0"
    "$APF" -s

    # No GRE chains
    run iptables -S GRE_IN 2>&1
    assert_failure

    # Restore for remaining tests
    "$APF" -f
    apf_set_config "USE_GRE" "1"
    "$APF" -s
}

@test "Flush preserves tunnel interface when GRE_PERSIST=1" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "GRE_PERSIST" "1"
    "$APF" -f

    # Tunnel interface should still exist
    run ip link show gre1
    assert_success

    # But GRE_IN chain should be gone
    run iptables -S GRE_IN 2>&1
    assert_failure

    # Restart for remaining tests
    "$APF" -s
}

@test "--gre-down tears down tunnel interface" {
    "$APF" --gre-down

    run ip link show gre1 2>&1
    assert_failure

    # Restart to restore
    "$APF" -s
}

@test "Invalid linkid rejected with error" {
    # Write a gre.rules with invalid linkid
    cat > "$APF_DIR/gre.rules" <<'GRECONF'
#!/bin/bash
role="source"
create_gretun 0 203.0.113.2 192.0.2.1
GRECONF

    "$APF" -f
    ip tunnel del gre1 2>/dev/null || true
    "$APF" -s

    # gre0 should NOT be created by our code (gre0 is kernel default, may exist)
    # The key check is that the log shows an error
    run grep "linkid must be 1-99" /var/log/apf_log
    assert_success

    # Restore valid config
    cat > "$APF_DIR/gre.rules" <<'GRECONF'
#!/bin/bash
role="source"
create_gretun 1 203.0.113.2 192.0.2.1 /opt/apf/gre.ips.test
GRECONF
    "$APF" -f
    "$APF" -s
}
