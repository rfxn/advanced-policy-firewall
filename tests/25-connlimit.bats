#!/usr/bin/env bats
#
# 25: Per-port connection limiting (connlimit)
#
# Validates IG_TCP_CLIMIT and IG_UDP_CLIMIT: empty produces no rules,
# single/multiple port:limit pairs, port ranges, UDP (no --syn),
# chain order (REJECT before ACCEPT), and VNET per-IP binding.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'
source /opt/tests/helpers/assert-iptables.bash

APF="/opt/apf/apf"
APF_DIR="/opt/apf"
VNET_IP="203.0.113.50"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_ports "22,80,443" "53" "" ""
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    ip addr del "$VNET_IP/24" dev veth-pub 2>/dev/null || true
    rm -f "$APF_DIR/vnet/$VNET_IP.rules"
    source /opt/tests/helpers/teardown-netns.sh
}

# =====================================================================
# Empty config — no connlimit rules
# =====================================================================

@test "empty IG_TCP_CLIMIT produces no connlimit rules" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_TCP_CLIMIT" ""
    apf_set_config "IG_UDP_CLIMIT" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_not_exists INPUT "connlimit"
}

# =====================================================================
# TCP connlimit
# =====================================================================

@test "IG_TCP_CLIMIT creates connlimit REJECT rule with correct port and limit" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_TCP_CLIMIT" "80:50"
    apf_set_config "IG_UDP_CLIMIT" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips INPUT "-p tcp.*--dport 80.*connlimit-above 50.*REJECT"
}

@test "IG_TCP_CLIMIT with multiple port:limit pairs" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_TCP_CLIMIT" "80:50,443:100"
    apf_set_config "IG_UDP_CLIMIT" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips INPUT "-p tcp.*--dport 80.*connlimit-above 50.*REJECT"
    assert_rule_exists_ips INPUT "-p tcp.*--dport 443.*connlimit-above 100.*REJECT"
}

@test "IG_TCP_CLIMIT with port range (underscore notation)" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_TCP_CLIMIT" "8080_8090:25"
    apf_set_config "IG_UDP_CLIMIT" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips INPUT "-p tcp.*--dport 8080:8090.*connlimit-above 25.*REJECT"
}

# =====================================================================
# UDP connlimit (no --syn)
# =====================================================================

@test "IG_UDP_CLIMIT creates connlimit rule without --syn" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_TCP_CLIMIT" ""
    apf_set_config "IG_UDP_CLIMIT" "53:200"
    "$APF" -f 2>/dev/null
    "$APF" -s

    assert_rule_exists_ips INPUT "-p udp.*--dport 53.*connlimit-above 200.*REJECT"
    # UDP rules must not have --syn (tcp-flags)
    local rules
    rules=$(iptables -S INPUT 2>/dev/null | grep "connlimit" | grep "udp")
    if echo "$rules" | grep -q "tcp-flags"; then
        echo "UDP connlimit rule should not have --syn/tcp-flags" >&2
        echo "$rules" >&2
        return 1
    fi
}

# =====================================================================
# Chain order — connlimit REJECT before ACCEPT
# =====================================================================

@test "connlimit REJECT appears BEFORE ACCEPT in chain order" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "IG_TCP_CLIMIT" "80:50"
    apf_set_config "IG_UDP_CLIMIT" ""
    apf_set_ports "22,80,443" "53" "" ""
    "$APF" -f 2>/dev/null
    "$APF" -s

    # Get line numbers: connlimit REJECT for port 80 must come before ACCEPT for port 80
    local rules
    rules=$(iptables -S INPUT 2>/dev/null)
    local reject_line accept_line
    reject_line=$(echo "$rules" | grep -n "connlimit-above 50.*REJECT" | head -1 | cut -d: -f1)
    accept_line=$(echo "$rules" | grep -n "dport 80.*ACCEPT" | head -1 | cut -d: -f1)

    [ -n "$reject_line" ] || { echo "No connlimit REJECT rule found"; echo "$rules"; return 1; }
    [ -n "$accept_line" ] || { echo "No ACCEPT rule for port 80 found"; echo "$rules"; return 1; }
    [ "$reject_line" -lt "$accept_line" ] || {
        echo "connlimit REJECT (line $reject_line) should appear before ACCEPT (line $accept_line)" >&2
        echo "$rules" >&2
        return 1
    }
}

# =====================================================================
# VNET per-IP binding
# =====================================================================

@test "VNET per-IP connlimit binds to specific IP" {
    source /opt/tests/helpers/apf-config.sh

    # Add secondary IP and enable VNET
    ip addr add "$VNET_IP/24" dev veth-pub 2>/dev/null || true
    apf_set_config "SET_VNET" "1"
    apf_set_config "IG_TCP_CLIMIT" ""
    apf_set_config "IG_UDP_CLIMIT" ""

    # Create complete VNET rule file with connlimit override
    # Must set VNET, override vars, and source cports.common
    mkdir -p "$APF_DIR/vnet"
    cat > "$APF_DIR/vnet/$VNET_IP.rules" <<VNETRULE
VNET="$VNET_IP"
IG_TCP_CPORTS="80,443"
IG_TCP_CLIMIT="80:30"
IG_UDP_CPORTS=""
IG_UDP_CLIMIT=""
. $APF_DIR/internals/cports.common
VNETRULE
    chmod 640 "$APF_DIR/vnet/$VNET_IP.rules"

    "$APF" -f 2>/dev/null
    "$APF" -s

    # iptables -S field order: -d IP comes before -p tcp
    assert_rule_exists_ips INPUT "-d $VNET_IP.*-p tcp.*--dport 80.*connlimit-above 30.*REJECT"

    # Cleanup
    apf_set_config "SET_VNET" "0"
    apf_set_config "IG_TCP_CLIMIT" ""
    rm -f "$APF_DIR/vnet/$VNET_IP.rules"
    ip addr del "$VNET_IP/24" dev veth-pub 2>/dev/null || true
    "$APF" -f 2>/dev/null
}
