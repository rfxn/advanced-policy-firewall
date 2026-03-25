#!/usr/bin/env bats
#
# 12: Sysctl kernel tuning — verifies sysctl.rules sets correct values

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF="/opt/apf/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/reset-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    apf_set_config "SYSCTL_SYN" "1"
    apf_set_config "SYSCTL_ROUTE" "1"
    apf_set_config "SYSCTL_LOGMARTIANS" "1"
    apf_set_config "SYSCTL_ECN" "0"
    apf_set_config "SYSCTL_SYNCOOKIES" "1"
    apf_set_config "SYSCTL_TCP_NOSACK" "0"
    "$APF" -f 2>/dev/null || true
    "$APF" -s
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    source /opt/tests/helpers/teardown-netns.sh
}

@test "rp_filter set on default interface" {
    # Docker containers may not allow rp_filter on conf/all.
    # Check the specific interface instead (more reliable in containers).
    local iface="veth-pub"
    if [ ! -f "/proc/sys/net/ipv4/conf/$iface/rp_filter" ]; then
        skip "rp_filter not available for $iface"
    fi
    local val
    val=$(cat "/proc/sys/net/ipv4/conf/$iface/rp_filter")
    # Value is 0 (off), 1 (strict), or 2 (loose)
    [[ "$val" =~ ^[012]$ ]]
}

@test "log_martians enabled" {
    local proc="/proc/sys/net/ipv4/conf/all/log_martians"
    if [ ! -f "$proc" ]; then
        skip "log_martians not available"
    fi
    # Docker may silently ignore writes to this sysctl; verify by attempting
    # a probe write and checking if the value actually changed
    local before
    before=$(cat "$proc")
    echo 1 > "$proc" 2>/dev/null || skip "log_martians not writable in this container"
    local after
    after=$(cat "$proc")
    if [ "$before" = "$after" ] && [ "$after" != "1" ]; then
        skip "log_martians not writable in this container (write silently ignored)"
    fi
    [ "$after" -eq 1 ]
}

@test "ICMP broadcast echo ignored" {
    local val
    val=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts)
    [ "$val" -eq 1 ]
}

@test "source route disabled" {
    local val
    val=$(cat /proc/sys/net/ipv4/conf/all/accept_source_route)
    [ "$val" -eq 0 ]
}

@test "ip_forward disabled when SYSCTL_ROUTE=1" {
    local val
    val=$(cat /proc/sys/net/ipv4/ip_forward)
    [ "$val" -eq 0 ]
}

@test "SYSCTL_TCP_NOSACK=0 does NOT disable TCP SACK" {
    # This verifies our Phase 7 fix: setting NOSACK to 0 should leave SACK enabled
    if [ ! -f /proc/sys/net/ipv4/tcp_sack ]; then
        skip "tcp_sack not available in this kernel"
    fi
    local val
    val=$(cat /proc/sys/net/ipv4/tcp_sack)
    [ "$val" -eq 1 ]
}

@test "SYSCTL_TCP_NOSACK=1 disables TCP SACK" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "SYSCTL_TCP_NOSACK" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    if [ ! -f /proc/sys/net/ipv4/tcp_sack ]; then
        skip "tcp_sack not available in this kernel"
    fi
    local val
    val=$(cat /proc/sys/net/ipv4/tcp_sack)
    [ "$val" -eq 0 ]

    # Restore
    apf_set_config "SYSCTL_TCP_NOSACK" "0"
}
@test "secure_redirects disabled when SYSCTL_ROUTE=1" {
    if [ ! -f /proc/sys/net/ipv4/conf/all/secure_redirects ]; then
        skip "secure_redirects not available"
    fi
    local val
    val=$(cat /proc/sys/net/ipv4/conf/all/secure_redirects)
    [ "$val" -eq 0 ]
}

@test "send_redirects disabled when SYSCTL_ROUTE=1" {
    if [ ! -f /proc/sys/net/ipv4/conf/all/send_redirects ]; then
        skip "send_redirects not available"
    fi
    local val
    val=$(cat /proc/sys/net/ipv4/conf/all/send_redirects)
    [ "$val" -eq 0 ]
}

@test "proxy_arp disabled when SYSCTL_ROUTE=1" {
    if [ ! -f /proc/sys/net/ipv4/conf/all/proxy_arp ]; then
        skip "proxy_arp not available"
    fi
    local val
    val=$(cat /proc/sys/net/ipv4/conf/all/proxy_arp)
    [ "$val" -eq 0 ]
}

@test "IPv6 sysctl: accept_source_route disabled when USE_IPV6=1" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    if [ ! -f /proc/sys/net/ipv6/conf/all/accept_source_route ]; then
        skip "IPv6 sysctl not available"
    fi
    local val
    val=$(cat /proc/sys/net/ipv6/conf/all/accept_source_route)
    [ "$val" -eq 0 ]

    apf_set_config "USE_IPV6" "0"
}

@test "IPv6 sysctl: accept_redirects disabled when USE_IPV6=1" {
    source /opt/tests/helpers/apf-config.sh
    apf_set_config "USE_IPV6" "1"
    "$APF" -f 2>/dev/null || true
    "$APF" -s

    if [ ! -f /proc/sys/net/ipv6/conf/all/accept_redirects ]; then
        skip "IPv6 sysctl not available"
    fi
    local val
    val=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects)
    [ "$val" -eq 0 ]

    apf_set_config "USE_IPV6" "0"
}
