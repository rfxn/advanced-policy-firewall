#!/usr/bin/env bats
#
# 14: Install path substitution and service installation
#
# Verifies install.sh correctly handles non-default INSTALL_PATH,
# creates expected files, sets permissions, and installs services.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF_DIR="/opt/apf"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
}

teardown_file() {
    # Restore clean install state (importconf tests may have re-run install.sh)
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/teardown-netns.sh
}

@test "non-default INSTALL_PATH: conf.apf references /opt/apf" {
    run grep "/opt/apf" "$APF_DIR/conf.apf"
    assert_success
}

@test "non-default INSTALL_PATH: apf script references /opt/apf" {
    # The main apf script should have paths sed-replaced
    run grep "/opt/apf" "$APF_DIR/apf"
    assert_success
}

@test "non-default INSTALL_PATH: firewall script references /opt/apf" {
    run grep "/opt/apf" "$APF_DIR/firewall"
    assert_success
}

@test "symlink created at BINPATH" {
    [ -L "/usr/local/sbin/apf" ]
    [ -x "/usr/local/sbin/apf" ]
}

@test "symlink created at COMPAT_BINPATH" {
    [ -L "/usr/local/sbin/fwmgr" ]
}

@test "conf.apf has correct permissions (640)" {
    local perms
    perms=$(stat -c "%a" "$APF_DIR/conf.apf")
    [ "$perms" = "640" ]
}

@test "apf executable has correct permissions (750)" {
    local perms
    perms=$(stat -c "%a" "$APF_DIR/apf")
    [ "$perms" = "750" ]
}

@test "cron.d/apf installed" {
    if [ ! -d "/etc/cron.d" ]; then
        skip "cron.d not available"
    fi
    [ -f "/etc/cron.d/apf" ]
}

@test "cron.d/apf contains daily restart and ipset and temp-expire" {
    if [ ! -f "/etc/cron.d/apf" ]; then
        skip "cron.d/apf not installed"
    fi
    run grep "apf -r" /etc/cron.d/apf
    assert_success
    run grep -- "--ipset-update" /etc/cron.d/apf
    assert_success
    run grep -- "--temp-expire" /etc/cron.d/apf
    assert_success
}

@test "legacy cron files removed during install" {
    [ ! -f "/etc/cron.daily/apf" ]
    [ ! -f "/etc/cron.d/apf_ipset" ]
    [ ! -f "/etc/cron.d/apf_temp" ]
}

@test "cron.d/apf references install path not /etc/apf" {
    if [ ! -f "/etc/cron.d/apf" ]; then
        skip "cron.d/apf not installed"
    fi
    run grep "/opt/apf/apf" /etc/cron.d/apf
    assert_success
    run grep "/etc/apf/apf" /etc/cron.d/apf
    assert_failure
}

# =====================================================================
# importconf upgrade path tests
#
# Simulate upgrade by creating .bk.last backup directory and re-running
# install.sh, which triggers importconf to merge old config into new.
# =====================================================================

@test "importconf preserves user config values during upgrade" {
    # Clean any pre-existing backup (setup_file install may create .bk.last symlink)
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    # Create backup simulating previous install
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    # Modify a config value in the backup
    sed -i 's/^IG_TCP_CPORTS=.*/IG_TCP_CPORTS="22,80,443"/' "${APF_DIR}.bk.last/conf.apf"
    # Re-run install (triggers importconf)
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" sh install.sh >/dev/null 2>&1
    # Verify the user's custom value was preserved
    run grep '^IG_TCP_CPORTS="22,80,443"' "$APF_DIR/conf.apf"
    assert_success
    # Clean up
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}

@test "importconf provides defaults for new variables" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    # Remove new variables from backup config (simulating upgrade from older version)
    sed -i '/^SYNFLOOD=/d' "${APF_DIR}.bk.last/conf.apf"
    sed -i '/^SMTP_BLOCK=/d' "${APF_DIR}.bk.last/conf.apf"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" sh install.sh >/dev/null 2>&1
    # Verify new variables got their defaults via .ca.def preamble
    run grep '^SYNFLOOD="0"' "$APF_DIR/conf.apf"
    assert_success
    run grep '^SMTP_BLOCK="0"' "$APF_DIR/conf.apf"
    assert_success
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}

@test "importconf preserves hook script permissions" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    # Make hook executable in backup (simulating user-activated hook)
    chmod 750 "${APF_DIR}.bk.last/hook_pre.sh"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" sh install.sh >/dev/null 2>&1
    # Verify hook retained executable permission (importconf uses cp -pf)
    [ -x "$APF_DIR/hook_pre.sh" ]
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}

@test "importconf preserves trust and rule files" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    # Add entries to backup trust/rule files
    echo "192.0.2.50 # test entry" >> "${APF_DIR}.bk.last/allow_hosts.rules"
    echo "198.51.100.1" >> "${APF_DIR}.bk.last/silent_ips.rules"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" sh install.sh >/dev/null 2>&1
    # Verify entries were preserved
    run grep "192.0.2.50" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "198.51.100.1" "$APF_DIR/silent_ips.rules"
    assert_success
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}

@test "importconf preserves preroute and postroute rules" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    # Add custom rules to preroute and postroute in backup
    echo "-A PREROUTING -p tcp --dport 80 -j TOS --set-tos 0x10" >> "${APF_DIR}.bk.last/preroute.rules"
    echo "-A POSTROUTING -p tcp --sport 80 -j TOS --set-tos 0x10" >> "${APF_DIR}.bk.last/postroute.rules"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" sh install.sh >/dev/null 2>&1
    # Verify custom preroute content preserved
    run grep "PREROUTING.*TOS" "$APF_DIR/preroute.rules"
    assert_success
    # Verify custom postroute content preserved
    run grep "POSTROUTING.*TOS" "$APF_DIR/postroute.rules"
    assert_success
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}

@test "log rotation config installed" {
    if [ ! -d "/etc/logrotate.d" ]; then
        skip "logrotate not available"
    fi
    [ -f "/etc/logrotate.d/apf" ]
}

@test "install directory has correct permissions (750)" {
    local perms
    perms=$(stat -c "%a" "$APF_DIR")
    [ "$perms" = "750" ]
}

@test "firewall script has correct permissions (750)" {
    local perms
    perms=$(stat -c "%a" "$APF_DIR/firewall")
    [ "$perms" = "750" ]
}

@test "vnetgen has correct permissions (750)" {
    local perms
    perms=$(stat -c "%a" "$APF_DIR/vnet/vnetgen")
    [ "$perms" = "750" ]
}

@test "man page installed to /usr/share/man/man8/" {
    if [ ! -d "/usr/share/man/man8" ]; then
        skip "man page directory not available"
    fi
    [ -f "/usr/share/man/man8/apf.8.gz" ]
}

@test "man page has correct permissions (644)" {
    if [ ! -f "/usr/share/man/man8/apf.8.gz" ]; then
        skip "man page not installed"
    fi
    local perms
    perms=$(stat -c '%a' /usr/share/man/man8/apf.8.gz)
    [ "$perms" = "644" ]
}

@test "man page contains path-substituted install path" {
    if [ ! -f "/usr/share/man/man8/apf.8.gz" ]; then
        skip "man page not installed"
    fi
    run zgrep '/opt/apf' /usr/share/man/man8/apf.8.gz
    assert_success
}

# =====================================================================
# install.sh modernization tests
# =====================================================================

@test "subdirectories have 750 permissions after install" {
    # All directories under INSTALL_PATH should be 750
    local bad
    bad=$(find "$APF_DIR" -type d ! -perm 750 2>/dev/null)
    [ -z "$bad" ]
}

@test "install produces no Device errors on stderr" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cd /opt/apf-src
    local stderr_out
    stderr_out=$(INSTALL_PATH="$APF_DIR" sh install.sh 2>&1 1>/dev/null)
    [[ ! "$stderr_out" =~ "Device" ]]
}

@test "upgrade produces no 'cannot stat' errors with empty vnet" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    # Remove any .rules files from backup vnet dir to trigger glob failure
    rm -f "${APF_DIR}.bk.last"/vnet/*.rules 2>/dev/null || true
    cd /opt/apf-src
    local output
    output=$(INSTALL_PATH="$APF_DIR" sh install.sh 2>&1)
    [[ ! "$output" =~ "cannot stat" ]]
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}

@test "same-version reinstall shows 'Restored configuration' message" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    cd /opt/apf-src
    local output
    output=$(INSTALL_PATH="$APF_DIR" sh install.sh 2>&1)
    [[ "$output" =~ "Restored configuration from backup" ]]
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}

@test "existing IFACE_UNTRUSTED preserved on upgrade" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    # Set custom interface in backup
    sed -i 's/^IFACE_UNTRUSTED=.*/IFACE_UNTRUSTED="ens192"/' "${APF_DIR}.bk.last/conf.apf"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" sh install.sh >/dev/null 2>&1
    # importconf should have preserved the user's custom value
    run grep '^IFACE_UNTRUSTED="ens192"' "$APF_DIR/conf.apf"
    assert_success
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}

@test "fresh install shows Default interface in output" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cd /opt/apf-src
    local output
    output=$(INSTALL_PATH="$APF_DIR" sh install.sh 2>&1)
    [[ "$output" =~ "Default interface:" ]]
}

@test "upgrade install shows Default interface in output" {
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
    cp -a "$APF_DIR" "${APF_DIR}.bk.last"
    cd /opt/apf-src
    local output
    output=$(INSTALL_PATH="$APF_DIR" sh install.sh 2>&1)
    [[ "$output" =~ "Default interface:" ]]
    rm -rf "${APF_DIR}.bk.last" "${APF_DIR}".bk[0-9]*
}
