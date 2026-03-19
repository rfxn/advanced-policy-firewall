#!/usr/bin/env bats
#
# 14: Install path substitution and service installation
#
# Verifies install.sh correctly handles non-default INSTALL_PATH,
# creates expected files, sets permissions, and installs services.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF_DIR="/opt/apf"
# pkg_backup places .bk.last symlink in parent dir of install path
BK_SYMLINK="/opt/.bk.last"

# _create_test_backup — create backup directory and .bk.last symlink
# simulating pkg_backup behavior for upgrade path testing
_create_test_backup() {
    local bk_dir="${APF_DIR}.bk.test"
    cp -a "$APF_DIR" "$bk_dir"
    rm -f "$BK_SYMLINK"
    ln -s "$bk_dir" "$BK_SYMLINK"
    echo "$bk_dir"
}

# _clean_test_backup — remove backup directory, symlink, and any
# pkg_backup-created timestamped directories
_clean_test_backup() {
    rm -f "$BK_SYMLINK"
    rm -rf "${APF_DIR}".bk.test "${APF_DIR}".[0-9]* "${APF_DIR}".bk[0-9]*
}

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
}

teardown_file() {
    # Restore clean install state (importconf tests may have re-run install.sh)
    _clean_test_backup
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

@test "non-default INSTALL_PATH: apf_core.sh uses INSTALL_PATH variable" {
    # apf_core.sh uses $INSTALL_PATH throughout (no hardcoded /etc/apf to sed-replace)
    run grep 'INSTALL_PATH' "$APF_DIR/internals/apf_core.sh"
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

@test "runtime cron refresh.apf cleaned during install" {
    if [ ! -d "/etc/cron.d" ]; then
        skip "cron.d not available"
    fi
    # Simulate runtime-created refresh cron
    echo "*/10 * * * * root /opt/apf/apf --refresh >> /dev/null 2>&1 &" > /etc/cron.d/refresh.apf
    [ -f "/etc/cron.d/refresh.apf" ]
    cd /opt/apf-src
    # install.sh may exit non-zero in Docker (service setup fails) — tolerate it;
    # we're testing the cron file removal side effect, not install.sh exit code
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1 || true
    [ ! -f "/etc/cron.d/refresh.apf" ]
}

@test "runtime cron apf_develmode cleaned during install" {
    if [ ! -d "/etc/cron.d" ]; then
        skip "cron.d not available"
    fi
    # Simulate runtime-created develmode cron
    echo "*/5 * * * * root /opt/apf/apf -f >> /dev/null 2>&1" > /etc/cron.d/apf_develmode
    [ -f "/etc/cron.d/apf_develmode" ]
    cd /opt/apf-src
    # install.sh may exit non-zero in Docker (service setup fails) — tolerate it
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1 || true
    [ ! -f "/etc/cron.d/apf_develmode" ]
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
# Simulate upgrade by modifying the live install, then re-running
# install.sh. pkg_backup creates a backup of the modified install
# (updating .bk.last), and importconf merges old config from that
# backup into the fresh install.
# =====================================================================

@test "importconf preserves user config values during upgrade" {
    _clean_test_backup
    # Modify a config value in the live install (simulating user customization)
    sed -i 's/^IG_TCP_CPORTS=.*/IG_TCP_CPORTS="22,80,443"/' "$APF_DIR/conf.apf"
    # Re-run install — pkg_backup backs up the modified install, importconf merges
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    # Verify the user's custom value was preserved
    run grep '^IG_TCP_CPORTS="22,80,443"' "$APF_DIR/conf.apf"
    assert_success
    _clean_test_backup
}

@test "importconf provides defaults for new variables" {
    _clean_test_backup
    # Remove variables from live install (simulating upgrade from older version)
    sed -i '/^SYNFLOOD=/d' "$APF_DIR/conf.apf"
    sed -i '/^SMTP_BLOCK=/d' "$APF_DIR/conf.apf"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    # Verify new variables got their defaults from the new config template
    run grep '^SYNFLOOD="0"' "$APF_DIR/conf.apf"
    assert_success
    run grep '^SMTP_BLOCK="0"' "$APF_DIR/conf.apf"
    assert_success
    _clean_test_backup
}

@test "importconf preserves hook script permissions" {
    _clean_test_backup
    # Make hook executable in live install (simulating user-activated hook)
    chmod 750 "$APF_DIR/hook_pre.sh"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    # Verify hook retained executable permission (importconf uses cp -pf)
    [ -x "$APF_DIR/hook_pre.sh" ]
    _clean_test_backup
}

@test "importconf preserves trust and rule files" {
    _clean_test_backup
    # Add entries to live trust/rule files (simulating user customization)
    echo "192.0.2.50 # test entry" >> "$APF_DIR/allow_hosts.rules"
    echo "198.51.100.1" >> "$APF_DIR/silent_ips.rules"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    # Verify entries were preserved
    run grep "192.0.2.50" "$APF_DIR/allow_hosts.rules"
    assert_success
    run grep "198.51.100.1" "$APF_DIR/silent_ips.rules"
    assert_success
    _clean_test_backup
}

@test "importconf preserves preroute and postroute rules" {
    _clean_test_backup
    # Add custom rules to live preroute and postroute (simulating user customization)
    echo "-A PREROUTING -p tcp --dport 80 -j TOS --set-tos 0x10" >> "$APF_DIR/preroute.rules"
    echo "-A POSTROUTING -p tcp --sport 80 -j TOS --set-tos 0x10" >> "$APF_DIR/postroute.rules"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    # Verify custom preroute content preserved
    run grep "PREROUTING.*TOS" "$APF_DIR/preroute.rules"
    assert_success
    # Verify custom postroute content preserved
    run grep "POSTROUTING.*TOS" "$APF_DIR/postroute.rules"
    assert_success
    _clean_test_backup
}

@test "importconf migrates EG_DROP_CMD from space to comma separated" {
    _clean_test_backup
    # Set space-separated EG_DROP_CMD in live install (simulating pre-2.0.2 config)
    sed -i 's/^EG_DROP_CMD=.*/EG_DROP_CMD="eggdrop psybnc bitchx"/' "$APF_DIR/conf.apf"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    # Verify EG_DROP_CMD converted to comma-separated in installed conf.apf
    run grep '^EG_DROP_CMD="eggdrop,psybnc,bitchx"' "$APF_DIR/conf.apf"
    assert_success
    _clean_test_backup
}

@test "importconf preserves already comma-separated EG_DROP_CMD" {
    _clean_test_backup
    # Set already comma-separated EG_DROP_CMD (should not be changed)
    sed -i 's/^EG_DROP_CMD=.*/EG_DROP_CMD="eggdrop,psybnc,bitchx"/' "$APF_DIR/conf.apf"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    run grep '^EG_DROP_CMD="eggdrop,psybnc,bitchx"' "$APF_DIR/conf.apf"
    assert_success
    _clean_test_backup
}

@test "importconf preserves cc_deny.rules during upgrade" {
    _clean_test_backup
    # Add CC deny entry (simulating user's country blocking config)
    echo "CN" >> "$APF_DIR/cc_deny.rules"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    run grep "CN" "$APF_DIR/cc_deny.rules"
    assert_success
    _clean_test_backup
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

@test "apf_core.sh library has correct permissions (640)" {
    local perms
    perms=$(stat -c "%a" "$APF_DIR/internals/apf_core.sh")
    [ "$perms" = "640" ]
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
    _clean_test_backup
    cd /opt/apf-src
    local stderr_out
    stderr_out=$(INSTALL_PATH="$APF_DIR" bash install.sh 2>&1 1>/dev/null)
    [[ ! "$stderr_out" =~ "Device" ]]
}

@test "upgrade produces no 'cannot stat' errors with empty vnet" {
    _clean_test_backup
    # Remove any .rules files from live vnet dir to test glob failure case
    rm -f "$APF_DIR"/vnet/*.rules 2>/dev/null || true
    cd /opt/apf-src
    local output
    output=$(INSTALL_PATH="$APF_DIR" bash install.sh 2>&1)
    [[ ! "$output" =~ "cannot stat" ]]
    _clean_test_backup
}

@test "same-version reinstall shows 'Restored configuration' message" {
    _clean_test_backup
    _create_test_backup >/dev/null
    cd /opt/apf-src
    local output
    output=$(INSTALL_PATH="$APF_DIR" bash install.sh 2>&1)
    [[ "$output" =~ "Restored configuration from backup" ]]
    _clean_test_backup
}

@test "existing IFACE_UNTRUSTED preserved on upgrade" {
    _clean_test_backup
    # Set custom interface in live install (simulating user customization)
    sed -i 's/^IFACE_UNTRUSTED=.*/IFACE_UNTRUSTED="ens192"/' "$APF_DIR/conf.apf"
    cd /opt/apf-src
    INSTALL_PATH="$APF_DIR" bash install.sh >/dev/null 2>&1
    # importconf should have preserved the user's custom value
    run grep '^IFACE_UNTRUSTED="ens192"' "$APF_DIR/conf.apf"
    assert_success
    _clean_test_backup
}

@test "fresh install shows Default interface in output" {
    _clean_test_backup
    cd /opt/apf-src
    local output
    output=$(INSTALL_PATH="$APF_DIR" bash install.sh 2>&1)
    [[ "$output" =~ "Default interface:" ]]
}

@test "upgrade install shows Default interface in output" {
    _clean_test_backup
    _create_test_backup >/dev/null
    cd /opt/apf-src
    local output
    output=$(INSTALL_PATH="$APF_DIR" bash install.sh 2>&1)
    [[ "$output" =~ "Default interface:" ]]
    _clean_test_backup
}
