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
