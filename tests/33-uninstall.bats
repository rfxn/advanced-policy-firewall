#!/usr/bin/env bats
#
# 33: Uninstall script basic coverage
#
# Validates uninstall.sh: non-existent path rejection, selective removal
# (keep/remove install dir), symlink/cron/man page cleanup.

load '/usr/local/lib/bats/bats-support/load'
load '/usr/local/lib/bats/bats-assert/load'

APF="/opt/apf/apf"
APF_DIR="/opt/apf"
APF_SRC="/opt/apf-src"

setup_file() {
    source /opt/tests/helpers/setup-netns.sh
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

teardown_file() {
    "$APF" -f 2>/dev/null || true
    # Ensure APF is re-installed for any subsequent test files
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
    source /opt/tests/helpers/teardown-netns.sh
}

@test "uninstall.sh exits 1 for non-existent INSTALL_PATH" {
    run env INSTALL_PATH=/opt/apf-nonexistent sh "$APF_SRC/uninstall.sh"
    assert_failure
    assert_output --partial "does not exist"
}

@test "uninstall.sh removes symlinks and man page, keeps dir when answering no" {
    # Pre-check: symlink and man page should exist after install
    [ -L "/usr/local/sbin/apf" ] || skip "apf symlink not present"

    # Answer 'n' to both prompts (remove dir? remove logs?)
    run sh -c "printf 'n\nn\n' | sh '$APF_SRC/uninstall.sh'"
    assert_success
    assert_output --partial "Removing"
    assert_output --partial "Kept $APF_DIR"

    # Symlink should be gone
    [ ! -L "/usr/local/sbin/apf" ]

    # Man page should be gone
    [ ! -f "/usr/share/man/man8/apf.8.gz" ]

    # Install dir should still exist
    [ -d "$APF_DIR" ]

    # Re-install for next test
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}

@test "uninstall.sh removes install dir and logs when answering yes" {
    # Answer 'y' to both prompts
    run sh -c "printf 'y\ny\n' | sh '$APF_SRC/uninstall.sh'"
    assert_success
    assert_output --partial "Removed $APF_DIR"
    assert_output --partial "Removed log files"

    # Install dir should be gone
    [ ! -d "$APF_DIR" ]

    # Re-install for subsequent tests
    source /opt/tests/helpers/install-apf.sh
    source /opt/tests/helpers/apf-config.sh
    apf_set_interface "veth-pub" ""
}
