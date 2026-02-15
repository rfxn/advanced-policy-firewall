#!/bin/bash
#
# Resets APF to clean state for testing. APF is pre-installed during
# Docker build; this script restores config and trust files to their
# pristine post-install state. Much faster than re-running install.sh.

APF_INSTALL="${APF_INSTALL:-/opt/apf}"

reset_apf() {
    cp "$APF_INSTALL/conf.apf.clean" "$APF_INSTALL/conf.apf"
    cp "$APF_INSTALL/allow_hosts.rules.clean" "$APF_INSTALL/allow_hosts.rules"
    cp "$APF_INSTALL/deny_hosts.rules.clean" "$APF_INSTALL/deny_hosts.rules"
    rm -f "$APF_INSTALL/internals/.apf.restore" \
          "$APF_INSTALL/internals/.apf6.restore" \
          "$APF_INSTALL/internals/.last.full" \
          "$APF_INSTALL/internals/.apf.restore.backend" \
          "$APF_INSTALL/internals/.localaddrs" \
          "$APF_INSTALL/internals/.localaddrs6"
    touch /var/log/apf_log
    chmod 600 /var/log/apf_log
}

reset_apf
