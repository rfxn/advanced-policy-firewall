#!/bin/bash
# APF post-configuration hook — sourced after all iptables rules are applied,
# including default DROP policies. All APF variables and helpers are available.
# Make this file executable (chmod 750) to activate.
#
# Example: restoring Docker chains after APF restart
# Example: ipt -I INPUT -s 203.0.113.0/24 -j ACCEPT
