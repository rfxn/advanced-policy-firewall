#!/bin/bash
# APF pre-configuration hook — sourced before any iptables rules are applied.
# Kernel modules are loaded and chains are flushed at this point.
# All APF variables and helpers (ipt/ipt4/ipt6, eout, etc.) are available.
# Make this file executable (chmod 750) to activate.
#
# Example: ipt -N MYCUSTOMCHAIN
