# Advanced Policy Firewall (APF)

[![Version](https://img.shields.io/badge/version-2.0.2-blue.svg)](CHANGELOG)
[![License: GPL v2](https://img.shields.io/badge/license-GPL_v2-green.svg)](COPYING.GPL)
[![CI](https://github.com/rfxn/advanced-policy-firewall/actions/workflows/smoke-test.yml/badge.svg?branch=master)](https://github.com/rfxn/advanced-policy-firewall/actions/workflows/smoke-test.yml)

**iptables/netfilter-based firewall management for Linux servers** — stateful packet filtering,
trust-based host management, reactive address blocking, and per-IP virtual network policies.

> (C) 2002-2026, R-fx Networks &lt;proj@rfxn.com&gt;<br>
> (C) 2026, Ryan MacDonald &lt;ryan@rfxn.com&gt;<br>
> Licensed under [GNU GPL v2](COPYING.GPL)

---

## Contents

- [1. Introduction](#1-introduction)
  - [1.1 Supported Systems & Requirements](#11-supported-systems--requirements)
- [2. Installation](#2-installation)
  - [2.1 Boot Loading](#21-boot-loading)
  - [2.2 Upgrading](#22-upgrading)
  - [2.3 Key Files](#23-key-files)
  - [2.4 Uninstallation](#24-uninstallation)
- [3. Configuration](#3-configuration)
  - [3.1 Basic Options](#31-basic-options)
  - [3.2 Outbound Filtering & Rate Limiting](#32-outbound-filtering--rate-limiting)
  - [3.3 Advanced Options](#33-advanced-options)
  - [3.4 Reactive Address Blocking](#34-reactive-address-blocking)
  - [3.5 Virtual Network Files](#35-virtual-network-files)
  - [3.6 Global Variables & Custom Rules](#36-global-variables--custom-rules)
  - [3.7 Hook Scripts](#37-hook-scripts)
  - [3.8 Silent IP Blocking](#38-silent-ip-blocking)
  - [3.9 Docker/Container Compatibility](#39-dockercontainer-compatibility)
  - [3.10 ipset Block Lists](#310-ipset-block-lists)
  - [3.11 GRE Tunnels](#311-gre-tunnels)
  - [3.12 Remote Block Lists](#312-remote-block-lists)
  - [3.13 Logging & Control](#313-logging--control)
  - [3.14 Implicit Blocking](#314-implicit-blocking)
  - [3.15 Firewall Order of Operations](#315-firewall-order-of-operations)
- [4. General Usage](#4-general-usage)
  - [4.1 Trust System](#41-trust-system)
  - [4.2 Global Trust System](#42-global-trust-system)
  - [4.3 Advanced Trust Syntax](#43-advanced-trust-syntax)
  - [4.4 Temporary Trust Entries](#44-temporary-trust-entries)
  - [4.5 Troubleshooting](#45-troubleshooting)
- [5. License](#5-license)
- [6. Support Information](#6-support-information)

---

## Quick Start

```bash
# Install
bash install.sh

# Configure — edit ports, interfaces, options
vi /etc/apf/conf.apf

# Start (DEVEL_MODE auto-flushes every 5 min until disabled)
apf -s

# Trust/deny hosts on the fly
apf -a 10.0.0.5 "office gateway"
apf -d 192.168.3.111 "brute force attempts"

# Disable dev mode for persistent operation
sed -i 's/DEVEL_MODE="1"/DEVEL_MODE="0"/' /etc/apf/conf.apf
apf -r
```

---

## 1. Introduction

Advanced Policy Firewall (APF) is an iptables(netfilter) based firewall system designed for Internet-facing Linux servers. Configuration is managed through a single annotated file (`conf.apf`) and day-to-day operations through the `apf` command.

The filtering performed by APF is three fold:

1. **Static rule based policies** (not to be confused with a "static firewall")
2. **Connection based stateful policies**
3. **Sanity based policies**

**Static rule based policies** is the most traditional method of firewalling — an unchanging set of rules for how traffic should be handled. For example, allowing/denying an address via the trust system or opening a port in `conf.apf`.

**Connection based stateful policies** distinguishes legitimate packets by tracking known connections. For example, FTP data transfers are dynamically permitted by relating port 21 control connections to the data channel — no complex static rules needed.

**Sanity based policies** matches traffic against known attack methods and Internet standards. Forged source addresses are discarded, malformed packets from broken routers are dropped or replied to with TCP Reset.

For a detailed description of all APF features, review `conf.apf` (under your install path) which has well outlined captions above all options.

**Filtering & Rules**
- Granular inbound/outbound TCP/UDP/ICMP/ICMPv6 port filtering
- IPv6 dual-stack support with automatic ip6tables rules
- Per-port concurrent connection limiting (connlimit)
- User/application-based outbound filtering (uid-owner, cmd-owner)
- SMTP outbound blocking with per-user and per-group exemptions
- Packet sanity checks (forged sources, malformed flags, fragments)
- Type of Service (TOS) traffic prioritization

**Trust System**
- Allow/deny host management (IPv4, IPv6, CIDR, FQDN)
- Advanced trust syntax (proto:flow:port:ip)
- Global trust with central server download
- Auto-expire and trim for deny lists

**Blocking & Prevention**
- Reactive address blocking (RAB) with port scan detection
- Remote block lists (Spamhaus, DShield, Project Honey Pot)
- ipset kernel-level block lists with O(1) lookup
- SYN flood rate limiting (iptables-level, complements kernel sysctl)
- Implicit blocking (P2P, private/reserved space, ident)

**Infrastructure**
- Virtual network (VNET) per-IP policies
- GRE tunnel management with dedicated chains
- Custom hook scripts (pre/post firewall rules)
- Silent IP blocking (silent drop for server addresses)
- Docker/container compatibility mode
- Fast load snapshots with nft backend detection
- Kernel tuning via sysctl (conntrack, syn-flood, routing)
- systemd service unit and legacy init support
- Automatic dependency checking with OS-aware install hints

### 1.1 Supported Systems & Requirements

The APF package is designed to run on Linux based operating systems that have an operational version of the iptables (netfilter) package installed. Both the traditional iptables-legacy and the newer iptables-nft backends are supported. You can find out more details on the netfilter project at: https://www.netfilter.org/

Most modern Linux distributions include all required iptables/netfilter modules by default. If you are building a custom kernel, ensure the following modules are available (built-in or modular):

```
iptable_filter
iptable_mangle
nf_conntrack
nf_conntrack_ftp
nf_conntrack_irc
xt_state (or nf_conntrack with CT target)
xt_multiport
xt_limit
xt_recent
xt_LOG (or nf_log_syslog)
xt_REJECT (ipt_REJECT / ip6t_REJECT)
xt_ecn
xt_length
xt_mac
xt_owner
xt_TCPMSS
```

For IPv6 support (`USE_IPV6=1`), also ensure:

```
ip6table_filter
ip6table_mangle
nf_conntrack_ipv6 (on kernels < 4.19; merged into nf_conntrack on 4.19+)
```

APF will attempt to load each module at startup and report any that are missing. You can check available modules with:

```bash
ls /lib/modules/$(uname -r)/kernel/net/netfilter/
```

**Supported platforms:**

- RHEL / Rocky Linux / AlmaLinux 8, 9
- CentOS 7 (legacy support)
- Debian 12
- Ubuntu 20.04, 24.04

APF will generally run on any Linux distribution that provides iptables (legacy or nft backend) and a bash shell with standard GNU utilities (grep, awk, sed, etc.).

APF includes automatic dependency checking at startup. Critical dependencies (iptables, ip, modprobe, ip6tables when `USE_IPV6=1`) will prevent the firewall from starting if missing. Optional dependencies (wget, iptables-save, iptables-restore, diff, ipset) produce warnings but allow startup to continue. Install hints are OS-aware and suggest the correct package manager command (apt-get, yum, or dnf) for your distribution.

---

## 2. Installation

The installation setup of APF is very straight forward, there is an included `install.sh` script that will perform all the tasks of installing APF for you.

```bash
# Default install
bash install.sh

# Custom install path
INSTALL_PATH=/etc/yourpath bash install.sh
```

If one so desires they may customize the setup of APF by editing the variables inside the `install.sh` script followed by also editing the path variables in the `conf.apf` and `internals.conf` files. This is however not recommended and the default paths should meet all user needs, they are:

- **Install Path:** `/etc/apf`
- **Bin Path:** `/usr/local/sbin/apf`

The package includes two convenience scripts, the first is `importconf` which will import all the variable settings from your previous version of APF into the new installation. The second is `get_ports`, a script which will output the system's currently in use 'server' ports for the user during the installation process in an effort to aid in configuring port settings.

All previous versions of APF are saved upon the installation of newer versions and stored in `/etc/apf.DDMMYYYY-EPOCH` format (e.g., `/etc/apf.19022026-1771538400`). In addition, there is a `/etc/.bk.last` symlink created pointing to the most recent backup directory.

After installation is completed the documentation and convenience scripts are copied to `/etc/apf/doc` and `/etc/apf/extras` respectively.

> **Note:** APF ships with `DEVEL_MODE="1"` enabled by default. This safety feature automatically flushes the firewall every 5 minutes to prevent lockout during initial configuration. Set `DEVEL_MODE="0"` in `conf.apf` once your configuration is verified and you are ready for persistent operation.

A comprehensive man page is installed automatically; run `man apf` for a complete CLI and configuration reference.

### 2.1 Boot Loading

On installation APF will install a systemd service unit (`apf.service`) on systems with systemd, or an init script to `/etc/init.d/apf` on older systems, and configure it to load on boot. If you are setting up APF in a more custom situation then you may follow the below instructions.

There are three modes of operation for having APF firewall your system and each has no real benefit except tailoring itself to your needs.

**The first and recommended approach** on modern systems is systemd:

```bash
systemctl enable apf
systemctl start apf
```

On older systems without systemd, use chkconfig (done by default during install on SysV-init systems):

```bash
chkconfig --add apf
chkconfig --level 345 apf on
```

**Secondly**, you can add the following string to the bottom of the `/etc/rc.local` file:

```bash
sh -c "/etc/apf/apf -s" &
```

It is **NOT** recommended that you use multiple startup methods together.

**The third and final approach** is to simply run APF in an on-demand fashion. That is, enable it with the `apf -s` command when desired and disable it with the `apf -f` when desired.

### 2.2 Upgrading

When upgrading from a previous version of APF:

- `install.sh` automatically backs up your existing installation to `/etc/apf.DDMMYYYY-EPOCH` before overwriting.
- `importconf` migrates your `conf.apf` settings into the new version, preserving customized values while adding new variables.
- New configuration variables introduced in later versions receive safe defaults from the `.ca.def` preamble, so upgrades never produce unbound variable errors.
- Hook scripts (`hook_pre.sh`, `hook_post.sh`), `silent_ips.rules`, and trust files are preserved across upgrades via `importconf`.
- Review the CHANGELOG for new features, changed defaults, and any manual steps required for your version.

### 2.3 Key Files

The following files are located under your install path (`/etc/apf` by default):

| File | Purpose |
|------|---------|
| `conf.apf` | Main configuration file |
| `allow_hosts.rules` | Local allow trust list |
| `deny_hosts.rules` | Local deny trust list |
| `glob_allow.rules` | Global (downloaded) allow list |
| `glob_deny.rules` | Global (downloaded) deny list |
| `ipset.rules` | ipset block list definitions |
| `gre.rules` | GRE tunnel definitions |
| `hook_pre.sh` | Pre-configuration hook script (640 = inactive) |
| `hook_post.sh` | Post-configuration hook script (640 = inactive) |
| `silent_ips.rules` | Silent IP blocking list |
| `preroute.rules` | Pre-routing custom rules |
| `postroute.rules` | Post-routing custom rules |
| `vnet/` | Per-IP virtual network policy files |
| `/etc/cron.d/apf` | Consolidated cron: daily restart, hourly ipset refresh, per-minute temp trust expiry |
| `/var/log/apf_log` | Default status log location |

### 2.4 Uninstallation

To fully remove APF from the system, run the uninstall script from the source directory:

```bash
sh uninstall.sh
```

The uninstaller will:

- Stop the firewall and flush all iptables rules
- Remove systemd service, SysV init scripts, and rc.local entries
- Remove cron entries (current and legacy)
- Remove logrotate config, symlinks, and man page
- Prompt before removing the install directory and log files

To override the install path (if APF was installed to a non-default location):

```bash
INSTALL_PATH=/opt/apf sh uninstall.sh
```

---

## 3. Configuration

APF ships with minimal preconfigured options by design. Only port 22 (SSH) is open by default, with advanced features like outbound filtering, reactive address blocking, and the virtual network subsystem disabled.

The main configuration file is `conf.apf` (under your install path, `/etc/apf` by default). It uses integer values (`0` = disabled, `1` = enabled) for most options unless otherwise noted. Each option has detailed usage information directly above it in the file — review it from top to bottom before starting the firewall.

### 3.1 Basic Options

This section will cover some of the basic configuration options found inside of the `conf.apf` configuration file. These options, despite how basic, are the most vital in the proper operation of your firewall.

**`DEVEL_MODE`** - Development/testing mode. The firewall shuts itself off every 5 minutes via cronjob to prevent lockout from configuration errors. Enabled by default on new installs; disable once you are satisfied with your configuration.

**`INSTALL_PATH`** - Installation path for APF (default: `/etc/apf`).

**`IFACE_UNTRUSTED`** - The Internet-facing interface that firewall rules are applied against (WAN interface).

**`IFACE_TRUSTED`** - Interfaces to exempt from all firewall rules with an implicit trust rule. Use for administrative private links, VPN interfaces, or trusted LANs (similar to a DMZ).

**`SET_VERBOSE`** - Print detailed event logs to the screen during command line firewall operations for easier troubleshooting.

**`USE_IPV6`** - Enable IPv6 dual-stack support. APF will load IPv6 kernel modules and apply ip6tables rules alongside iptables. Includes IPv6 chain creation, port filtering, trust system support, packet sanity checks, and ICMPv6 filtering. NDP types 133-136 are always permitted for IPv6 connectivity. When enabled, `IG_ICMPV6_TYPES` and `EG_ICMPV6_TYPES` control which ICMPv6 types are allowed. IPv6 sysctl hardening is applied when `SYSCTL_ROUTE=1`. IPv6 addresses in advanced trust syntax use bracket notation (e.g., `d=22:s=[2001:db8::1]`). The VNET subsystem does not currently support IPv6.

**`SET_FASTLOAD`** - Save and restore firewall snapshots for fast startup. Instead of regenerating every rule, APF loads from a saved snapshot. Configuration changes and iptables backend changes (legacy vs nft) are detected automatically, forcing a full reload when needed.

**`SET_VNET`** - Enable the virtual network subsystem (VNET) which generates per-IP policy files for aliased addresses. See [section 3.5](#35-virtual-network-files).

**`SET_ADDIFACE`** - Firewall additional untrusted interfaces through the VNET system. See [section 3.5](#35-virtual-network-files).

**Port filtering variables** (global context, overridable via VNET per-IP rules):

| Variable | Purpose |
|----------|---------|
| `IG_TCP_CPORTS` | Inbound TCP ports ("server" ports, e.g., `22,80,443`) |
| `IG_UDP_CPORTS` | Inbound UDP ports (e.g., `53` for DNS) |
| `IG_ICMP_TYPES` | Inbound ICMP types (see `internals/icmp.types`) |
| `IG_ICMPV6_TYPES` | Inbound ICMPv6 types (requires `USE_IPV6="1"`); NDP types 133-136 always permitted |
| `EGF` | Top level toggle for outbound (egress) filtering; recommended to enable |
| `EG_TCP_CPORTS` | Outbound TCP ports ("client" ports, e.g., `80,443`) |
| `EG_UDP_CPORTS` | Outbound UDP ports (e.g., `53,873`) |
| `EG_ICMP_TYPES` | Outbound ICMP types (see `internals/icmp.types`) |
| `EG_ICMPV6_TYPES` | Outbound ICMPv6 types (requires `USE_IPV6="1"`); NDP types 133-136 always permitted |

**`LOG_DROP`** - Enable detailed firewall packet logging. Typically left disabled on production systems due to log volume and disk I/O impact.

### 3.2 Outbound Filtering & Rate Limiting

These options control rate limiting, per-user outbound restrictions, and protocol-specific blocking. They build on the basic port filtering in [section 3.1](#31-basic-options).

**Per-port connection limiting** (via `xt_connlimit` module):

| Variable | Purpose |
|----------|---------|
| `IG_TCP_CLIMIT` | Per-port concurrent connection limit for inbound TCP; format is `port:limit` pairs (e.g., `"80:50,443:100,8080_8090:25"`) |
| `IG_UDP_CLIMIT` | Per-port concurrent connection limit for inbound UDP; same format |

Connections exceeding the limit from a single source IP are rejected. Port ranges use underscore notation. Set empty to disable (default). Connlimit rules are inserted before ACCEPT rules to ensure they take effect. Overridable via VNET per-IP rules.

**SYN flood protection** (via `xt_limit` module):

| Variable | Purpose |
|----------|---------|
| `SYNFLOOD` | When `"1"`, rate-limits inbound TCP SYN packets; complements kernel-level protection (`SYSCTL_SYN`, `SYSCTL_SYNCOOKIES`) with iptables enforcement |
| `SYNFLOOD_RATE` | Maximum SYN packet rate; format is `packets/unit` where unit is `s` (seconds), `m` (minutes), `h` (hours); default `"100/s"` |
| `SYNFLOOD_BURST` | Initial burst allowance before rate limiting kicks in; allows short traffic spikes without triggering; default `"150"` |

Under-limit SYN packets RETURN for normal processing (port filtering, trust checks, etc.). Excess packets are logged (if `LOG_DROP="1"`) and dropped via `TCP_STOP`. Dual-stack (IPv4 + IPv6 when `USE_IPV6="1"`).

**User/application-based outbound filtering** (requires `EGF="1"`):

| Variable | Purpose |
|----------|---------|
| `EG_TCP_UID` | UID-based outbound TCP filtering; format is `uid:port` pairs (e.g., `"0:22,33:80"`) |
| `EG_UDP_UID` | UID-based outbound UDP filtering; same format |
| `EG_DROP_CMD` | Comma-separated executable names blocked from outbound network access (e.g., `"eggdrop,psybnc,bitchx"`). Uses iptables `--cmd-owner` match. Depends on kernel xt_owner command support, detected at runtime and skipped gracefully if unavailable |

**SMTP outbound blocking** (independent of `EGF` — works whether outbound filtering is on or off):

| Variable | Purpose |
|----------|---------|
| `SMTP_BLOCK` | When `"1"`, blocks outbound SMTP for all processes except whitelisted users/groups. Forces web apps and user scripts to use the local MTA instead of opening direct SMTP connections |
| `SMTP_PORTS` | Ports to block (default `"25,465,587"` — SMTP, SMTPS, submission) |
| `SMTP_ALLOWUSER` | Comma-separated usernames allowed to send outbound SMTP. Root (UID 0) is always allowed regardless of this setting |
| `SMTP_ALLOWGROUP` | Comma-separated group names allowed to send outbound SMTP. Uses `--gid-owner` match, detected at runtime and skipped gracefully if unavailable |

Panel examples: InterWorx (`SMTP_ALLOWUSER="iworx"` `SMTP_ALLOWGROUP="mail"`), cPanel (`SMTP_ALLOWUSER="cpanel"` `SMTP_ALLOWGROUP="mail,mailman"`), Plesk (`SMTP_ALLOWUSER="postfix"` `SMTP_ALLOWGROUP="postfix,mail"`).

### 3.3 Advanced Options

The advanced options, although not required, are those which afford the firewall the ability to be a more robust and encompassing solution in protecting a host. These options should be reviewed on a case-by-case basis and enabled only as you determine their merit to meet a particular need on a host or network.

**`SET_MONOKERN`** - Expect iptables modules compiled directly into the kernel instead of loadable modules. Only enable for custom kernels with modular support disabled.

**`VF_ROUTE`** - Verify that `IFACE_*` addresses have route entries before loading. Prevents lockout from configuration errors.

**`VF_LGATE`** - Require all traffic to arrive via a specific MAC address. Useful for servers behind a NAT/MASQ gateway.

**`TCP_STOP`, `UDP_STOP`, `ALL_STOP`** - Control how filtered packets are handled:

| Value | Behavior | Tradeoff |
|-------|----------|----------|
| `DROP` (default) | Silent discard | Low resource use; reveals firewall presence |
| `RESET` | TCP RST reply | Standards-compliant; uses resources to reply |
| `REJECT` | ICMP error reply | Port appears closed, not firewalled |
| `PROHIBIT` | ICMP-only reply | Lighter than RESET; default expected behavior for UDP |

**`PKT_SANITY`** - Top level toggle for packet sanity checks. Ensures all packets conform to strict TCP/IP standards. Sub-options (`PKT_SANITY_INV`, `PKT_SANITY_FUDP`, `PKT_SANITY_PZERO`) are preconfigured to suit most situations. See `conf.apf` for details.

**Type of Service (`TOS_*`)** - Classify traffic priority based on port numbers. Default settings improve throughput and reliability for FTP, HTTP, SMTP, POP3 and IMAP. Review `conf.apf` for detailed TOS options.

**Traceroute (`TCR_*`)** - `TCR_PASS` controls whether traceroutes are accepted. `TCR_PORTS` defines the UDP port range used for detection.

**Kernel Tuning** - APF applies kernel-level network hardening via sysctl when the firewall starts. These settings are controlled by the `SYSCTL_*` variables in `conf.apf`:

| Variable | Purpose |
|----------|---------|
| `SYSCTL_CONNTRACK` | Connection tracking table size (default 131072) |
| `SYSCTL_CONNTRACK_ADAPTIVE` | Auto-scale conntrack_max at 80% usage |
| `SYSCTL_TCP` | TCP performance/security tweaks (timestamps, SACK) |
| `SYSCTL_TCP_NOSACK` | Disable TCP SACK (CVE-2019 mitigations) |
| `SYSCTL_SYN` | Syn-flood mitigation (backlog, retry, timeout) |
| `SYSCTL_ROUTE` | Spoofing/redirect protection (rp_filter, etc.) |
| `SYSCTL_LOGMARTIANS` | Log impossible source addresses |
| `SYSCTL_ECN` | Explicit Congestion Notification |
| `SYSCTL_SYNCOOKIES` | SYN cookie flood protection |
| `SYSCTL_OVERFLOW` | Overflow control |

See `conf.apf` for detailed descriptions of each setting and their sub-options.

### 3.4 Reactive Address Blocking

The Reactive Address Blocking (RAB) system provides in-line intrusion prevention by automatically blocking addresses that trigger sanity violations or port scan detection. RAB is configured through the `RAB_*` variables in `conf.apf`.

**`RAB`** - Top level toggle for the reactive address blocking system.

**`RAB_SANITY`** - Enables RAB for sanity violations (address spoofing, packet flag modification). Offending addresses are temporarily banned for the `RAB_TIMER` duration.

**`RAB_PSCAN_LEVEL`** - Enables RAB for port scan violations. Values: `0` (disabled), `1` (low), `2` (medium), `3` (high security).

**`RAB_HITCOUNT`** - Number of violation hits before an address is blocked. Keep very low to prevent evasive measures. Default is 0 or 1 (instant block).

**`RAB_TIMER`** - Block duration in seconds (default: 300s / 5 minutes). Maximum: 43200 seconds (12 hours).

**`RAB_TRIP`** - Resets the block timer to 0 if a blocked address attempts ANY subsequent communication. This cuts off attacks at the legs before they mount into something tangible.

**`RAB_LOG_HIT`** - Log all violation hits. Recommended for insightful log data on probing attempts. `LOG_DROP=1` overrides this to force logging.

**`RAB_LOG_TRIP`** - Log all subsequent traffic from blocked addresses. Can generate a lot of logs but provides valuable information about attacker intent. `LOG_DROP=1` overrides this to force logging.

### 3.5 Virtual Network Files

When `SET_VNET=1`, APF generates per-IP policy files under the `vnet/` directory for each aliased address on the `IFACE_UNTRUSTED` interface. Each file (e.g., `vnet/192.168.1.100.rules`) can override the global port filtering variables (`IG_TCP_CPORTS`, `EG_TCP_CPORTS`, etc.) for that specific IP address. This allows fine-grained control over which ports are open on each address. Run `apf -s` after editing VNET files to apply changes. Note that the VNET subsystem operates on IPv4 addresses only.

### 3.6 Global Variables & Custom Rules

All variables defined in `conf.apf` are available for use in VNET per-IP rule files, allowing you to import global settings and selectively override them. For custom iptables rules beyond what `conf.apf` provides, you can add rules directly to the `preroute.rules` file which is loaded early in the firewall chain. Any valid iptables syntax can be used in these files, as they are sourced directly into the firewall's bash execution environment.

### 3.7 Hook Scripts

APF supports custom pre- and post-configuration hook scripts that are sourced during firewall startup:

- **`hook_pre.sh`** — sourced after flush/module init but before any iptables rules. Use for custom chains, NAT rules, or early ACCEPT/DROP overrides.
- **`hook_post.sh`** — sourced after all rules including default DROP policies. Use for Docker chain restoration, custom logging, or rules that must be applied last.

Both scripts ship as permission 640 (inactive). To activate, make executable: `chmod 750 /etc/apf/hook_pre.sh`. All APF variables and helpers (`ipt`/`ipt4`/`ipt6`, `eout`, etc.) are available. Scripts are preserved across upgrades via `importconf`.

### 3.8 Silent IP Blocking

The `silent_ips.rules` file lists server IP addresses that should receive no traffic at all. Traffic to and from these addresses is silently dropped (no logging) in both INPUT and OUTPUT chains. One IP or CIDR per line, `#` comments supported, both IPv4 and IPv6.

Positioned after loopback and trusted interface acceptance — loopback and trusted interfaces still work. All other traffic is blocked before trust chains, block lists, or port filtering. An empty or comment-only file is a no-op. Preserved across upgrades via `importconf`.

### 3.9 Docker/Container Compatibility

When running APF alongside Docker, Podman, Kubernetes, or other container runtimes, the default flush behavior (which wipes all iptables rules and chains) will destroy the container runtime's networking rules. The `DOCKER_COMPAT` option solves this by switching APF to a surgical flush mode.

**`DOCKER_COMPAT`** - When set to `"1"`, APF's flush operation only removes APF-owned chains from the filter table, leaving all external chains intact. Specifically:

- FORWARD chain policy and rules are preserved (Docker routing)
- nat table is left untouched (Docker port mapping and MASQUERADE rules)
- raw table is left untouched
- External INPUT and OUTPUT rules (non-APF) are saved before flush and restored afterward, protecting rules from Docker Swarm, kube-proxy, Calico CNI, and similar tools
- DOCKER, DOCKER-USER, DOCKER-ISOLATION, and container-runtime chains in all tables are preserved
- mangle PREROUTING/POSTROUTING are still flushed (APF-managed)

When `DOCKER_COMPAT` is enabled, `SET_FASTLOAD` is automatically disabled because iptables-restore would overwrite the external chains that `DOCKER_COMPAT` is designed to protect. Snapshot saving is also skipped in compat mode.

Enable this option if you see Docker containers losing network connectivity after running `apf -s` or `apf -r`.

### 3.10 ipset Block Lists

The ipset subsystem uses kernel-level hash tables for high-performance IP matching. Instead of creating one iptables rule per blocked IP address (which scales linearly), ipset creates a single iptables rule per block list that references a kernel hash set, providing O(1) lookup performance regardless of list size.

**`USE_IPSET`** - Set to `"1"` to enable ipset block list support. Requires the `ipset` utility to be installed (`apt-get install ipset` / `yum install ipset`). When disabled or ipset is not installed, the `ipset.rules` file is ignored.

**`IPSET_LOG_RATE`** - Default log rate limit (per minute) for ipset blocklist matches. Individual lists can control their own logging via the log field in `ipset.rules`.

**`IPSET_REFRESH`** - Default refresh interval (seconds) for ipset lists during `--ipset-update`. Lists with `interval=0` in `ipset.rules` use this value. Default: `21600` (6 hours). Minimum effective interval is 1 hour since the cron runs hourly.

The block lists are defined in the `ipset.rules` file. Each line defines a set with the format:

```
name:flow:ipset_type:log:interval:maxelem:file_or_url
```

Where:
- `name` - unique list name (used for ipset set and iptables chain naming)
- `flow` - `src` or `dst` (match source or destination address)
- `ipset_type` - `ip` or `net` (`hash:ip` for single addresses, `hash:net` for CIDR blocks)
- `log` - `0` or `1` (per-list logging, rate governed by `IPSET_LOG_RATE`)
- `interval` - refresh interval in seconds for `--ipset-update` (`0` = use `IPSET_REFRESH`; minimum effective is 1 hour)
- `maxelem` - max entries to load (`0` = unlimited, capped at 1048576)
- `file_or_url` - local file path or URL (`https://` for remote download)

Example:
```
firehol_level2:src:net:1:0:0:https://iplists.firehol.org/files/firehol_level2.netset
```

Run `apf --ipset-update` to hot-reload all ipset block lists without restarting the firewall. A cron job (`cron.d/apf`) runs hourly; actual refresh timing is governed by per-list intervals and `IPSET_REFRESH`.

### 3.11 Country Code Filtering (GeoIP)

APF supports GeoIP-based country blocking using ipset hash tables. Countries are specified using ISO 3166-1 alpha-2 codes (e.g., `CN`, `RU`, `US`) or continent shorthand (`@EU`, `@AS`, `@NA`, `@SA`, `@AF`, `@OC`). Requires ipset (`USE_IPSET="auto"` or `"1"`).

Country IP data is downloaded from public registries (ipverse.net, ipdeny.com) and cached locally in the `geoip/` directory. Data refreshes automatically per `CC_INTERVAL` (default: 7 days).

**Quick start:**
```bash
# Block all traffic from China
apf -d CN

# Block all traffic from Europe
apf -d @EU

# Allow only US traffic (all others blocked)
apf -a US

# Block inbound SSH from Russia
apf -d "tcp:in:d=22:s=RU"

# Temporary deny for 7 days
apf -td CN 7d "suspicious activity"

# View status
apf --cc

# Manual data refresh
apf --cc-update

# Remove a country block
apf -u CN
```

| Variable | Default | Description |
|----------|---------|-------------|
| `CC_LOG` | `1` | Log country-blocked packets (requires `LOG_DROP="1"`) |
| `CC_LOG_ONLY` | `0` | Audit mode: LOG without DROP (measure impact first) |
| `CC_SRC` | `auto` | Data source: `auto`, `ipverse`, `ipdeny` |
| `CC_INTERVAL` | `7` | Days between auto-refresh (0 to disable) |
| `CC_IPV6` | `1` | Include IPv6 country blocks when `USE_IPV6="1"` |

Rules files: `cc_deny.rules` (block countries) and `cc_allow.rules` (permit-only mode). Advanced syntax supports per-port/protocol rules. Wildcard `*` in advanced entries expands to all simple CCs in the same file.

### 3.12 GRE Tunnels

APF can manage GRE (Generic Routing Encapsulation) point-to-point tunnels with dedicated firewall chains and protocol 47 rules. This is useful for servers that need encapsulated point-to-point links to remote endpoints.

**`USE_GRE`** - Set to `"1"` to enable GRE tunnel management. Requires the `ip` utility (iproute2 package). When disabled, `gre.rules` is ignored.

**`GRE_PERSIST`** - When set to `"1"`, tunnel interfaces are kept alive when the firewall is flushed or stopped. Only firewall rules are removed. When set to `"0"`, tunnel interfaces are also torn down on flush. Default is `"1"`.

**`GRE_KEEPALIVE`** - Keepalive interval (seconds) and retry count before declaring a tunnel dead. Format: `"interval retries"` (e.g., `"10 3"`). Set to `"0 0"` to disable. Requires kernel >= 3.x.

**`GRE_MTU`** - Tunnel MTU. Leave empty for auto-calculation (parent interface MTU minus 24 bytes GRE overhead). Set explicitly for double-encapsulation scenarios (e.g., `"1400"`).

**`GRE_TTL`** - IP TTL for GRE tunnel packets. Default is `"255"`.

Tunnels are defined in the `gre.rules` file, which is a bash script sourced during firewall startup. Each tunnel is created by setting a role variable and calling the `create_gretun` function:

```bash
role="source"  # or "target"
create_gretun LINKID LOCAL_IP REMOTE_IP [IPFILE]
```

Where `LINKID` is a tunnel ID (1-99, interface = `gre${LINKID}`), `LOCAL_IP` is this host's public IP, `REMOTE_IP` is the remote endpoint, and `IPFILE` is an optional file of IPs to route through the tunnel (one per line). Addresses are auto-assigned: source=`192.168.${LINKID}.1`, target=`192.168.${LINKID}.2`.

Per-tunnel overrides can be set before each `create_gretun` call:
- `gre_keepalive="10 3"` - override `GRE_KEEPALIVE`
- `gre_mtu="1400"` - override `GRE_MTU`
- `gre_ttl="128"` - override `GRE_TTL`
- `gre_key="12345"` - GRE key for tunnel identification

See the `gre.rules` file header for complete examples.

When tunnels are created, APF automatically:
- Creates GRE_IN and GRE_OUT chains for tunnel traffic
- Adds protocol 47 (GRE) ACCEPT rules for each tunnel endpoint
- Creates per-tunnel interface ACCEPT rules in INPUT and OUTPUT
- Configures MTU, keepalive, and IP addresses as specified

CLI commands:

```bash
apf --gre-up       # bring up all tunnels defined in gre.rules
apf --gre-down     # tear down all tunnels and remove firewall rules
apf --gre-status   # show current tunnel interface status
```

### 3.13 Remote Block Lists

APF can automatically download and apply IP block lists from external sources. Each list is loaded into a dedicated iptables chain on full firewall start. The following `DLIST_*` variables in `conf.apf` control these lists:

| Variable | Description |
|----------|-------------|
| `DLIST_PHP` | Project Honey Pot harvester/spammer IPs |
| `DLIST_SPAMHAUS` | Spamhaus DROP list (stolen/zombie netblocks) |
| `DLIST_DSHIELD` | DShield top suspicious hosts |
| `DLIST_RESERVED` | IANA reserved/unassigned networks |
| `DLIST_ECNSHAME` | ECN broken hosts (requires `SYSCTL_ECN="1"`) |

Each has a companion `_URL` variable (e.g., `DLIST_PHP_URL`) for the download source. Set the toggle to `"1"` to enable a list. Lists are validated during parsing and backed up before each download. Failed downloads restore from backup to prevent data loss. Note that `DLIST_RESERVED` interacts with `BLK_RESNET` — when both are enabled, the downloaded reserved.networks list supplements the built-in private.networks blocking.

### 3.14 Logging & Control

APF provides configurable logging of filtered packets through the `LOG_*` variables in `conf.apf`:

| Variable | Purpose |
|----------|---------|
| `LOG_DROP` | Master toggle for firewall packet logging |
| `LOG_LEVEL` | Syslog level for log entries (default: `crit`) |
| `LOG_TARGET` | `LOG` (kernel syslog), `NFLOG` (ulogd2/nfnetlink), or `ULOG` (deprecated) |
| `LOG_IA` | Log interactive access (SSH/Telnet, requires `LOG_DROP="1"`) |
| `LOG_LGATE` | Log foreign gateway traffic |
| `LOG_EXT` | Extended logging (TCP/IP options in output) |
| `LOG_RATE` | Max logged events per minute (default: 30) |
| `LOG_APF` | Path to APF status log (default: `/var/log/apf_log`) |

For iptables concurrency control, `IPT_LOCK_SUPPORT` and `IPT_LOCK_TIMEOUT` configure the `-w` lock flag behavior for iptables >= 1.4.20. This prevents concurrent iptables modifications from corrupting rule state.

### 3.15 Implicit Blocking

The `BLK_*` variables in `conf.apf` control implicit blocking of specific traffic patterns without explicit port rules. These apply globally to all interfaces:

| Variable | Purpose |
|----------|---------|
| `BLK_P2P_PORTS` | Block common P2P protocol ports (e.g., BitTorrent, Kazaa, eDonkey) |
| `BLK_PORTS` | Silently drop common attack ports (NetBIOS, RPC, etc.) without logging |
| `BLK_MCATNET` | Block multicast traffic (`224.0.0.0/4`, `ff00::/8`) |
| `BLK_PRVNET` | Block private IPv4 address space (`10/8`, `172.16/12`, `192.168/16`, etc.) on untrusted interfaces |
| `BLK_RESNET` | Block reserved/unassigned IPv4 space |
| `BLK_TCP_SACK_PANIC` | Block low-MSS TCP SACK exploit packets (CVE-2019-11477) |
| `BLK_IDENT` | REJECT ident (TCP 113) requests instead of silently dropping; some services stall without ident response |

### 3.16 Firewall Order of Operations

When APF starts (`apf -s`), rules are loaded in a specific order that determines how packets are evaluated. Understanding this order is essential for troubleshooting and for knowing which features take precedence.

**INPUT chain evaluation order** (first match wins):

| # | Rule | Action |
|---|------|--------|
| 1 | TCP SACK Panic (MSS 1-500) | DROP |
| 2 | Loopback interface | ACCEPT |
| 3 | Trusted interfaces (`IFACE_TRUSTED`) | ACCEPT |
| 4 | Silent IPs (`silent_ips.rules`) | DROP |
| 5 | GRE tunnel chains | per-tunnel |
| 6 | TALLOW (local allow list) | ACCEPT |
| 7 | TGALLOW (global allow list) | ACCEPT |
| 8 | TDENY (local deny list) | DROP |
| 9 | TGDENY (global deny list) | DROP |
| 10 | Remote block lists (PHP, DShield, Spamhaus) | DROP |
| 11 | ipset block lists | DROP |
| 12 | Common drop ports (`BLK_PORTS`) | DROP |
| 13 | Packet sanity checks | DROP |
| 14 | SYN flood rate limiting (SYNFLOOD) | RETURN/DROP |
| 15 | IDENT / Multicast / P2P blocking | REJECT/DROP |
| 16 | RAB trip and portscan rules | DROP |
| 17 | State tracking (ESTABLISHED,RELATED) | ACCEPT |
| 18 | VNET per-IP port rules | ACCEPT |
| 19 | Connlimit (per-port connection limits) | REJECT |
| 20 | Inbound TCP/UDP port ACCEPT | ACCEPT |
| 21 | ICMP / ICMPv6 / NDP | ACCEPT |
| 22 | Non-SYN NEW tcp DROP | DROP |
| 23 | DNS, FTP, SSH, Traceroute helpers | ACCEPT |
| 24 | Log (rate-limited) | LOG |
| 25 | Default DROP (tcp, udp, all) | DROP |

**Key precedence rules:**
- Trusted interfaces bypass all filtering
- Silent IPs are dropped immediately after trusted interfaces, before all other filtering
- Allow lists are evaluated before deny lists
- Block lists, sanity checks, and RAB are evaluated before state tracking
- State tracking fast-paths established connections; deny lists and blocklists still block
- Connlimit REJECT runs before port ACCEPT
- VNET per-IP rules override global port configuration
- Hook scripts (`hook_pre.sh` / `hook_post.sh`) run outside the normal chain; pre-hook before any rules, post-hook after default policies

For the complete step-by-step initialization flow — including source file references, each chain's creation point, and the full OUTPUT chain evaluation order — see [FLOW.md](FLOW.md) (also installed as `/etc/apf/doc/FLOW`).

---

## 4. General Usage

The `/usr/local/sbin/apf` command has a number of options that will ease the day-to-day use of your firewall:

```
usage: apf [OPTION]

Firewall Control:
  -s, --start ................. load all firewall rules
  -r, --restart ............... flush & reload all firewall rules
  -f, --stop, --flush ......... flush all firewall rules
  --rules ..................... dump active rules to stdout
  -l, --list .................. view all firewall rules in editor
  --info ...................... show firewall status summary
  -t, --status ................ page through full status log
  -e, --refresh ............... refresh & re-resolve DNS in trust rules

Trust Management:
  -a HOST [CMT], --allow ...... add host to allow list and load rule
  -d HOST [CMT], --deny ....... add host to deny list and load rule
  -u HOST, --remove ........... remove host from all trust files
  --list-allow ................ display allow list entries
  --list-deny ................. display deny list entries
  --lookup HOST ............... check if host exists in trust system

  Advanced trust syntax:  apf -a "tcp:in:d=22:s=10.0.0.0/8"
                          apf -d "d=3306:s=192.168.1.5"

Temporary Trust:
  -ta HOST TTL [CMT] .......... temporarily allow host (5m, 1h, 7d)
  -td HOST TTL [CMT] .......... temporarily deny host
  --temp-list ................. list temp entries with remaining TTL
  --temp-flush ................ remove all temporary entries

Diagnostics:
  -g PATTERN, --search ........ search iptables/ipset rules & trust files
  --validate, --check ......... validate config without starting firewall
  -o, --dump-config ........... output all configuration variables
  -v, --version ............... output version number
  -h, --help .................. show this help message

Subsystems:
  --ipset-update .............. hot-reload ipset block lists
  --gre-up .................... bring up GRE tunnels
  --gre-down .................. tear down GRE tunnels
  --gre-status ................ show GRE tunnel status
```

The **`--rules`** option dumps all active iptables rules to stdout in `iptables -S` format, suitable for piping (e.g., `apf --rules | grep DROP`). The **`-l|--list`** option opens rules in an editor for browsing.

The **`--info`** option shows a firewall status summary organized into sections: status (active state, rule/chain counts), trust system (allow/deny/temp entry counts, ban expiry, block escalation, FQDN resolution), filtering (stop targets, port lists, packet sanity, connlimit, SYN flood, SMTP blocking), subsystems (fast load, RAB, VNET, Docker compat, ipset, GRE, remote lists), and logging (log file, log drops, recent entries). The **`-t|--status`** option pages through the full APF status log at `/var/log/apf_log`.

The **`-e|--refresh`** option flushes trust chains and reloads them from rule files, re-resolving any DNS names. Useful for dynamic DNS entries in the trust system.

The **`-a|--allow`** and **`-d|--deny`** options add entries to the trust system immediately without a firewall restart. Both accept an optional comment string. The **`-u|--remove`** option removes an address from all trust files. See [section 4.1](#41-trust-system) for details.

The **`--lookup`** option checks whether a host exists in any trust file (allow, deny, global allow, global deny) without searching iptables rules. Exits 0 if found, 1 if not — useful in scripts: `apf --lookup 192.168.1.50 && echo "found"`

The **`-g|--search`** option searches all iptables rules (IPv4 + IPv6), ipset sets, and trust files for a pattern match. Case-insensitive, with line-numbered output. Useful for quickly finding which rules or trust entries match a given IP, port, or chain name. Examples:

```bash
apf -g 192.168.1.50
apf -g DROP
apf -g :443
```

The **`--dump-config`** option outputs all configured variables and their values — useful for troubleshooting or when reporting problems (see [section 6](#6-support-information)).

The **`--validate|--check`** option validates the configuration without starting the firewall. Useful for verifying changes before a restart.

The **`--list-allow`** and **`--list-deny`** options display the contents of the allow and deny trust files (comments and blank lines excluded).

### 4.1 Trust System

The trust system in APF is a very traditional setup with two basic trust levels: allow and deny. These two basic trust levels are also extended with two global trust levels that can be imported from a remote server to assist with central trust management in a large scale deployment.

The two basic trust level files are located at:

- `/etc/apf/allow_hosts.rules`
- `/etc/apf/deny_hosts.rules`

These files by nature are static, meaning that once you add an entry to them, they will remain in the files till you remove them yourself. The trust files accept FQDN (fully qualified domain names), IPv4 addresses, and IPv6 addresses with optional bit masking. FQDNs are pre-resolved to IP addresses via `getent` before loading into iptables. When `USE_IPV6=1`, both A and AAAA records are used. Resolved addresses are stored as metadata in trust file comments for efficient removal. The resolution timeout is controlled by `FQDN_TIMEOUT` (default 10 seconds) in `conf.apf`. On refresh (`apf -e`), FQDNs are re-resolved to pick up DNS changes. Examples:

```
yourhost.you.com        (FQDN — resolved to IP before loading)
192.168.2.102           (IPv4 Address)
192.168.1.0/24          (IPv4 Address with 24 bit mask)
2001:db8::1             (IPv6 Address)
2001:db8::/32           (IPv6 Address with prefix length)
```

Common bit masks:
- `/24` (192.168.1.0 to 192.168.1.255)
- `/16` (192.168.0.0 to 192.168.255.255)

There are two methods for adding entries to the trust files. The first is by editing the files manually with an editor. The second is by using the `apf` command:

```bash
# Trust an address
apf -a myhost.example.com "my home dynamic-ip"

# Deny an address
apf -d 192.168.3.111 "keeps trying to bruteforce"

# Remove an address
apf -u myhost.example.com

# Advanced trust syntax (see section 4.3 for full format)
apf -a "tcp:in:d=22:s=10.0.0.0/8"       # allow inbound TCP 22 from subnet
apf -d "d=3306:s=203.0.113.50"           # deny port 3306 (tcp+udp) from host
apf -u "tcp:in:d=22:s=10.0.0.0/8"       # remove advanced trust entry
```

The `--remove|-u` option does not accept a comment string and will remove entries that match from allow_hosts.rules, deny_hosts.rules and the global extensions of these files. When removing a bare IP, any advanced trust entries containing that IP are also removed.

The trust system has several operational controls in `conf.apf`:

| Variable | Purpose |
|----------|---------|
| `SET_EXPIRE` | Auto-expire deny entries after N seconds (`0` to disable). Use `"static"` or `"noexpire"` in a ban comment to exempt it. |
| `SET_REFRESH` | Refresh interval in minutes for trust rules and DNS re-resolution (default: 10) |
| `SET_REFRESH_MD5` | Skip refresh if trust files are unchanged (`1` to enable) |
| `FQDN_TIMEOUT` | Timeout in seconds for FQDN resolution in trust rules (default: 10) |
| `SET_TRIM` | Max deny entries before oldest are purged (default: 250) |

For temporary trust entries with per-entry TTL, see [section 4.4](#44-temporary-trust-entries).

### 4.2 Global Trust System

The global trust system extends the local trust files with centrally managed allow and deny lists that can be downloaded from a remote server. The files `glob_allow.rules` and `glob_deny.rules` are populated by setting the `GA_URL` and `GD_URL` variables in `conf.apf` to the URLs of your remote trust lists. Set `USE_RGT="1"` in `conf.apf` to enable automatic downloading of global trust files. APF will periodically download these lists and load them into the TGALLOW and TGDENY chains. This is useful for organizations managing multiple servers that need to share a common set of trusted or blocked addresses. The `--remove` (`-u`) option will also remove entries from the global trust files.

### 4.3 Advanced Trust Syntax

The trust rules can be made in advanced format with 4 options (`proto:flow:port:ip`):

1. **protocol** - packet protocol tcp/udp
2. **flow in/out** - packet direction, inbound or outbound
3. **s/d=port** - packet source or destination port
4. **s/d=ip(/xx)** - packet source or destination address, masking supported

When protocol is omitted, rules are created for both TCP and UDP. When flow is omitted, rules apply to both inbound and outbound traffic. When defining rules with protocol, flow is required.

**Syntax:**
```
proto:flow:[s/d]=port:[s/d]=ip(/mask)
s - source, d - destination, flow - packet flow in/out
```

**Examples:**

```bash
# inbound to destination port 22 from 198.51.100.11
tcp:in:d=22:s=198.51.100.11

# outbound to destination port 23 to destination host 198.51.100.9
out:d=23:d=198.51.100.9

# inbound to destination port 3306 from 198.51.100.0/24
d=3306:s=198.51.100.0/24
```

**IPv6 addresses** use bracket notation to protect colons from the field delimiter parser:

```bash
# inbound to destination port 22 from IPv6 address 2001:db8::1
d=22:s=[2001:db8::1]

# inbound to destination port 443 from IPv6 network 2001:db8::/32
tcp:in:d=443:s=[2001:db8::/32]
```

Plain (non-advanced) IPv6 addresses can be added directly without brackets:
```
2001:db8::1
```

### 4.4 Temporary Trust Entries

In addition to permanent trust entries, APF supports temporary allow/deny with per-entry TTL (time-to-live). Temporary entries are stored in the same trust files with `ttl=` and `expire=` metadata markers and are automatically removed when their TTL expires.

**TTL formats:**

| Format | Example | Meaning |
|--------|---------|---------|
| Bare seconds | `300` | 5 minutes |
| Seconds suffix | `300s` | 5 minutes |
| Minutes | `5m` | 5 minutes |
| Hours | `1h` | 1 hour |
| Days | `7d` | 7 days |

**Usage:**

```bash
# Temporarily allow a host for 1 hour
apf -ta 10.0.0.5 1h "temp maintenance access"

# Temporarily deny a host for 7 days
apf -td 192.168.3.111 7d "temp block"

# Advanced syntax with TTL
apf -ta "tcp:in:d=443:s=192.168.1.100" 1h "temp HTTPS access"
apf -td "d=80:s=203.0.113.50" 24h "temp block port 80"

# List all temporary entries with remaining TTL
apf --templ

# Flush all temporary entries immediately
apf --tempf

# Remove a temporary entry manually (same as permanent entries)
apf -u 10.0.0.5
```

Expiry is handled automatically by a cron job that runs every minute (`/etc/cron.d/apf`). Temporary entries use their own per-entry TTL and are not affected by the global `SET_EXPIRE` timer. To reset a temp entry's timer, remove it first (`apf -u HOST`) then re-add it with a new TTL.

**Block Escalation:**

When the same IP address is repeatedly temp-denied, APF can automatically promote it to a permanent deny entry. This is controlled by two variables in `conf.apf`:

| Variable | Purpose |
|----------|---------|
| `PERMBLOCK_COUNT` | Number of temp denies within `PERMBLOCK_INTERVAL` before auto-promoting to permanent (default: `0`, disabled) |
| `PERMBLOCK_INTERVAL` | Time window in seconds for counting repeat temp denies (default: `86400`, 24 hours) |

For example, setting `PERMBLOCK_COUNT="3"` and `PERMBLOCK_INTERVAL="86400"` will permanently block any IP that is temp-denied 3 or more times within 24 hours. Escalated entries are added to `deny_hosts.rules` with a `"noexpire"` marker so they are not affected by `SET_EXPIRE`.

### 4.5 Troubleshooting

**Locked out of the server?** `DEVEL_MODE="1"` (the default) auto-flushes the firewall every 5 minutes. If DEVEL_MODE is off, rebooting will clear rules unless boot loading is configured (see [section 2.1](#21-boot-loading)).

**Docker containers lost network after `apf -s`?** Set `DOCKER_COMPAT="1"` in `conf.apf` to preserve container networking rules during firewall operations. See [section 3.9](#39-dockercontainer-compatibility).

**Firewall rules gone after reboot?** Ensure boot loading is configured — systemd service, chkconfig, or rc.local entry. See [section 2.1](#21-boot-loading).

**ipset block lists not loading?** Install the ipset package (`apt-get install ipset` / `yum install ipset`), set `USE_IPSET="1"` in `conf.apf`, and verify with `apf -o | grep IPSET`.

**How to see what is blocked?** Use `apf -g IP` to search iptables rules and trust files, or `apf --rules | grep IP` to search loaded rules directly.

**How to check if APF is running?** Run `apf -t` to view the status log, or `iptables -S | head` to check for loaded rules.

---

## 5. License

APF is developed and supported on a volunteer basis by Ryan MacDonald [ryan@rfxn.com].

APF (Advanced Policy Firewall) is distributed under the GNU General Public License (GPL) without restrictions on usage or redistribution. The APF copyright statement, and GNU GPL, "COPYING.GPL" are included in the top-level directory of the distribution. Credit must be given for derivative works as required under GNU GPL.

---

## 6. Support Information

The APF source repository is at: https://github.com/rfxn/advanced-policy-firewall

Bugs, feature requests, and general questions can be filed as GitHub issues or sent to proj@rfxn.com. When reporting issues, include the output of `apf --dump-config` to help diagnose configuration problems. For a complete CLI and configuration reference, run `man apf`.

The official project page is at: https://www.rfxn.com/projects/advanced-policy-firewall/
