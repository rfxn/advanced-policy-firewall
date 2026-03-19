# APF Library Decomposition — Design Spec

> **Date:** 2026-03-18
> **Project:** APF (Advanced Policy Firewall)
> **Branch:** `2.0.2`
> **Scope:** Decompose `functions.apf` (3,291 lines) and absorb `firewall` (386 lines) into functionally-organized sub-libraries

---

## Problem Statement

`functions.apf` is a 3,291-line monolith containing 110 functions across ~15 functional
domains. The `firewall` script adds another 386 lines of procedural orchestration with
one local function. This makes the codebase difficult to navigate, review, and maintain.

Two domain libraries have already been successfully extracted (`geoip.apf` at 1,469
lines/25 functions, `ctlimit.apf` at 356 lines/7 functions), establishing the internal
library pattern. This spec extends that pattern to decompose the remaining code, aligning
with BFD's `bfd_*.sh` sub-library convention.

## Goals

1. No file exceeds ~1,000 lines (flexible ceiling when functional coherence demands it)
2. `files/apf` becomes a thin CLI wrapper (args + case dispatch only)
3. All critical functionality lives in sub-libraries under `files/internals/`
4. Function signatures and behavior are unchanged — internal reorganization only
5. Remove identified dead variables (~3 findings)
6. All 672 tests pass without modification
7. Naming convention aligns with BFD: `apf_*.sh` extension, `apf.lib.sh` hub

## Non-Goals

- Refactoring function internals or changing APIs
- Adding new features or capabilities
- Modifying test files (unless they reference old filenames)
- Changing the CLI interface
- Modifying upstream shared libraries (`elog_lib.sh`, `pkg_lib.sh`, `geoip_lib.sh`)

---

## Architecture

### File Map

```
files/apf                        (~200 lines)  CLI wrapper: args + case dispatch
files/internals/
  apf.lib.sh                     (~150 lines)  Sourcing hub + shared utilities
  apf_ipt.sh                     (~250 lines)  iptables helpers + module loading
  apf_validate.sh                (~400 lines)  Input + config validation
  apf_trust.sh                   (~900 lines)  Trust system + block escalation + temp expiry
  apf_ipset.sh                   (~250 lines)  ipset management
  apf_dlist.sh                   (~250 lines)  Remote deny lists + download
  apf_core.sh                    (~800 lines)  Lifecycle (start/full-load/flush/deps/mutex/cron/rules/info)
  apf_cli.sh                     (~150 lines)  CLI display/search (help, list, search, status, ovars)
  apf_geoip.sh                 (~1470 lines)   GeoIP country blocking (renamed from geoip.apf)
  apf_ctlimit.sh                (~360 lines)   Connection tracking limits (renamed from ctlimit.apf)
```

**Deleted:** `files/firewall` (absorbed into `apf_core.sh` as `firewall_full_load()`)

**Renamed:** `functions.apf` -> `apf.lib.sh`, `geoip.apf` -> `apf_geoip.sh`,
`ctlimit.apf` -> `apf_ctlimit.sh`

### Size Comparison

| Metric | Before | After |
|--------|--------|-------|
| Files | 5 (apf, firewall, functions.apf, geoip.apf, ctlimit.apf) | 11 (apf + 10 sub-libraries) |
| Total lines | ~5,910 | ~5,880 |
| Largest file | 3,291 (functions.apf) | ~1,470 (apf_geoip.sh, already extracted) |
| Largest new file | -- | ~900 (apf_trust.sh) |
| Net reduction | -- | ~30 lines (dead var cleanup + redundant conf.apf source) |

### Sourcing Order

`apf` sources `conf.apf`, which sources `internals.conf`, which sources `apf.lib.sh`.
`apf.lib.sh` sources all sub-libraries in dependency order:

```
files/apf
 +-- source conf.apf
      +-- CNFINT -> internals/internals.conf
           +-- rab.ports
           +-- apf.lib.sh (hub)
           |    +-- geoip_lib.sh          (upstream -- geolocation primitives)
           |    +-- elog_lib.sh            (upstream -- structured logging)
           |    +-- apf_ipt.sh            (no APF deps)
           |    +-- apf_validate.sh       (no APF deps)
           |    +-- apf_trust.sh          (depends: ipt, validate)
           |    +-- apf_ipset.sh          (depends: ipt, validate)
           |    +-- apf_dlist.sh          (depends: validate, ipset)
           |    +-- apf_cli.sh            (depends: trust, ipt, validate)
           |    +-- apf_core.sh           (depends: all above)
           +-- gretunnel.sh              (upstream -- GRE tunnels)
```

Lazily sourced on demand (unchanged from current behavior):

```
apf_core.sh (firewall_full_load / ct_enabled check) -> apf_ctlimit.sh
apf_core.sh (firewall_full_load / cc_enabled check) -> apf_geoip.sh
apf case dispatcher (--cc/--ct CLI paths)            -> apf_geoip.sh / apf_ctlimit.sh
```

No circular dependencies exist in this order.

### Key Changes from Current Chain

- `internals.conf` sources `apf.lib.sh` instead of `functions.apf` (one-line change)
- `apf.lib.sh` sources sub-libraries in dependency order instead of being a monolith
- `geoip_lib.sh` moves from its current location inside `functions.apf` (L728) to
  `apf.lib.sh`, keeping eager-source semantics. Previously sourced inside the library
  file at load time; now sourced in the hub before the sub-libraries
- `gretunnel.sh` stays sourced from `internals.conf` (independent, not part of decomposition)
- `firewall_full_load()` in `apf_core.sh` replaces `files/firewall` -- sources
  `hook_pre.sh`, `preroute.rules`, `sysctl.rules`, `bt.rules`, `log.rules`,
  `vnet/main.vnet`, `main.rules` (which sources `cports.common`), `postroute.rules`,
  `hook_post.sh` in the same sequence

### Dependency Rules

- Upstream libraries (`geoip_lib`, `elog_lib`, `gretunnel`) are never modified.
  `pkg_lib` is install-time only (sourced by `install.sh` and `importconf`), not
  part of the runtime sourcing chain
- Each sub-library uses the established source guard pattern:
  `[[ -n "${_APF_STEM_LOADED:-}" ]] && return 0 2>/dev/null; _APF_STEM_LOADED=1`
- Each sub-library has a version variable: `APF_STEM_VERSION="1.0.0"`
- Private functions use `_prefix_*` naming scoped to their module
- All sub-libraries resolve paths via `$INSTALL_PATH` and `$_internals_dir`

---

## File Contents

### `files/apf` -- Thin CLI Wrapper (~200 lines)

**Retains:**
- Shebang, header, version/copyright globals
- Source `conf.apf`
- `apf_banner()` -- version header display
- Main `case` dispatcher (all CLI flags -> library function calls)
- `EXIT`/`INT`/`TERM` trap registration

**Moves out:** `start()` -> `apf_core.sh`.

### `apf.lib.sh` -- Sourcing Hub + Shared Utilities (~150 lines)

**Contains:**
- Source guard (`_APF_LIB_LOADED`), version (`APF_LIB_VERSION`)
- `_internals_dir` resolution via `BASH_SOURCE[0]`
- Sources upstream libs (`geoip_lib.sh`, `elog_lib.sh`) then all `apf_*.sh` in
  dependency order (9 files)
- Shared micro-utilities used across 3+ sub-libraries:
  - `eout()` -- logging wrapper
  - `devm()` -- dev mode check
  - `trim()` -- whitespace trim
  - `_apf_reg_tmp()` / `_apf_cleanup_tmp()` / `_apf_cleanup_stale_tmp()` -- temp
    file lifecycle

### `apf_ipt.sh` -- iptables Helpers + Module Loading (~250 lines)

- `detect_ipt_backend()` -- nft vs legacy detection
- `snapshot_save()` -- `iptables-save` / `ip6tables-save` to restore files
- `ipt()` -- dual-stack (IPv4 + IPv6) rule application
- `ipt4()` -- IPv4-only
- `ipt6()` -- IPv6-only (no-op when `USE_IPV6=0`)
- `ipt_dst()` -- VNET-aware dual-stack for inbound
- `ipt_src()` -- VNET-aware dual-stack for outbound
- `ipt_for_host()` -- per-host rule application (IPv4/IPv6 dispatch)
- `ml()` -- single kernel module load with modprobe dry-run + fallback
- `modinit()` -- load all required netfilter modules

**Dependencies:** None. Sourced first among APF modules.

### `apf_validate.sh` -- Input + Config Validation (~400 lines)

- `valid_ip_cidr()` -- IP/CIDR format validation
- `valid_host()` -- IPv4/IPv6/CIDR/FQDN gate
- `is_fqdn()` -- FQDN regex check (requires IPv4 exclusion guard)
- `valid_cc()` -- country code validation (calls `geoip_expand_codes()`)
- `cc_enabled()` -- GeoIP feature predicate
- `ct_enabled()` -- conntrack feature predicate
- `geoip_expand_codes()` -- override of `geoip_lib.sh` version (bridges `_VCC_CODES`)
- `parse_ttl()` -- TTL string -> seconds conversion
- `_sanitize_comment()` -- trust comment sanitization
- `validate_config()` (~155 lines) -- comprehensive config variable validation
- `expand_port()` -- port range expansion

**Dependencies:** `geoip_lib.sh` (for `_GEOIP_VCC_*` variables read by `valid_cc()`).

### `apf_trust.sh` -- Trust System + Block Escalation + Temp Expiry (~900 lines)

**Trust parsing and rule generation:**
- `trust_protect_ipv6()` / `trust_restore_ipv6()` -- IPv6 bracket escaping
- `trust_parse_fields()` -- advanced trust syntax field splitting
- `_trust_unpack_fields()` -- structured field extraction
- `valid_trust_entry()` -- trust entry format validation
- `trust_entry_rule()` -- trust entry -> iptables rule generation

**Trust CLI operations:**
- `_resolve_fqdn_metadata()` -- FQDN resolution for trust display
- `_trust_remove_ip_rules()` -- remove live iptables rules for an IP
- `_trust_remove_advanced_entries()` -- remove advanced trust file entries
- `cli_trust_remove()` -- CLI `-u` handler
- `_trust_action_target()` -- determine allow/deny target file
- `_trust_check_duplicate()` -- duplicate entry detection
- `cli_trust()` -- CLI `-a`/`-d` handler
- `cli_trust_temp()` -- CLI `-ta`/`-td` handler

**Block escalation (RAB):**
- `record_block()` -- RAB block recording
- `check_block_escalation()` -- escalation threshold check
- `escalate_to_permanent()` -- temp -> permanent promotion
- `_maybe_block_escalate()` -- escalation orchestrator

**Trust file loading:**
- `load_local_addrs()` -- populate local address list
- `is_local_addr()` -- local address check
- `resolve_fqdn()` -- FQDN -> IP resolution
- `_trust_local_addr_blocked()` -- warn on self-blocking
- `_trust_hosts_advanced()` -- advanced trust syntax loading
- `trust_hosts()` -- main trust file loading (dead params V-002 removed)
- `allow_hosts()` / `deny_hosts()` -- named wrappers

**Temp entry management:**
- `_parse_temp_comment()` -- temp entry metadata extraction
- `expirebans()` -- SET_EXPIRE-based global expiry
- `expire_temp_entries()` -- per-entry TTL expiry
- `list_temp_entries()` -- `--templ` display
- `flush_temp_entries()` -- `--tempf` bulk flush

**Refresh cycle:**
- `refresh()` -- re-resolve FQDNs, re-download globs, rebuild trust chains

**Dependencies:** `apf_ipt.sh` (`ipt`, `ipt4`, `ipt_for_host`),
`apf_validate.sh` (`valid_host`, `valid_ip_cidr`, `is_fqdn`, `parse_ttl`,
`valid_trust_entry`, `_sanitize_comment`).

### `apf_ipset.sh` -- ipset Management (~250 lines)

- `ipset_migrate_rules()` -- convert trust file entries to ipset format
- `ipset_populate_set()` -- bulk-load ipset from data file
- `_ipset_parse_entry()` -- parse trust entry for ipset compatibility
- `_ipset_resolve_data()` -- resolve data source for ipset population
- `ipset_load()` -- create and populate ipset
- `ipset_update_timestamp()` -- update ipset metadata
- `ipset_update()` -- refresh existing ipset
- `ipset_flush()` -- destroy ipset (called from flush path)

**Dependencies:** `apf_ipt.sh` (`ipt4`), `apf_validate.sh` (`valid_ip_cidr`).

### `apf_dlist.sh` -- Remote Deny Lists + Download (~250 lines)

- `download_url()` -- wget/curl wrapper
- `dlist_resnet()` -- reserved network list loading
- `dlist_download()` -- generic deny list download + validation
- `dlist_php()` / `dlist_dshield()` / `dlist_spamhaus()` / `dlist_ecnshame()` --
  specific deny list downloaders
- `dlist_load_hosts()` -- load deny list into iptables chain
- `dlist_php_hosts()` / `dlist_dshield_hosts()` / `dlist_spamhaus_hosts()` /
  `dlist_ecnshame_hosts()` -- specific host loaders
- `glob_trust_download()` -- global trust list download
- `glob_allow_download()` / `glob_deny_download()` -- named wrappers

**Dependencies:** `apf_validate.sh` (`valid_ip_cidr`),
`apf_ipset.sh` (`ipset_load`, `ipset_update`).

### `apf_cli.sh` -- CLI Display/Search (~150 lines)

- `help()` -- usage text
- `list()` -- `apf -l` iptables rule listing
- `rules()` -- `apf -lr` formatted rules display
- `status()` -- `apf -t` status log tail
- `cli_validate()` -- config validation CLI wrapper
- `list_trust_file()` -- trust file content display
- `search()` -- `apf -g` pattern search across rules and trust files
- `ovars()` -- `apf -o` config variable dump
- `trust_lookup()` -- IP lookup across trust files
- `cl_cports()` -- port filter chain listing

**Dependencies:** `apf_trust.sh` (`list_temp_entries`, `trust_lookup`),
`apf_ipt.sh` (`ipt`, `ipt4`), `apf_validate.sh` (`expand_port`).

### `apf_core.sh` -- Lifecycle + Orchestration (~800 lines)

**Startup:**
- `start()` -- fast-load vs full-load dispatch (moved from `files/apf`)
- `firewall_full_load()` -- absorbed from `files/firewall`: `modinit()`, `flush(1)`,
  `hook_pre.sh`, `preroute.rules`, `sysctl.rules`, trust chains, GeoIP, `bt.rules`,
  state tracking, `log.rules`, `vnet/main.vnet`, `main.rules` (-> `cports.common`),
  `postroute.rules`, `hook_post.sh`, save snapshot
- `_verify_iface_route()` -- interface validation (moved from `files/firewall`)
- `firewall_info()` (~150 lines) -- startup info banner (config summary, feature status)

**Dependencies and prerequisites:**
- `check_deps()` -- dependency checking
- `check_rab()` -- RAB prerequisite check

**Flush and teardown:**
- `flush_apf_chains()` -- chain teardown
- `flush()` -- full flush orchestration
- `save_external_baseline()` / `restore_external_baseline()` -- external chain preservation

**Process management:**
- `mutex_lock()` / `mutex_unlock()` -- process locking

**Rule-generation helpers (called by bt.rules/log.rules/cports.common during full load):**
- `_log_drop()` -- iptables LOG + DROP/REJECT rule pair
- `_rab_log()` -- RAB-specific LOG rule
- `pkt_sanity_flags()` -- packet sanity TCP flag check rules
- `tosroute()` -- ToS/DSCP mangle MARK rules (PREROUTING/POSTROUTING)
- `dnet()` -- network block DROP rules (reserved/private/multicast)
- `cdports()` -- common/dynamic port range rules
- `lgate_mac()` -- MAC address gate rules

**Cron handlers:**
- `cron_refresh()` -- cron-driven refresh handler
- `cron_ctlimit()` -- cron-driven conntrack scan handler

**Dependencies:** All above modules. Top-level orchestrator.

### `apf_geoip.sh` (~1,470 lines, renamed from `geoip.apf`)

Unchanged internally -- 25 functions. Filename changes from `geoip.apf` to
`apf_geoip.sh`. Source guard is already `_APF_GEOIP_LOADED` (unchanged).
Add new `APF_GEOIP_VERSION="1.0.0"` per sub-library convention (does not exist
in current file).

### `apf_ctlimit.sh` (~360 lines, renamed from `ctlimit.apf`)

Unchanged internally -- 7 functions. Filename changes from `ctlimit.apf` to
`apf_ctlimit.sh`. Source guard is already `_APF_CTLIMIT_LOADED` (unchanged).
Add new `APF_CTLIMIT_VERSION="1.0.0"` per sub-library convention (does not exist
in current file).

---

## Dead Code Cleanup

Three dead variable findings to address during decomposition:

| ID | Location | Type | Severity | Action |
|---|---|---|---|---|
| V-001 | `trust_entry_rule()` L945 | Dead assignment | High | Remove `_TER_DIR="$dir"` -- zero readers anywhere |
| V-002 | `trust_hosts()` L2257 | Dead parameters | Medium | Remove `action_tcp`, `action_udp` from signature; update `deny_hosts()` to stop passing `$TCP_STOP`/`$UDP_STOP` |
| V-003 | `valid_cc()` L742/746 | Undead API var | Low | Keep `_VCC_TYPE` -- tested API output, trivial cost |

### Notable Non-Dead Items

- `geoip_expand_codes()` is intentionally shadowed: APF version in `apf_validate.sh`
  overrides `geoip_lib.sh` version to bridge `_VCC_CODES`. Sourcing order guarantees
  correct override (hub sources `geoip_lib.sh` before `apf_validate.sh`).
- All 110 functions have callers. No dead functions found.
- Wrapper functions (`allow_hosts`, `deny_hosts`, `ipt4`, `glob_allow_download`, etc.)
  are legitimate named entry points with fixed arguments -- not dead.

---

## Sourced Rule Files (Unchanged)

The following files remain as sourced scripts, not absorbed into libraries. They are
configuration-driven rule templates containing sequential iptables commands, not
callable function units:

- `files/bt.rules` (251 lines) -- blocked traffic, deny lists, packet sanity, RAB
- `files/sysctl.rules` (170 lines) -- kernel tunable application
- `files/main.rules` (8 lines) -- sources `cports.common` for port filtering
- `files/internals/cports.common` (188 lines) -- port filtering rules (sourced via `main.rules`)
- `files/log.rules` (14 lines) -- logging rules
- `files/preroute.rules` (3 lines) -- PREROUTING mangle (ToS routing)
- `files/postroute.rules` (4 lines) -- POSTROUTING mangle (ToS routing)
- `files/vnet/main.vnet` (32 lines) -- VNET per-IP policy loader
- `files/hook_pre.sh` / `files/hook_post.sh` -- user hooks

These are sourced by `firewall_full_load()` in `apf_core.sh` in the same sequence
as the current `files/firewall` script.

---

## Sub-Library Convention

All new sub-libraries follow the pattern established by BFD's `bfd_*.sh` convention:

```bash
#!/bin/bash
# GPL v2 full header
# Copyright (C) 2002-2026, R-fx Networks <proj@rfxn.com>
# Copyright (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# APF <module description>

# Source guard -- replace STEM with file stem in UPPER_CASE
# e.g., apf_ipt.sh -> _APF_IPT_LOADED / APF_IPT_VERSION
[[ -n "${_APF_STEM_LOADED:-}" ]] && return 0 2>/dev/null
_APF_STEM_LOADED=1

# Module version
# shellcheck disable=SC2034
APF_STEM_VERSION="1.0.0"

# Functions...
```

- Private functions: `_prefix_*` naming (e.g., `_trust_unpack_fields`, `_ipset_parse_entry`)
- Public functions: no leading underscore
- Internal state variables: `_PREFIXED_VAR` (underscore prefix)
- Data structures: parallel indexed arrays (bash 4.1 compat, no `declare -A`)
- All paths resolved via variables (`$INSTALL_PATH`, `$_internals_dir`), never hardcoded

---

## Migration Safety

### Test Suite

All 672 tests source the chain via `install-apf.sh` -> `apf -s` or direct `source`
of config/functions. After decomposition, `internals.conf` sources `apf.lib.sh`
which sources all sub-libraries -- the full function set is available at the same
names with the same signatures. **No test modifications needed** unless tests
reference old filenames directly.

Verification: grep all test files for references to `functions.apf`, `geoip.apf`,
`ctlimit.apf`, or `firewall` by filename -- update any matches.

### Install Path

`install.sh` bulk-copies `files/internals/` to the install directory. New `apf_*.sh`
files are automatically included. The `sed -i "s:/etc/apf:$INSTALL_PATH:g"` pass
runs across all files. Verify:
- The sed target list includes the new filenames (or uses a wildcard)
- `files/firewall` removal is reflected (remove from sed list, remove from install copy)
- `internals.conf` sourcing line updated from `functions.apf` to `apf.lib.sh`

### Existing Users (Upgrade Path)

- `functions.apf`, `geoip.apf`, `ctlimit.apf` become orphans in
  `$INSTALL_PATH/internals/` after upgrade -- `install.sh` should clean them up
  (add explicit `rm` for old filenames in pre-install cleanup)
- `files/firewall` becomes orphan in `$INSTALL_PATH/` -- same cleanup needed
- Cron jobs reference firewall indirectly via `apf -r` -- no breakage since the
  CLI entry point is unchanged
- Any user scripts that `source $INSTALL_PATH/internals/functions.apf` directly
  would break -- this is an unsupported use, but document in CHANGELOG

### Backward Compatibility

- All CLI flags unchanged (case dispatcher stays in `files/apf`)
- All config variables unchanged
- All trust file formats unchanged
- All exit codes unchanged
- All cron entries unchanged (`apf -e`, `apf -r` still work)
- `importconf` and `get_ports` in `files/extras/` -- verify they don't reference
  moved filenames

### Uninstall

`uninstall.sh` removes `$INSTALL_PATH/` wholesale -- no changes needed for the
decomposition itself. Verify it doesn't reference `firewall` or `functions.apf`
by name for individual cleanup steps.

---

## Verification

After each phase:

```bash
# Syntax check all sub-libraries + CLI
bash -n files/apf files/internals/apf.lib.sh files/internals/apf_*.sh

# Shellcheck
shellcheck files/apf files/internals/apf.lib.sh files/internals/apf_*.sh

# Standard grep checks per parent CLAUDE.md
grep -rn '$IP6T ' files/ | grep -v IPT_FLAGS
grep -rn '$IP6T.*0/0' files/
grep -rn '\bwhich\b' files/
grep -rn '\begrep\b' files/
grep -rn '`' files/
grep -rn '|| true' files/
grep -rn '2>/dev/null' files/
grep -rn '^\s*cp \|^\s*mv \|^\s*rm ' files/
grep -rn '/usr/bin/\(rm\|mv\|cp\)' files/
grep -rn '\\cp \|\\mv \|\\rm ' files/
grep -rn 'local [a-z_]*=\$(' files/
grep -rn '^\s*cd ' files/

# Verify no references to old filenames remain in source
grep -rn 'functions\.apf' files/ install.sh uninstall.sh
grep -rn 'geoip\.apf' files/ install.sh uninstall.sh
grep -rn 'ctlimit\.apf' files/ install.sh uninstall.sh
grep -rn '/firewall' files/apf install.sh uninstall.sh

# Verify orphan cleanup in install.sh
grep -n 'functions.apf\|geoip.apf\|ctlimit.apf' install.sh
```

Full test suite on Debian 12 + Rocky 9 after final phase. Lint-only between
intermediate phases unless the phase touches core logic.

---

## Risks

1. **Sourcing order sensitivity** -- A function referenced before its defining module
   is sourced will fail at runtime. The dependency chain is acyclic and the sourcing
   order respects it, but each phase must verify with `bash -n` + a basic `apf -s` /
   `apf -f` smoke test.

2. **`geoip_expand_codes()` shadow ordering** -- The APF override in `apf_validate.sh`
   must be sourced AFTER `geoip_lib.sh` to properly shadow it. The sourcing chain
   guarantees this (`geoip_lib.sh` first, then `apf_validate.sh`), but any reordering
   would silently break `valid_cc()`.

3. **`firewall_full_load()` absorption** -- The current `files/firewall` sources
   `conf.apf` independently. When absorbed, this redundant source is removed. Verify
   no variable is re-initialized by that second source that downstream code depends
   on being "fresh."

4. **Rule file sourcing context** -- `bt.rules`, `cports.common`, `log.rules`,
   `sysctl.rules` are sourced inside `firewall_full_load()`. They reference variables
   and functions set earlier in the load. Since the current `files/firewall` already
   sources these from a top-level procedural context (not inside a function), wrapping
   them in a function body changes `local` scoping behavior. However, `files/firewall`
   uses no `local` variables -- all variables are globals set by `conf.apf`. Verify
   with `apf -s` on each target OS.

5. **Orphan file cleanup** -- Users upgrading from 2.0.2 will have `functions.apf`,
   `geoip.apf`, `ctlimit.apf`, and `firewall` as orphans. If `install.sh` doesn't
   clean them, the old files sit inert but confusing. The source guards in old files
   won't conflict (different guard variable names), but explicit cleanup is cleaner.

6. **Test filename references** -- Any test that greps for or references `functions.apf`,
   `geoip.apf`, `ctlimit.apf`, or `firewall` by filename (path checks, install
   verification tests) will need updating.
