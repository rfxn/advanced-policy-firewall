# Granular CC Advanced Trust Entry Removal — Design Spec

**Date:** 2026-03-22
**Version:** 2.0.3
**Status:** Draft
**Tracks:** UAT-003

---

## 1. Problem Statement

When an admin adds multiple CC rules for the same country — e.g., a bare
`ZZ` (block all traffic) and `tcp:in:d=22:s=ZZ` (block SSH specifically) —
removing the advanced entry via `apf -u tcp:in:d=22:s=ZZ` destroys ALL
rules for that country, including the bare entry.

**Root cause:** `cli_trust_remove()` (apf_trust.sh:349) extracts only the
CC code (`ZZ`) from the full advanced entry and delegates to
`cli_cc_remove("ZZ")`, which performs a nuke-all removal: all rules file
entries, all iptables rules across CC_DENY/CC_ALLOW/CC_DENYP/CC_ALLOWP,
all ipsets, and all cached GeoIP data.

**Impact:** An admin who carefully builds layered CC policies (global block
plus per-port overrides) can accidentally destroy the entire country's
blocking with one remove command. This violates the CLI symmetry principle:
you should be able to remove exactly what you added.

**Measurements:**
- `cli_trust_remove()`: 116 lines (apf_trust.sh:339-454)
- `cli_cc_remove()`: 90 lines (apf_geoip.sh:1331-1420)
- `_geoip_add_advanced_rule()`: 97 lines (apf_geoip.sh:508-604)
- Affected test file: 1045 lines (tests/35-geoip.bats)

---

## 2. Goals

1. `apf -u tcp:in:d=22:s=ZZ` removes ONLY that advanced entry from rules
   files and its corresponding iptables rules — bare `ZZ` and other
   advanced entries for the same CC are preserved
2. `apf -u ZZ` continues to remove all entries for that CC (nuke-all,
   backward compatible)
3. Ipsets are destroyed only when no CC entries remain for that country
   after targeted removal
4. GeoIP cache files are preserved during targeted removal when other
   entries for the CC remain (performance requirement — avoid re-download)
5. All existing CC removal tests continue to pass unchanged

---

## 3. Non-Goals

- Per-rule removal for *simple* (bare CC) entries — `apf -u ZZ` stays
  nuke-all
- Temporary advanced CC entries — `apf -td tcp:in:d=22:s=ZZ 1h` is not
  currently supported (cli_cc_trust_temp only handles bare CCs); adding
  temp advanced CC is a separate feature
- CC_ALLOW granular removal — architecturally identical to CC_DENY, so
  the implementation covers both, but testing focuses on CC_DENY (the
  common case)
- Cleanup of empty CC_DENYP/CC_ALLOWP chains after last entry removal —
  harmless empty chains are cleaned on next `apf -r`

---

## 4. Architecture

### File Map

| File | Action | Est. Lines Changed | Purpose |
|------|--------|-------------------|---------|
| `files/internals/apf_trust.sh` | Modify | ~8 | Route full advanced CC entries to `cli_cc_remove_entry()` |
| `files/internals/apf_geoip.sh` | Modify | ~80 new | New `cli_cc_remove_entry()` + helper `_geoip_cc_has_entries()` |
| `tests/35-geoip.bats` | Modify | ~75 new | 5 new test cases |
| `CHANGELOG` | Modify | 3 | Fix entry |
| `CHANGELOG.RELEASE` | Modify | 3 | Fix entry |

### No-Touch Files

These files are NOT modified:
- `files/apf` — CLI dispatch unchanged (already passes full string)
- `files/internals/apf_validate.sh` — validation unchanged
- `files/internals/apf_cli.sh` — help text unchanged (no new CLI syntax)
- All other test files — no cross-impact

### Size Comparison

| Metric | Before | After |
|--------|--------|-------|
| `apf_geoip.sh` | 1471 lines | ~1555 lines (+84) |
| `apf_trust.sh` | 1355 lines | ~1363 lines (+8) |
| `35-geoip.bats` | 1045 lines | ~1120 lines (+75) |

### Dependency Tree

```
apf -u "tcp:in:d=22:s=ZZ"
  └─ cli_trust_remove()                    [apf_trust.sh]
       ├─ [*=* && valid_cc(last_field)]
       │    ├─ CHANGED: full entry → cli_cc_remove_entry()   [apf_geoip.sh, NEW]
       │    │    ├─ parse entry (reuse trust_parse_fields)
       │    │    ├─ remove exact line from cc_deny/cc_allow.rules
       │    │    ├─ reconstruct + iptables -D in CC_DENYP/CC_ALLOWP
       │    │    ├─ remove LOG rules via eval+grep (same pattern as cli_cc_remove)
       │    │    └─ _geoip_cc_has_entries()                  [apf_geoip.sh, NEW]
       │    │         ├─ grep cc_deny.rules + cc_allow.rules for bare CC or =CC$
       │    │         ├─ if none remain → cli_cc_remove() for ipset/rule cleanup
       │    │         └─ NEVER delete cache files
       │    └─ UNCHANGED: bare CC → cli_cc_remove()          [apf_geoip.sh, existing]
       └─ [regular trust entries]           [unchanged]
```

### Key Changes

1. **Routing split in `cli_trust_remove()`** — currently line 353 always
   calls `cli_cc_remove "$_ctr_last_field"`. After: calls
   `cli_cc_remove_entry "$DIP" "$_ctr_last_field"` when the input is a
   full advanced entry, preserving `cli_cc_remove "$DIP"` for bare CCs
   at line 399.

2. **New `cli_cc_remove_entry()`** — mirrors `_geoip_add_advanced_rule()`
   parsing logic but issues `-D` instead of `-A`. Only targets
   CC_DENYP/CC_ALLOWP chains (advanced entries never go into CC_DENY/CC_ALLOW).

3. **New `_geoip_cc_has_entries()`** — extracted from the pattern at
   `_expire_cc_temp_entry()` lines 1453-1463. Returns 0 if any entry
   (bare or advanced) exists for the CC in either rules file.

### Dependency Rules

- `cli_cc_remove_entry()` MUST source `apf_geoip.sh` before being called
  (same pattern as existing CC routing at line 352)
- `_geoip_cc_has_entries()` is called only from `cli_cc_remove_entry()`
  and `_expire_cc_temp_entry()` (refactored to use the shared helper)
- `cli_cc_remove()` is NEVER called from `cli_cc_remove_entry()` directly
  — the has-entries check calls it only when no entries remain

---

## 5. File Contents

### 5a. `files/internals/apf_trust.sh` — Changes

| Function | Current behavior | New behavior | Lines affected |
|----------|-----------------|--------------|----------------|
| `cli_trust_remove()` | Extracts CC, calls `cli_cc_remove("$cc")` | Passes full entry to `cli_cc_remove_entry("$entry", "$cc")` | 349-354 |

**Change detail:** Replace lines 352-354:

```bash
# BEFORE:
cli_cc_remove "$_ctr_last_field"
return $?

# AFTER:
# Continent shorthand (e.g., tcp:in:d=22:s=@EU) → nuke-all per continent
# (per-rule granularity is for individual CCs only)
if [[ "$_ctr_last_field" == @* ]]; then
    cli_cc_remove "$_ctr_last_field"
else
    cli_cc_remove_entry "$DIP" "$_ctr_last_field"
fi
return $?
```

The bare CC path at lines 397-400 remains unchanged — `cli_cc_remove "$DIP"`
continues to do nuke-all.

### 5b. `files/internals/apf_geoip.sh` — New Functions

#### `_geoip_cc_has_entries()`

| Function | Signature | Purpose | Dependencies |
|----------|-----------|---------|--------------|
| `_geoip_cc_has_entries()` | `(cc)` | Check if any entry (bare or advanced) exists for CC in rules files | `$CC_DENY_HOSTS`, `$CC_ALLOW_HOSTS` |

Returns 0 if any entry exists, 1 if none. Checks both CC rules files for:
- Bare CC: `grep -v '^#' | grep -Fxq "$cc"`
- Advanced entries: `grep -v '^#' | grep -q "=${cc}$"`

~15 lines. Placed immediately before `_expire_cc_temp_entry()`.

#### `cli_cc_remove_entry()`

| Function | Signature | Purpose | Dependencies |
|----------|-----------|---------|--------------|
| `cli_cc_remove_entry()` | `(entry, cc)` | Remove single advanced CC entry from rules + iptables | `trust_parse_fields()`, `expand_port()`, `_geoip_cc_has_entries()`, `cli_cc_remove()` |

**Step-by-step logic:**

1. Validate inputs: `$entry` non-empty, `$cc` passes `valid_cc`
2. Determine chain: scan `$CC_DENY_HOSTS` for `$entry` → `CC_DENYP`/`$ALL_STOP`;
   scan `$CC_ALLOW_HOSTS` → `CC_ALLOWP`/`ACCEPT`
3. Remove from rules file: sed to delete exact entry line + its comment
4. Parse entry (same logic as `_geoip_add_advanced_rule()` lines 518-542):
   replace CC with PLACEHOLDER, `trust_parse_fields`, extract proto/dir/pflow/port/ipflow
5. Build iptables match args: `-p $proto --dport $port` (or `--sport`)
6. Determine ipset direction: `src` if `s=CC`, `dst` if `d=CC`
7. IPv4 action rule: `$IPT -D $chain $match -m set --match-set apf_cc4_${cc} $ipset_dir -j $action`
   **Note:** Under `CC_LOG_ONLY=1`, no action rule exists — the `-D`
   fails silently (`2>/dev/null`). Step 8 is the sole removal mechanism
   for audit-mode rules. Do not treat step 7 failure as function-level
   failure.
8. IPv4 LOG rules: grep `$IPT -S $chain` for `apf_cc4_${cc}` matching
   the proto/port, eval `-D` (same security gates as `cli_cc_remove`)
9. IPv6: same pattern with `$IP6T` and `apf_cc6_${cc}` (when `USE_IPV6=1`)
10. Call `_geoip_cc_has_entries "$cc"` — if returns 1 (no entries remain),
    call `cli_cc_remove "$cc"` for full cleanup (ipsets, remaining
    iptables rules, cache)

**Direction handling:** The `dir` field from parsing determines whether
the rule was originally applied via INPUT, OUTPUT, or both parent chains.
For removal, `dir` is irrelevant — rules live in CC_DENYP/CC_ALLOWP
regardless, and the `-j CC_DENYP` jump in INPUT/OUTPUT must NOT be
removed (other CCs may use it). Only the specific rule within
CC_DENYP/CC_ALLOWP is deleted.

**Dual-file behavior:** If the same entry exists in both `cc_deny.rules`
and `cc_allow.rules` (user error), remove from both files and issue
`-D` against both CC_DENYP and CC_ALLOWP. This mirrors `cli_cc_remove()`
which iterates both files.

**Parsing guidance:** Use the same manual case-switch as
`_geoip_add_advanced_rule:524-529`, NOT `_trust_unpack_fields()` — the
latter expects a real IP in the last field and would run unnecessary
`trust_restore_ipv6` on `PLACEHOLDER`. Add a cross-reference comment:
`# SYNC: parsing mirrors _geoip_add_advanced_rule:518-542`

~65 lines. Placed between `cli_cc_trust_temp()` and `cli_cc_remove()`.

### 5c. `files/internals/apf_geoip.sh` — Modified Functions

| Function | Current behavior | New behavior | Lines affected |
|----------|-----------------|--------------|----------------|
| `_expire_cc_temp_entry()` | Inline has-entries check (1453-1463) | Calls `_geoip_cc_has_entries()` | 1453-1463 |

**Refactor detail:** Replace the inline grep block with:
```bash
if ! _geoip_cc_has_entries "$cc"; then
    cli_cc_remove "$cc" > /dev/null 2>&1
fi
```

This is a pure refactor — behavior identical, code deduplicated.

### 5d. Ipset and cache cleanup after targeted removal

When `cli_cc_remove_entry()` calls `_geoip_cc_has_entries()` and finds no
remaining entries, it calls `cli_cc_remove "$cc"` which handles:
- iptables rule removal (any remaining simple rules)
- Ipset destruction
- Cache file deletion (existing behavior of `cli_cc_remove`)

**Cache preservation:** When other entries remain for the CC after targeted
removal, cache files are untouched (Goal 4). When `_geoip_cc_has_entries`
returns "no entries remain," the full `cli_cc_remove` path runs — which
deletes cache. This is correct: the CC is now fully removed (semantically
equivalent to `apf -u ZZ`), and cache for a fully-removed CC is expected
to be cleaned up.

### 5e. Examples

**Targeted removal (new behavior):**
```bash
$ apf -d ZZ "block all China"
deny China (ZZ)

$ apf -d "tcp:in:d=22:s=ZZ" "block SSH from China"
deny advanced CC rule: tcp:in:d=22:s=ZZ (China)

$ apf -u "tcp:in:d=22:s=ZZ"
Removed tcp:in:d=22:s=ZZ from trust system.
# Only the advanced entry is removed
# Bare ZZ still in cc_deny.rules, ipset still loaded

$ grep -v '^#' /etc/apf/cc_deny.rules
ZZ
# tcp:in:d=22:s=ZZ is gone
```

**Nuke-all (unchanged behavior):**
```bash
$ apf -u ZZ
Removed ZZ from trust system.
# Everything gone: bare ZZ, all advanced ZZ entries, ipsets, cache
```

**Last advanced entry removal triggers full cleanup:**
```bash
$ apf -d "tcp:in:d=22:s=ZZ" "only rule"
deny advanced CC rule: tcp:in:d=22:s=ZZ (China)

$ apf -u "tcp:in:d=22:s=ZZ"
Removed tcp:in:d=22:s=ZZ from trust system.
# No entries remain → ipsets destroyed, cache deleted (same as nuke-all)
```

**Error case — entry not found:**
```bash
$ apf -u "tcp:in:d=443:s=ZZ"
tcp:in:d=443:s=ZZ not found in trust system.
```

---

## 6. Conventions

- Function naming: `cli_cc_remove_entry()` follows existing
  `cli_cc_remove()` / `cli_cc_trust()` / `cli_cc_trust_advanced()` pattern
- Private helper naming: `_geoip_cc_has_entries()` follows existing
  `_geoip_add_simple_rules()` / `_geoip_add_advanced_rule()` pattern
- IFS reset: `local IFS=$' \t\n'` at entry (same as `_geoip_add_simple_rules`
  and `_geoip_add_advanced_rule`)
- Entry parsing: `trust_protect_ipv6` + `trust_parse_fields` +
  `_trust_unpack_fields` or direct `$_TF_*` access (same as
  `_geoip_add_advanced_rule` lines 518-529)
- LOG rule removal: eval with three-gate security (same as `cli_cc_remove`
  lines 1380-1392)
- Source guard: function added within existing `_APF_GEOIP_LOADED` guard

---

## 7. Interface Contracts

**CLI:** Unchanged. `apf -u` already accepts advanced CC entries. The
behavioral change is internal — targeted removal instead of nuke-all.

**Config:** Unchanged. No new configuration variables.

**File formats:** Unchanged. CC rules files retain the same format:
```
# added tcp:in:d=22:s=ZZ on 03/22/26 14:30:00 addedtime=1742657400 with comment: block SSH
tcp:in:d=22:s=ZZ
```

**Exit codes:** Unchanged. Returns 0 if entry found and removed, 1 if not found.

---

## 8. Migration Safety

**Upgrade path:** No migration needed. The change is internal logic only —
no config changes, no file format changes, no new files.

**Downgrade path:** If a user downgrades from 2.0.3 to 2.0.2, `apf -u`
for advanced CC entries reverts to nuke-all behavior. No data corruption.

**Install/uninstall:** No impact — `cli_cc_remove_entry()` is sourced
from `apf_geoip.sh` which is already part of the install/uninstall
lifecycle.

**Fast load:** No impact — fast load uses `iptables-restore` from
snapshot; removal functions are not involved.

---

## 9. Dead Code and Cleanup

The inline has-entries check in `_expire_cc_temp_entry()` (lines 1453-1463)
is replaced by a call to `_geoip_cc_has_entries()`. The old inline code is
deleted — no dead code remains.

No other dead code discovered during codebase reading.

---

## 10a. Test Strategy

| Goal | Test file | Test description |
|------|-----------|-----------------|
| Goal 1 | tests/35-geoip.bats | `@test "apf -u advanced CC entry preserves bare CC entry"` |
| Goal 1 | tests/35-geoip.bats | `@test "apf -u advanced CC entry removes only its iptables rules"` |
| Goal 2 | tests/35-geoip.bats | existing: `@test "apf -u ZZ removes both simple and advanced entries"` (unchanged) |
| Goal 3 | tests/35-geoip.bats | `@test "targeted CC removal destroys ipset when last entry removed"` |
| Goal 4 | tests/35-geoip.bats | `@test "targeted CC removal preserves cache when other entries remain"` |
| Goal 1 | tests/35-geoip.bats | `@test "targeted CC removal under CC_LOG_ONLY removes LOG rule"` |
| Goal 5 | — | Run full test suite — all existing tests pass |

**Test details:**

**Test 1: Preserve bare entry**
- Add `ZZ` (simple) + `tcp:in:d=22:s=ZZ` (advanced)
- Remove `tcp:in:d=22:s=ZZ` via `apf -u`
- Assert: bare `ZZ` still in `cc_deny.rules`
- Assert: ipset `apf_cc4_ZZ` still exists
- Assert: `CC_DENY` chain still has ipset match rule for `ZZ`
- Assert: `tcp:in:d=22:s=ZZ` absent from `cc_deny.rules`

**Test 2: Targeted iptables removal**
- Add `tcp:in:d=22:s=ZZ` + `tcp:in:d=443:s=ZZ`
- Remove only `tcp:in:d=22:s=ZZ`
- Assert: CC_DENYP has rule for port 443 but NOT port 22
- Assert: `tcp:in:d=443:s=ZZ` still in `cc_deny.rules`

**Test 3: Last entry triggers ipset cleanup**
- Add only `tcp:in:d=22:s=ZZ` (no bare entry)
- Remove it
- Assert: ipset `apf_cc4_ZZ` destroyed
- Assert: `cc_deny.rules` has no ZZ reference

**Test 4: Cache preservation**
- Add `ZZ` (simple) + `tcp:in:d=22:s=ZZ` (advanced)
- Remove `tcp:in:d=22:s=ZZ`
- Assert: `$APF_DIR/geoip/ZZ.4` still exists (cache preserved)

**Test 5: CC_LOG_ONLY targeted removal**
- Set `CC_LOG_ONLY=1`
- Add `tcp:in:d=22:s=ZZ` (only LOG rules created, no DROP)
- Remove `tcp:in:d=22:s=ZZ`
- Assert: CC_DENYP has no rules matching `apf_cc4_ZZ` and port 22
- Assert: entry absent from `cc_deny.rules`

---

## 10b. Verification Commands

```bash
# Goal 1: targeted removal preserves other entries
apf -d ZZ "test" && apf -d "tcp:in:d=22:s=ZZ" "test"
apf -u "tcp:in:d=22:s=ZZ"
grep -Fx "ZZ" /etc/apf/cc_deny.rules
# expect: ZZ (bare entry preserved)

grep -Fx "tcp:in:d=22:s=ZZ" /etc/apf/cc_deny.rules
# expect: (no output — entry removed)

# Goal 2: nuke-all unchanged
apf -d ZZ "test" && apf -d "tcp:in:d=22:s=ZZ" "test"
apf -u ZZ
grep "ZZ" /etc/apf/cc_deny.rules
# expect: (no output — everything removed)

# Goal 3: ipset cleanup when no entries remain
apf -d "tcp:in:d=22:s=ZZ" "test"
apf -u "tcp:in:d=22:s=ZZ"
ipset list apf_cc4_ZZ 2>&1
# expect: ipset v*.* ... The set with the given name does not exist

# Goal 4: cache preserved during targeted removal
apf -d ZZ "test" && apf -d "tcp:in:d=22:s=ZZ" "test"
apf -u "tcp:in:d=22:s=ZZ"
ls /etc/apf/geoip/ZZ.4
# expect: /etc/apf/geoip/ZZ.4 (file exists)

# Goal 5: all existing tests pass (663 current + 5 new = 668)
make -C tests test 2>&1 | tail -5
# expect: === Results: 4/4 groups passed (668 tests, 0 failed) ===
```

---

## 11. Risks

1. **Parsing divergence between add and remove paths** — if
   `cli_cc_remove_entry()` reconstructs iptables rules differently from
   `_geoip_add_advanced_rule()`, the `-D` won't match the `-A` and
   rules become orphaned.
   **Mitigation:** Extract shared parsing into a helper function, or
   use identical inline code with clear cross-reference comments. The
   roundtrip test (add then remove, verify chain empty) catches this.

2. **LOG rule mismatch** — LOG rules include `$LEXT` and
   `--log-prefix` which contain runtime values. The `-D` must match
   exactly.
   **Mitigation:** Use the same eval+grep `-S` pattern as
   `cli_cc_remove()` (scan actual loaded rules, not reconstructed ones).
   This is already proven safe in production.

3. **Race with cron `--temp-expire`** — targeted removal and cron
   expiry could operate on the same CC simultaneously.
   **Mitigation:** Existing mutex_lock on the `-u` CLI handler
   (commit 2a1ace5) prevents concurrent operations. Cron's
   `--temp-expire` also acquires the mutex.

---

## 11b. Edge Cases

| Scenario | Expected behavior | Handling |
|----------|-------------------|---------|
| Remove advanced entry that doesn't exist | Exit 1, "not found" message | `grep -Fxq` check before attempting removal |
| Remove advanced entry when bare CC also exists | Only advanced entry removed, bare CC preserved | Targeted sed on rules file, targeted `-D` on CC_DENYP only |
| Remove last advanced entry (no bare CC) | Entry removed, ipsets destroyed, cache deleted | `_geoip_cc_has_entries()` → `cli_cc_remove()` |
| Remove advanced CC_ALLOW entry (not CC_DENY) | Same logic, CC_ALLOWP chain | Function scans both rules files to determine chain/action |
| Two identical advanced entries (duplicate) | Both removed from rules file, iptables `-D` removes one | Sed `%^${entry}$%d` removes all matching lines; iptables loop removes until failure |
| Advanced entry with continent shorthand `tcp:in:d=22:s=@EU` | Route extracts `@EU`, passes to cli_cc_remove (nuke-all) | Continent advanced entries are not individually removable — nuke-all is correct for the continent scope |
| IPv6 advanced entry (USE_IPV6=1, CC_IPV6=1) | IPv6 iptables rules also removed | Function mirrors IPv4 logic for ip6tables |
| Advanced entry with sport (e.g., `tcp:out:s=80:d=ZZ`) | Correctly builds `--sport 80` and removes from OUTPUT chain | Same parsing as `_geoip_add_advanced_rule()` |
| CC_LOG_ONLY=1 (audit mode) | Only LOG rules exist (no DROP/ACCEPT) — still removed | eval+grep pattern handles LOG rules |
| Firewall not running (chains don't exist) | Rules file cleaned, iptables `-D` fails silently | `2>/dev/null` on all `-D` calls, return based on file match |

---

## 12. Open Questions

None — all design decisions resolved in brainstorming.
