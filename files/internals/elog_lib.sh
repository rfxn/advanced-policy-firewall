#!/bin/bash
#
# elog_lib.sh — Structured Event Logging Library 1.0.0
###
# Copyright (C) 2002-2026 R-fx Networks <proj@rfxn.com>
#                         Ryan MacDonald <ryan@rfxn.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
###
#
# Shared structured event logging library for rfxn projects.
# Source this file after setting ELOG_* configuration variables.
# No project-specific code — all behavior controlled via variables.

# Source guard — safe for repeated sourcing
# shellcheck disable=SC2154
[[ -n "${_ELOG_LIB_LOADED:-}" ]] && return 0 2>/dev/null
_ELOG_LIB_LOADED=1
# shellcheck disable=SC2034 # version checked by consumers
ELOG_LIB_VERSION="1.0.0"

# --- Configuration variables (set by consumer before sourcing) ---
# All use ${VAR:-default} — safe when sourced from inside functions (BATS).
#
# ELOG_APP          — app name in log lines (default: basename $0)
# ELOG_LOG_DIR      — log directory path (default: /var/log/${ELOG_APP})
# ELOG_LOG_FILE     — primary log file path (default: ${ELOG_LOG_DIR}/${ELOG_APP}.log)
# ELOG_AUDIT_FILE   — audit log file path, always JSONL (default: ${ELOG_LOG_DIR}/audit.log)
# ELOG_SYSLOG_FILE  — secondary syslog output file (empty = disabled)
# ELOG_LEGACY_LOG   — old log path; elog_init() creates symlink to new path
# ELOG_LEVEL        — minimum severity: 0=debug 1=info 2=warn 3=error 4=critical (default: 1)
# ELOG_VERBOSE      — when "1", debug-level messages emit to stdout (default: 0)
# ELOG_FORMAT       — "classic" or "json" (default: classic)
# ELOG_TS_FORMAT    — date strftime format (default: "%b %e %H:%M:%S")
# ELOG_STDOUT       — "always"|"never"|"flag" (default: always)
# ELOG_STDOUT_PREFIX — "full"|"short"|"none" (default: full)
# ELOG_LOG_MAX_LINES — max lines in app log before truncation (0 = disabled)
# ELOG_ROTATE_FREQUENCY — logrotate frequency (default: weekly)
# ELOG_ROTATE_COUNT — logrotate keep count (default: 12)
# ELOG_ROTATE_COMPRESS — logrotate compress (default: compress)

# --- Internal state ---
_ELOG_INIT_DONE=0
_ELOG_WRITE_COUNT=0
_ELOG_TRUNCATE_CHECK_INTERVAL=50

# --- Internal functions ---

# _elog_level_num(name) — maps level name to numeric value
# Returns: 0=debug, 1=info, 2=warn, 3=error, 4=critical; unknown defaults to 1
_elog_level_num() {
	case "${1:-info}" in
		debug)    echo 0 ;;
		info)     echo 1 ;;
		warn)     echo 2 ;;
		error)    echo 3 ;;
		critical) echo 4 ;;
		*)        echo 1 ;;
	esac
}

# _elog_level_name(num) — maps numeric value to level name
_elog_level_name() {
	case "${1:-1}" in
		0) echo "debug" ;;
		1) echo "info" ;;
		2) echo "warn" ;;
		3) echo "error" ;;
		4) echo "critical" ;;
		*) echo "info" ;;
	esac
}

# _elog_json_escape(str) — escape string for safe JSON embedding
# Handles: backslash, double-quote, newline, tab, carriage return
_elog_json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\t'/\\t}"
	s="${s//$'\r'/\\r}"
	echo "$s"
}

# _elog_extract_tag(msg) — extract {tag} prefix from message
# Returns the tag name (without braces), or empty if no tag found
_elog_extract_tag() {
	local msg="$1"
	local tag_pat='^\{([^}]+)\}'
	if [[ "$msg" =~ $tag_pat ]]; then
		echo "${BASH_REMATCH[1]}"
	fi
}

# _elog_strip_tag(msg) — strip {tag} prefix (and trailing space) from message
_elog_strip_tag() {
	local msg="$1"
	local tag_pat='^\{[^}]+\} '
	if [[ "$msg" =~ $tag_pat ]]; then
		echo "${msg#"${BASH_REMATCH[0]}"}"
	else
		echo "$msg"
	fi
}

# ---------------------------------------------------------------------------
# Log File Architecture
# ---------------------------------------------------------------------------

# elog_init() — initialize log environment
# Creates log directory, touches log files, sets permissions, creates legacy
# symlinks, auto-enables file and audit_file output modules.
# Call once at consumer startup after setting ELOG_APP.
# Returns 0 on success, 1 on failure (directory creation failed).
elog_init() {
	local _app="${ELOG_APP:-${0##*/}}"
	local _log_dir="${ELOG_LOG_DIR:-/var/log/${_app}}"
	local _log_file="${ELOG_LOG_FILE:-${_log_dir}/${_app}.log}"
	local _audit_file="${ELOG_AUDIT_FILE:-${_log_dir}/audit.log}"

	# Export computed paths back to env for consumers
	ELOG_LOG_DIR="$_log_dir"
	ELOG_LOG_FILE="$_log_file"
	ELOG_AUDIT_FILE="$_audit_file"

	# Create log directory
	if [ ! -d "$_log_dir" ]; then
		if ! mkdir -p "$_log_dir" 2>/dev/null; then
			echo "elog_lib: failed to create log directory: $_log_dir" >&2
			return 1
		fi
		chmod 750 "$_log_dir"
	fi

	# Touch log files with correct permissions
	local _f
	for _f in "$_log_file" "$_audit_file"; do
		if [ ! -f "$_f" ]; then
			touch "$_f" 2>/dev/null || {
				echo "elog_lib: failed to create log file: $_f" >&2
				return 1
			}
			chmod 640 "$_f"
		fi
	done

	# Legacy symlink
	if [ -n "${ELOG_LEGACY_LOG:-}" ]; then
		if [ ! -e "$ELOG_LEGACY_LOG" ] && [ ! -L "$ELOG_LEGACY_LOG" ]; then
			ln -sf "$_log_file" "$ELOG_LEGACY_LOG" 2>/dev/null || true
		fi
	fi

	# Auto-enable output modules
	if [ -n "$_log_file" ]; then
		elog_output_enable "file" 2>/dev/null || true
	fi
	if [ -n "$_audit_file" ]; then
		elog_output_enable "audit_file" 2>/dev/null || true
	fi
	if [ -n "${ELOG_SYSLOG_FILE:-}" ]; then
		elog_output_enable "syslog_file" 2>/dev/null || true
	fi

	_ELOG_INIT_DONE=1
	return 0
}

# elog_logrotate_snippet() — output logrotate config to stdout
# Consumer pipes to /etc/logrotate.d/<project>
elog_logrotate_snippet() {
	local _app="${ELOG_APP:-${0##*/}}"
	local _log_dir="${ELOG_LOG_DIR:-/var/log/${_app}}"
	local _log_file="${ELOG_LOG_FILE:-${_log_dir}/${_app}.log}"
	local _audit_file="${ELOG_AUDIT_FILE:-${_log_dir}/audit.log}"
	local _freq="${ELOG_ROTATE_FREQUENCY:-weekly}"
	local _count="${ELOG_ROTATE_COUNT:-12}"
	local _compress="${ELOG_ROTATE_COMPRESS:-compress}"

	cat <<-LOGROTATE
	${_log_file} ${_audit_file} {
	    ${_freq}
	    rotate ${_count}
	    ${_compress}
	    delaycompress
	    missingok
	    notifempty
	    create 640 root root
	    sharedscripts
	    postrotate
	        # Signal consumer to reopen log handles (if applicable)
	        [ -f /var/run/${_app}.pid ] && kill -HUP \$(cat /var/run/${_app}.pid) 2>/dev/null || true
	    endscript
	}
	LOGROTATE
}

# _elog_truncate_check() — truncate app log if over ELOG_LOG_MAX_LINES
# Atomic: tail+cat to preserve inode (critical for inotifywait consumers).
# Called periodically from elog(), not on every write.
_elog_truncate_check() {
	local _max="${ELOG_LOG_MAX_LINES:-0}"
	[ "$_max" -le 0 ] 2>/dev/null && return 0
	local _file="${ELOG_LOG_FILE:-}"
	[ -z "$_file" ] && return 0
	[ ! -f "$_file" ] && return 0

	local _count
	_count=$(wc -l < "$_file")
	_count="${_count## }"
	if [ "$_count" -gt "$_max" ]; then
		local _tmpf
		_tmpf=$(mktemp "${_file}.XXXXXX") || return 0
		tail -n "$_max" "$_file" > "$_tmpf"
		cat "$_tmpf" > "$_file"
		rm -f "$_tmpf"
	fi
}

# _elog_auto_enable — enable output modules on first use (pre-init fallback)
# Enables all 4 built-in modules (gated by file variable).
# Source filtering in _elog_dispatch prevents cross-contamination.
_elog_auto_enable() {
	[ "$_ELOG_INIT_DONE" -ne 0 ] && return 0
	if [ -n "${ELOG_LOG_FILE:-}" ] && ! elog_output_enabled "file"; then
		elog_output_enable "file" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	if [ -n "${ELOG_AUDIT_FILE:-}" ] && ! elog_output_enabled "audit_file"; then
		elog_output_enable "audit_file" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	if [ -n "${ELOG_SYSLOG_FILE:-}" ] && ! elog_output_enabled "syslog_file"; then
		elog_output_enable "syslog_file" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	if ! elog_output_enabled "stdout"; then
		elog_output_enable "stdout" 2>/dev/null || true  # safe: module may not be registered yet
	fi
	_ELOG_INIT_DONE=1
}

# ---------------------------------------------------------------------------
# Output Module Registry
# ---------------------------------------------------------------------------

# Parallel indexed arrays (no declare -A — breaks when sourced from functions)
_ELOG_OUTPUT_NAMES=()
_ELOG_OUTPUT_HANDLERS=()
_ELOG_OUTPUT_ENABLED=()
_ELOG_OUTPUT_FORMATS=()
_ELOG_OUTPUT_SOURCES=()

# _elog_output_find name — locate output module index by name
# Sets _ELOG_OUTPUT_IDX on success (avoids subshell fork).
# Returns 0 if found, 1 if not found.
_elog_output_find() {
	local name="$1"
	local i
	_ELOG_OUTPUT_IDX=-1
	for i in "${!_ELOG_OUTPUT_NAMES[@]}"; do
		if [ "${_ELOG_OUTPUT_NAMES[$i]}" = "$name" ]; then
			_ELOG_OUTPUT_IDX=$i
			return 0
		fi
	done
	return 1
}

# elog_output_register name handler_fn format source — register an output module
# Appends to parallel indexed arrays. Module starts disabled (enabled=0).
# format: "classic", "json", "cef"
# source: "all" (elog+event), "elog" (app log only), "event" (structured events only)
# Returns 1 if name is empty, handler_fn is empty, or name already registered.
elog_output_register() {
	local name="$1" handler_fn="$2" format="${3:-classic}" source="${4:-all}"
	if [ -z "$name" ]; then
		echo "elog_lib: output name cannot be empty." >&2
		return 1
	fi
	if [ -z "$handler_fn" ]; then
		echo "elog_lib: handler function cannot be empty for output '$name'." >&2
		return 1
	fi
	if _elog_output_find "$name"; then
		echo "elog_lib: output '$name' already registered." >&2
		return 1
	fi
	_ELOG_OUTPUT_NAMES+=("$name")
	_ELOG_OUTPUT_HANDLERS+=("$handler_fn")
	_ELOG_OUTPUT_ENABLED+=("0")
	_ELOG_OUTPUT_FORMATS+=("$format")
	_ELOG_OUTPUT_SOURCES+=("$source")
	return 0
}

# elog_output_enable name — mark output module as active
# Returns 1 if module not registered.
elog_output_enable() {
	local name="$1"
	if ! _elog_output_find "$name"; then
		echo "elog_lib: output '$name' not registered." >&2
		return 1
	fi
	_ELOG_OUTPUT_ENABLED[_ELOG_OUTPUT_IDX]=1
	return 0
}

# elog_output_disable name — mark output module as inactive
# Returns 1 if module not registered.
elog_output_disable() {
	local name="$1"
	if ! _elog_output_find "$name"; then
		echo "elog_lib: output '$name' not registered." >&2
		return 1
	fi
	_ELOG_OUTPUT_ENABLED[_ELOG_OUTPUT_IDX]=0
	return 0
}

# elog_output_enabled name — check if output module is active
# Returns 0 if enabled, 1 if disabled or not found.
elog_output_enabled() {
	local name="$1"
	if ! _elog_output_find "$name"; then
		return 1
	fi
	[ "${_ELOG_OUTPUT_ENABLED[_ELOG_OUTPUT_IDX]}" = "1" ]
}

# ---------------------------------------------------------------------------
# Built-in Output Handlers
# ---------------------------------------------------------------------------

# _elog_out_file formatted_line — append to ELOG_LOG_FILE
_elog_out_file() {
	local _line="$1"
	if [ -n "${ELOG_LOG_FILE:-}" ]; then
		echo "$_line" >> "$ELOG_LOG_FILE"
	fi
}

# _elog_out_audit formatted_line — append JSONL to ELOG_AUDIT_FILE
# Always writes JSON regardless of ELOG_FORMAT setting
_elog_out_audit() {
	local _line="$1"
	if [ -n "${ELOG_AUDIT_FILE:-}" ]; then
		echo "$_line" >> "$ELOG_AUDIT_FILE"
	fi
}

# _elog_out_syslog_file formatted_line — append to ELOG_SYSLOG_FILE
_elog_out_syslog_file() {
	local _line="$1"
	if [ -n "${ELOG_SYSLOG_FILE:-}" ]; then
		echo "$_line" >> "$ELOG_SYSLOG_FILE"
	fi
}

# _elog_out_stdout formatted_line level msg — output to terminal
# Respects ELOG_STDOUT and ELOG_STDOUT_PREFIX settings.
# $2=level, $3=msg, $4=stdout_flag (for flag mode)
_elog_out_stdout() {
	local _line="$1" _level="$2" _msg="$3" _stdout_flag="${4:-}"
	local _stdout="${ELOG_STDOUT:-always}"
	local _app="${ELOG_APP:-${0##*/}}"
	local _pid="$$"

	case "$_stdout" in
		always) ;;
		never) return 0 ;;
		flag)
			[ -z "$_stdout_flag" ] && return 0
			;;
	esac

	local _prefix="${ELOG_STDOUT_PREFIX:-full}"
	case "$_prefix" in
		full)  echo "$_line" ;;
		short) echo "${_app}(${_pid}): $_msg" ;;
		none)  echo "$_msg" ;;
	esac
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

# _elog_dispatch api_source formatted_line json_line level msg stdout_flag
# Routes output to all enabled modules whose source filter matches api_source.
# api_source: "elog" or "event"
_elog_dispatch() {
	local _api="$1" _classic="$2" _json="$3" _level="$4" _msg="$5" _stdout_flag="${6:-}"
	local _i _name _handler _enabled _format _source _line

	for _i in "${!_ELOG_OUTPUT_NAMES[@]}"; do
		_enabled="${_ELOG_OUTPUT_ENABLED[$_i]}"
		[ "$_enabled" = "1" ] || continue

		_source="${_ELOG_OUTPUT_SOURCES[$_i]}"
		# Source filter: "all" accepts both, otherwise must match
		if [ "$_source" != "all" ] && [ "$_source" != "$_api" ]; then
			continue
		fi

		_name="${_ELOG_OUTPUT_NAMES[$_i]}"
		_handler="${_ELOG_OUTPUT_HANDLERS[$_i]}"
		_format="${_ELOG_OUTPUT_FORMATS[$_i]}"

		# Select formatted line based on module's declared format
		case "$_format" in
			json)    _line="$_json" ;;
			*)       _line="$_classic" ;;
		esac

		# stdout handler gets extra args for prefix handling
		if [ "$_name" = "stdout" ]; then
			"$_handler" "$_line" "$_level" "$_msg" "$_stdout_flag"
		else
			"$_handler" "$_line"
		fi
	done
}

# ---------------------------------------------------------------------------
# Event Taxonomy
# ---------------------------------------------------------------------------

# _elog_event_type_valid(type) — returns 0 for known event types, 1 for unknown
# 23 canonical event types across 7 categories. Guidance only — elog_event()
# does not enforce; consumers may pass unknown types.
_elog_event_type_valid() {
	case "${1:-}" in
		# Detection
		threat_detected|threshold_exceeded|pattern_matched|scan_started|scan_completed)
			return 0 ;;
		# Enforcement
		block_added|block_removed|block_escalated|quarantine_added|quarantine_removed)
			return 0 ;;
		# Trust
		trust_added|trust_removed)
			return 0 ;;
		# Network
		rule_loaded|rule_removed|service_state)
			return 0 ;;
		# Alert
		alert_sent|alert_failed)
			return 0 ;;
		# Monitor
		monitor_started|monitor_stopped)
			return 0 ;;
		# System
		config_loaded|config_error|file_cleaned|error_occurred)
			return 0 ;;
		*)
			return 1 ;;
	esac
}

# _elog_event_severity(type) — returns default severity name for event type
# error: block_escalated, alert_failed, config_error, error_occurred
# warn:  threat_detected, threshold_exceeded, block_added, quarantine_added
# info:  all others + unknown types
# No types default to critical — consumer must escalate explicitly.
_elog_event_severity() {
	case "${1:-}" in
		block_escalated|alert_failed|config_error|error_occurred)
			echo "error" ;;
		threat_detected|threshold_exceeded|block_added|quarantine_added)
			echo "warn" ;;
		*)
			echo "info" ;;
	esac
}

# ---------------------------------------------------------------------------
# Public API: elog()
# ---------------------------------------------------------------------------

# elog(level, message [, stdout_flag])
# Primary logging function — backward compatible with BFD v1.0.0 API.
#
# Levels: debug, info, warn, error, critical
# - debug: stdout only (bare text), gated by ELOG_VERBOSE=1, never writes to files
# - info+: formatted output routed through output module dispatch
#
# Returns 0 always (logging must never cause caller failure).
elog() {
	local _level="${1:-info}"
	local _msg="${2:-}"
	local _stdout_flag="${3:-}"

	# empty message — no output
	[ -z "$_msg" ] && return 0

	local _level_num
	_level_num=$(_elog_level_num "$_level")

	# debug level: stdout only (bare text), gated solely by ELOG_VERBOSE
	# (not subject to ELOG_LEVEL filtering — ELOG_VERBOSE is its own gate)
	if [ "$_level_num" -eq 0 ]; then
		if [ "${ELOG_VERBOSE:-0}" = "1" ]; then
			echo "$_msg"
		fi
		return 0
	fi

	local _min_level="${ELOG_LEVEL:-1}"

	# below minimum severity — suppress
	[ "$_level_num" -lt "$_min_level" ] && return 0

	# Fallback: auto-enable modules if init wasn't called (backward compat)
	_elog_auto_enable

	# info+ levels: format and route
	local _ts _host _app _pid
	_ts=$(date +"${ELOG_TS_FORMAT:-%b %e %H:%M:%S}")
	_host=$(hostname -s 2>/dev/null || hostname)
	_app="${ELOG_APP:-${0##*/}}"
	_pid="$$"

	# Build classic formatted line
	local _classic_line
	_classic_line="$_ts $_host ${_app}(${_pid}): $_msg"

	# Build JSON formatted line
	local _json_line _esc_msg _tag _esc_tag _json_msg _iso_ts
	_tag=$(_elog_extract_tag "$_msg")
	if [ -n "$_tag" ]; then
		_json_msg=$(_elog_strip_tag "$_msg")
	else
		_json_msg="$_msg"
	fi
	_esc_msg=$(_elog_json_escape "$_json_msg")
	_iso_ts=$(date +"%Y-%m-%dT%H:%M:%S%z")
	if [ -n "$_tag" ]; then
		_esc_tag=$(_elog_json_escape "$_tag")
		_json_line="{\"ts\":\"${_iso_ts}\",\"host\":\"${_host}\",\"app\":\"${_app}\",\"pid\":${_pid},\"level\":\"${_level}\",\"tag\":\"${_esc_tag}\",\"msg\":\"${_esc_msg}\"}"
	else
		_json_line="{\"ts\":\"${_iso_ts}\",\"host\":\"${_host}\",\"app\":\"${_app}\",\"pid\":${_pid},\"level\":\"${_level}\",\"msg\":\"${_esc_msg}\"}"
	fi

	# Use dispatch if any modules are registered, else direct write (backward compat)
	if [ ${#_ELOG_OUTPUT_NAMES[@]} -gt 0 ]; then
		local _fmt="${ELOG_FORMAT:-classic}"
		local _out_classic _out_json
		if [ "$_fmt" = "json" ]; then
			_out_classic="$_json_line"
		else
			_out_classic="$_classic_line"
		fi
		_out_json="$_json_line"
		_elog_dispatch "elog" "$_out_classic" "$_out_json" "$_level" "$_msg" "$_stdout_flag"
	else
		# No modules registered — direct write (pre-init / backward compat)
		if [ -n "${ELOG_LOG_FILE:-}" ]; then
			local _fmt="${ELOG_FORMAT:-classic}"
			if [ "$_fmt" = "json" ]; then
				echo "$_json_line" >> "$ELOG_LOG_FILE"
			else
				echo "$_classic_line" >> "$ELOG_LOG_FILE"
			fi
		fi
		if [ -n "${ELOG_SYSLOG_FILE:-}" ]; then
			local _fmt="${ELOG_FORMAT:-classic}"
			if [ "$_fmt" = "json" ]; then
				echo "$_json_line" >> "$ELOG_SYSLOG_FILE"
			else
				echo "$_classic_line" >> "$ELOG_SYSLOG_FILE"
			fi
		fi
		# Stdout
		local _stdout="${ELOG_STDOUT:-always}"
		case "$_stdout" in
			always) ;;
			never) return 0 ;;
			flag)
				[ -z "$_stdout_flag" ] && return 0
				;;
		esac
		local _prefix="${ELOG_STDOUT_PREFIX:-full}"
		local _fmt="${ELOG_FORMAT:-classic}"
		case "$_prefix" in
			full)
				if [ "$_fmt" = "json" ]; then
					echo "$_json_line"
				else
					echo "$_classic_line"
				fi
				;;
			short)
				echo "${_app}(${_pid}): $_msg"
				;;
			none)
				echo "$_msg"
				;;
		esac
	fi

	# Periodic log truncation check
	_ELOG_WRITE_COUNT=$((_ELOG_WRITE_COUNT + 1))
	if [ $((_ELOG_WRITE_COUNT % _ELOG_TRUNCATE_CHECK_INTERVAL)) -eq 0 ]; then
		_elog_truncate_check
	fi

	return 0
}

# Convenience wrappers
elog_debug() { elog debug "$@"; }
elog_info()  { elog info "$@"; }
elog_warn()  { elog warn "$@"; }
elog_error() { elog error "$@"; }
elog_critical() { elog critical "$@"; }

# ---------------------------------------------------------------------------
# Public API: elog_event()
# ---------------------------------------------------------------------------

# elog_event(event_type, severity, message [, key1=val1 ...])
# Structured event logging — dispatches via api_source="event" to audit_file
# and any custom modules registered with source="event" or source="all".
#
# - Empty type: stderr warning + return 1
# - Empty message: return 0 (no output)
# - Severity filtering: _elog_level_num < ELOG_LEVEL → suppress, return 0
# - Builds JSON envelope with mandatory fields: ts, host, app, pid, type, level, msg
# - Extracts {tag} from message; parses remaining args as key=value extra fields
# - Does NOT increment _ELOG_WRITE_COUNT (audit log not subject to truncation)
# - Returns 0 on success
elog_event() {
	local _type="${1:-}"
	local _level="${2:-info}"
	local _msg="${3:-}"

	# Empty type — input validation error
	if [ -z "$_type" ]; then
		echo "elog_lib: elog_event() requires event_type as first argument" >&2
		return 1
	fi

	# Empty message — no output
	[ -z "$_msg" ] && return 0

	# Severity filtering
	local _level_num _min_level
	_level_num=$(_elog_level_num "$_level")
	_min_level="${ELOG_LEVEL:-1}"
	[ "$_level_num" -lt "$_min_level" ] && return 0

	# Pre-init fallback
	_elog_auto_enable

	# Timestamp and identity
	local _ts _host _app _pid
	_ts=$(date +"${ELOG_TS_FORMAT:-%b %e %H:%M:%S}")
	_host=$(hostname -s 2>/dev/null || hostname)
	_app="${ELOG_APP:-${0##*/}}"
	_pid="$$"

	# Extract {tag} from message
	local _tag _json_msg
	_tag=$(_elog_extract_tag "$_msg")
	if [ -n "$_tag" ]; then
		_json_msg=$(_elog_strip_tag "$_msg")
	else
		_json_msg="$_msg"
	fi

	# JSON-escape mandatory fields
	local _esc_msg _esc_type _iso_ts
	_esc_msg=$(_elog_json_escape "$_json_msg")
	_esc_type=$(_elog_json_escape "$_type")
	_iso_ts=$(date +"%Y-%m-%dT%H:%M:%S%z")

	# Parse key=value extra fields from remaining args
	local _pair _key _val _esc_key _esc_val _extra=""
	shift 3 2>/dev/null || true  # safe: fewer than 3 args means no extras
	for _pair in "$@"; do
		_key="${_pair%%=*}"
		_val="${_pair#*=}"
		[ "$_key" = "$_pair" ] && continue  # no = found
		[ -z "$_key" ] && continue           # empty key
		_esc_key=$(_elog_json_escape "$_key")
		_esc_val=$(_elog_json_escape "$_val")
		_extra="${_extra},\"${_esc_key}\":\"${_esc_val}\""
	done

	# Build JSON envelope
	local _json_line
	_json_line="{\"ts\":\"${_iso_ts}\",\"host\":\"${_host}\",\"app\":\"${_app}\",\"pid\":${_pid},\"type\":\"${_esc_type}\",\"level\":\"${_level}\",\"msg\":\"${_esc_msg}\""
	if [ -n "$_tag" ]; then
		local _esc_tag
		_esc_tag=$(_elog_json_escape "$_tag")
		_json_line="${_json_line},\"tag\":\"${_esc_tag}\""
	fi
	_json_line="${_json_line}${_extra}}"

	# Build classic line: timestamp host app(pid): [type] message
	local _classic_line
	if [ -n "$_tag" ]; then
		_classic_line="$_ts $_host ${_app}(${_pid}): [${_type}] {${_tag}} ${_json_msg}"
	else
		_classic_line="$_ts $_host ${_app}(${_pid}): [${_type}] ${_json_msg}"
	fi

	# Dispatch via event api_source — reaches audit_file and source="all" modules
	_elog_dispatch "event" "$_classic_line" "$_json_line" "$_level" "$_msg" ""

	return 0
}

# ---------------------------------------------------------------------------
# Built-in Module Registration
# ---------------------------------------------------------------------------

# Register built-in output modules — consumers enable via elog_output_enable or elog_init()
# file: app log, format follows ELOG_FORMAT, receives elog() output
# audit_file: audit log, always JSONL, receives elog_event() output only
# syslog_file: syslog echo, format follows ELOG_FORMAT, receives all output
# stdout: terminal, classic format with prefix modes, receives all output
elog_output_register "file" "_elog_out_file" "classic" "elog"
elog_output_register "audit_file" "_elog_out_audit" "json" "event"
elog_output_register "syslog_file" "_elog_out_syslog_file" "classic" "elog"
elog_output_register "stdout" "_elog_out_stdout" "classic" "all"
