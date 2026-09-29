#!/usr/bin/env bash
# cPanel Sentry — shared helpers. Sourced by every component.
# shellcheck disable=SC2034

SENTRY_CONF="${SENTRY_CONF:-/etc/cpanel-sentry/sentry.conf}"

# ---- load config ----------------------------------------------------
sentry_load_conf() {
  if [[ -f "$SENTRY_CONF" ]]; then
    # shellcheck source=/dev/null
    source "$SENTRY_CONF"
  fi
  : "${STATE_DIR:=/var/lib/cpanel-sentry}"
  : "${LOG_DIR:=/var/log/cpanel-sentry}"
  : "${LIB_DIR:=/usr/local/cpanel-sentry}"
  : "${HOME_ROOT:=/home}"
  : "${BLOCK_THRESHOLD:=1}"
  : "${BLOCK_WINDOW:=3600}"
  : "${BLOCK_TTL:=0}"
  WHITELIST_FILE="$STATE_DIR/whitelist.txt"
  BLOCKLIST_FILE="$STATE_DIR/blocklist.txt"
  HITS_LOG="$LOG_DIR/hits.log"
  SENTRY_LOG="$LOG_DIR/sentry.log"
}

# ---- logging --------------------------------------------------------
c_reset='\033[0m'; c_red='\033[0;31m'; c_grn='\033[0;32m'; c_yel='\033[0;33m'; c_blu='\033[0;34m'
say()  { printf "${c_blu}[*]${c_reset} %s\n" "$*"; }
ok()   { printf "${c_grn}[+]${c_reset} %s\n" "$*"; }
warn() { printf "${c_yel}[!]${c_reset} %s\n" "$*"; }
err()  { printf "${c_red}[x]${c_reset} %s\n" "$*" >&2; }
log()  { mkdir -p "$LOG_DIR" 2>/dev/null; printf '%s %s\n' "$(date '+%F %T')" "$*" >> "${SENTRY_LOG:-/var/log/cpanel-sentry/sentry.log}"; }

need_root() { [[ $EUID -eq 0 ]] || { err "Must run as root."; exit 1; }; }

# ---- validation -----------------------------------------------------
# Accept IPv4, IPv4/CIDR, IPv6, IPv6/CIDR.
valid_ip() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] && return 0
  [[ "$ip" =~ ^([0-9a-fA-F:]+:+)+[0-9a-fA-F]*(/[0-9]{1,3})?$ ]] && return 0
  return 1
}

is_whitelisted() {
  local ip="$1"
  [[ -f "$WHITELIST_FILE" ]] || return 1
  grep -qxF "$ip" "$WHITELIST_FILE"
}

# ---- iptables persistence ------------------------------------------
sentry_persist() {
  command -v iptables-save >/dev/null || return 0
  iptables-save  > /etc/iptables.save 2>/dev/null || true
  iptables-save  > /etc/sysconfig/iptables 2>/dev/null || true
  command -v ip6tables-save >/dev/null && ip6tables-save > /etc/sysconfig/ip6tables 2>/dev/null || true
  log "iptables ruleset persisted"
}

# Add a DROP for an IP (idempotent), respecting whitelist. TTL handled by caller.
sentry_block_ip() {
  local ip="$1" reason="${2:-abuse}"
  valid_ip "$ip" || { warn "skip invalid ip: $ip"; return 1; }
  if is_whitelisted "$ip"; then warn "refuse to block whitelisted $ip"; return 1; fi
  if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then return 0; fi
  iptables -I INPUT 1 -s "$ip" -j DROP
  grep -qxF "$ip" "$BLOCKLIST_FILE" 2>/dev/null || echo "$ip" >> "$BLOCKLIST_FILE"
  log "BLOCK $ip ($reason)"
  sentry_persist
}

sentry_unblock_ip() {
  local ip="$1"
  while iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; do iptables -D INPUT -s "$ip" -j DROP; done
  sed -i "\#^${ip}\$#d" "$BLOCKLIST_FILE" 2>/dev/null || true
  log "UNBLOCK $ip"
  sentry_persist
}
