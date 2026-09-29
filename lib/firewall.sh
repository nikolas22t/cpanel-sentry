#!/usr/bin/env bash
# cPanel Sentry — firewall module.
# Builds a cPanel-safe iptables ruleset:
#   * SSH (and optionally WHM/cPanel ports) restricted to ALLOW_IPS, in+out
#   * default-DROP INPUT with every ACTIVE customer/service port allowed
#   * passive FTP preserved via the conntrack FTP helper
#   * applied behind an auto-rollback safety net, then persisted
# Nothing customer-facing (web/mail/ftp/dns/cpanel) is blocked.

fw_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$fw_here/common.sh"

# Standard cPanel/WHM service ports that must stay reachable for customers.
FW_CPANEL_TCP="20 21 25 26 53 80 110 143 443 465 587 993 995 2077 2078 2079 2080 2082 2083 2086 2087 2091 2095 2096"
FW_CPANEL_UDP="53"
# Ports considered "management" (restricted when LOCK_PANEL=1).
FW_PANEL_TCP="2086 2087 2083 2096 2078 2080"

# Detect every TCP/UDP port with a process LISTENING on a non-loopback
# address — these are live services we must not break.
fw_detect_public_ports() {
  local proto="$1" flag; [[ "$proto" == udp ]] && flag="-ulnH" || flag="-tlnH"
  ss $flag 2>/dev/null | awk '{print $4}' \
    | grep -Ev '^127\.|^\[::1\]' \
    | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^[0-9]+$' | sort -un
}

fw_accept_tcp() { local p="$1"; iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$p" -j ACCEPT; }
fw_accept_udp() { local p="$1"; iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$p" -j ACCEPT; }

# Restrict a TCP port to the allowlist (in + out), dropping everyone else.
fw_restrict_port() {
  local port="$1" ip
  # keep established alive first
  iptables -C INPUT -p tcp --dport "$port" -m state --state ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -p tcp --dport "$port" -m state --state ESTABLISHED -j ACCEPT
  for ip in $ALLOW_IPS; do
    iptables -C INPUT -p tcp --dport "$port" -s "$ip" -j ACCEPT 2>/dev/null \
      || iptables -I INPUT 1 -p tcp --dport "$port" -s "$ip" -j ACCEPT
    iptables -C OUTPUT -p tcp --dport "$port" -d "$ip" -j ACCEPT 2>/dev/null \
      || iptables -I OUTPUT 1 -p tcp --dport "$port" -d "$ip" -j ACCEPT
  done
  iptables -C OUTPUT -p tcp --dport "$port" -m state --state ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -I OUTPUT 1 -p tcp --dport "$port" -m state --state ESTABLISHED -j ACCEPT
  iptables -C INPUT  -p tcp --dport "$port" -j DROP 2>/dev/null || iptables -A INPUT  -p tcp --dport "$port" -j DROP
  iptables -C OUTPUT -p tcp --dport "$port" -j DROP 2>/dev/null || iptables -A OUTPUT -p tcp --dport "$port" -j DROP
}

fw_arm_rollback() {
  [[ "${ROLLBACK_SECONDS:-0}" -gt 0 ]] || return 0
  iptables-save > "$STATE_DIR/rollback.rules"
  nohup bash -c "sleep ${ROLLBACK_SECONDS}; iptables-restore < '$STATE_DIR/rollback.rules'; logger 'cpanel-sentry firewall rollback fired'" \
    >/dev/null 2>&1 &
  echo $! > "$STATE_DIR/rollback.pid"
  warn "Auto-rollback armed: rules revert in ${ROLLBACK_SECONDS}s unless confirmed (sentry-apply --confirm)."
}

fw_cancel_rollback() {
  [[ -f "$STATE_DIR/rollback.pid" ]] || return 0
  kill "$(cat "$STATE_DIR/rollback.pid")" 2>/dev/null || true
  rm -f "$STATE_DIR/rollback.pid"
  ok "Rollback cancelled — firewall kept."
}

fw_apply() {
  need_root; sentry_load_conf
  [[ -n "$ALLOW_IPS" ]] || { err "ALLOW_IPS is empty — refusing (would lock you out)."; return 1; }
  mkdir -p "$STATE_DIR"

  say "Backing up current ruleset -> $STATE_DIR/pre-sentry.rules"
  iptables-save > "$STATE_DIR/pre-sentry.rules"
  fw_arm_rollback

  # --- passive FTP helper (so default-DROP doesn't break uploads) ----
  modprobe nf_conntrack_ftp 2>/dev/null && echo nf_conntrack_ftp > /etc/modules-load.d/sentry-ftp.conf
  iptables -t raw -C PREROUTING -p tcp --dport 21 -j CT --helper ftp 2>/dev/null \
    || iptables -t raw -A PREROUTING -p tcp --dport 21 -j CT --helper ftp

  # --- base accepts (session-safe): loopback + established + icmp -----
  iptables -C INPUT -i lo -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i lo -j ACCEPT
  iptables -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 2 -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -C INPUT -p icmp --icmp-type echo-request -j ACCEPT 2>/dev/null \
    || iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

  # --- SSH allowlist -------------------------------------------------
  if [[ "${LOCK_SSH:-1}" -eq 1 ]]; then
    say "Restricting SSH (22) to allowlist (in + out)"
    fw_restrict_port 22
  else
    fw_accept_tcp 22
  fi

  # --- panel ports ---------------------------------------------------
  if [[ "${LOCK_PANEL:-0}" -eq 1 ]]; then
    say "Restricting WHM/cPanel management ports to allowlist"
    for p in $FW_PANEL_TCP; do fw_restrict_port "$p"; done
  fi

  # --- allow all live customer/service ports -------------------------
  local detected_tcp detected_udp p
  detected_tcp="$(fw_detect_public_ports tcp)"
  detected_udp="$(fw_detect_public_ports udp)"
  say "Allowing customer/service ports (cPanel defaults + detected live services)"
  for p in $FW_CPANEL_TCP $detected_tcp $EXTRA_TCP_PORTS; do
    [[ "$p" == 22 ]] && continue                       # 22 handled above
    [[ "${LOCK_PANEL:-0}" -eq 1 && " $FW_PANEL_TCP " == *" $p "* ]] && continue
    fw_accept_tcp "$p"
  done
  for p in $FW_CPANEL_UDP $detected_udp $EXTRA_UDP_PORTS; do fw_accept_udp "$p"; done

  # --- re-apply any existing blocklist entries -----------------------
  if [[ -f "$BLOCKLIST_FILE" ]]; then
    while read -r bip; do [[ -n "$bip" ]] && sentry_block_ip "$bip" "persisted" ; done < "$BLOCKLIST_FILE"
  fi

  # --- the switch ----------------------------------------------------
  if [[ "${ENABLE_FIREWALL:-1}" -eq 1 ]]; then
    iptables -P INPUT DROP
    ok "INPUT policy = DROP (OUTPUT/FORWARD left ACCEPT: mail, updates, Docker unaffected)"
  fi

  # --- boot persistence ----------------------------------------------
  if command -v systemctl >/dev/null; then
    yum -y -q install iptables-services >/dev/null 2>&1 || true
    systemctl enable iptables >/dev/null 2>&1 || true
  fi
  ( crontab -l 2>/dev/null | grep -v 'cpanel-sentry iptables-restore';
    echo "@reboot /sbin/iptables-restore < /etc/iptables.save # cpanel-sentry iptables-restore" ) | crontab - 2>/dev/null || true

  sentry_persist
  ok "Firewall applied."
  warn "Verify you still have access, then run:  sentry-apply --confirm   (cancels rollback)"
}
