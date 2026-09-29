#!/usr/bin/env bash
# =====================================================================
#  cPanel Sentry — interactive installer
#  Hardens a cPanel/WHM server (SSH allowlist + customer-safe firewall +
#  CMS virtual patches) and optionally deploys login honeypots that
#  auto-block attackers. Free / MIT. https://github.com/<you>/cpanel-sentry
# =====================================================================
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SRC/lib/common.sh"

need_root
say "cPanel Sentry installer"
echo

# ---- sane defaults ---------------------------------------------------
DEF_ALLOW="$(printf '%s' "${SSH_CLIENT:-}" | awk '{print $1}')"
LIB_DIR=/usr/local/cpanel-sentry
STATE_DIR=/var/lib/cpanel-sentry
LOG_DIR=/var/log/cpanel-sentry
ETC=/etc/cpanel-sentry

ask()      { local p="$1" d="${2:-}" a; read -r -p "$(printf '%s' "$p")${d:+ [$d]}: " a; echo "${a:-$d}"; }
ask_yn()   { local p="$1" d="${2:-y}" a; read -r -p "$p [$([ "$d" = y ] && echo Y/n || echo y/N)]: " a; a="${a:-$d}"; [[ "$a" =~ ^[Yy] ]] && echo 1 || echo 0; }

# ---- gather answers --------------------------------------------------
echo "── SSH / management allowlist ─────────────────────────────"
[[ -n "$DEF_ALLOW" ]] && say "Detected your current SSH IP: $DEF_ALLOW"
ALLOW_IPS="$(ask 'Whitelist IPs/CIDRs allowed for SSH (space separated)' "$DEF_ALLOW")"
if [[ -z "$ALLOW_IPS" ]]; then err "Refusing to continue with an empty allowlist (lock-out risk)."; exit 1; fi
for ip in $ALLOW_IPS; do valid_ip "$ip" || { err "Invalid IP: $ip"; exit 1; }; done
LOCK_SSH="$(ask_yn 'Restrict SSH (22) to the allowlist, inbound + outbound?' y)"
LOCK_PANEL="$(ask_yn 'Also restrict WHM/cPanel panel ports to the allowlist?' n)"

echo; echo "── Firewall ───────────────────────────────────────────────"
ENABLE_FIREWALL="$(ask_yn 'Enable customer-safe default-DROP firewall (all live web/mail/ftp/dns/cpanel ports stay open)?' y)"
EXTRA_TCP_PORTS="$(ask 'Extra inbound TCP ports to keep open (space separated)' '')"
EXTRA_UDP_PORTS="$(ask 'Extra inbound UDP ports to keep open (space separated)' '')"
ROLLBACK_SECONDS="$(ask 'Auto-rollback seconds (safety net against lock-out)' '180')"

echo; echo "── Auto-block engine ──────────────────────────────────────"
BLOCK_THRESHOLD="$(ask 'Honeypot hits before an IP is blocked' '1')"
BLOCK_WINDOW="$(ask 'Counting window in seconds' '3600')"
BLOCK_TTL="$(ask 'Block duration in seconds (0 = permanent)' '0')"

echo; echo "── Honeypots ──────────────────────────────────────────────"
say "Fake wp-login / Joomla admin traps are deployed ONLY where no real"
say "login exists — valid WordPress/Joomla admin paths are never touched."
ENABLE_HONEYPOTS="$(ask_yn 'Deploy login honeypots to accounts?' y)"
HOME_ROOT="$(ask 'Account home root' '/home')"

echo; echo "── Admin portal ───────────────────────────────────────────"
INSTALL_PORTAL="$(ask_yn 'Install the web admin portal (localhost + SSH tunnel)?' y)"
PORTAL_DIR="$(ask 'Portal install directory' "$LIB_DIR/portal")"
PORTAL_URL_PATH="$(ask 'Portal URL path' '/sentry')"
PORTAL_PORT="$(ask 'Portal localhost port' '8443')"

echo; echo "── Branding (white-label) ─────────────────────────────────"
BRAND_NAME="$(ask 'Brand name shown in portal/logs' 'cPanel Sentry')"
BRAND_TAG="$(ask 'Brand tagline' 'Server protection')"

# ---- install files ---------------------------------------------------
echo; say "Installing files…"
mkdir -p "$LIB_DIR" "$STATE_DIR/spool" "$LOG_DIR" "$ETC" "$PORTAL_DIR"
cp -rf "$SRC/lib" "$SRC/bin" "$SRC/honeypot" "$LIB_DIR/"
cp -f  "$SRC/portal/index.php" "$PORTAL_DIR/"
chmod +x "$LIB_DIR"/bin/* 2>/dev/null || true
for b in sentry-apply sentry-ctl sentry-blocklistd; do ln -sf "$LIB_DIR/bin/$b" "/usr/local/bin/$b"; done
touch "$STATE_DIR/whitelist.txt" "$STATE_DIR/blocklist.txt"
chmod 0733 "$STATE_DIR/spool" 2>/dev/null || true

# seed whitelist with allowlist IPs (they must never be trapped/blocked)
for ip in $ALLOW_IPS; do grep -qxF "$ip" "$STATE_DIR/whitelist.txt" || echo "$ip" >> "$STATE_DIR/whitelist.txt"; done

# ---- write config ----------------------------------------------------
cat > "$ETC/sentry.conf" <<EOF
# cPanel Sentry config — generated $(date '+%F %T')
BRAND_NAME="$BRAND_NAME"
BRAND_TAG="$BRAND_TAG"
ALLOW_IPS="$ALLOW_IPS"
LOCK_SSH=$LOCK_SSH
LOCK_PANEL=$LOCK_PANEL
ENABLE_FIREWALL=$ENABLE_FIREWALL
EXTRA_TCP_PORTS="$EXTRA_TCP_PORTS"
EXTRA_UDP_PORTS="$EXTRA_UDP_PORTS"
ROLLBACK_SECONDS=$ROLLBACK_SECONDS
BLOCK_THRESHOLD=$BLOCK_THRESHOLD
BLOCK_WINDOW=$BLOCK_WINDOW
BLOCK_TTL=$BLOCK_TTL
ENABLE_HONEYPOTS=$ENABLE_HONEYPOTS
HOME_ROOT="$HOME_ROOT"
INSTALL_PORTAL=$INSTALL_PORTAL
PORTAL_DIR="$PORTAL_DIR"
PORTAL_URL_PATH="$PORTAL_URL_PATH"
PORTAL_PORT=$PORTAL_PORT
STATE_DIR="$STATE_DIR"
LOG_DIR="$LOG_DIR"
LIB_DIR="$LIB_DIR"
EOF
chmod 600 "$ETC/sentry.conf"
ok "Config written -> $ETC/sentry.conf"

# ---- block-engine cron ----------------------------------------------
( crontab -l 2>/dev/null | grep -v 'sentry-blocklistd';
  echo "* * * * * $LIB_DIR/bin/sentry-blocklistd >/dev/null 2>&1 # cpanel-sentry" ) | crontab -
ok "Block engine scheduled (every minute)."

# ---- portal password + service --------------------------------------
if [[ "$INSTALL_PORTAL" -eq 1 ]]; then
  cat > /usr/local/bin/sentry-portal-pass <<'PP'
#!/usr/bin/env bash
read -r -s -p "New portal password: " p; echo
php -r 'echo password_hash($argv[1], PASSWORD_DEFAULT);' "$p" > /etc/cpanel-sentry/portal.pass
chmod 600 /etc/cpanel-sentry/portal.pass; echo "Portal password set."
PP
  chmod +x /usr/local/bin/sentry-portal-pass
  say "Set a portal password now:"; sentry-portal-pass || warn "Set later with: sentry-portal-pass"
  if command -v systemctl >/dev/null; then
    cat > /etc/systemd/system/cpanel-sentry-portal.service <<EOF
[Unit]
Description=$BRAND_NAME admin portal
After=network.target
[Service]
ExecStart=$(command -v php) -S 127.0.0.1:$PORTAL_PORT -t $PORTAL_DIR
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable --now cpanel-sentry-portal >/dev/null 2>&1 || true
    ok "Portal running on 127.0.0.1:$PORTAL_PORT — reach it with:"
    echo "    ssh -L $PORTAL_PORT:127.0.0.1:$PORTAL_PORT root@<server>   then open http://127.0.0.1:$PORTAL_PORT/"
  fi
fi

# ---- honeypots -------------------------------------------------------
if [[ "$ENABLE_HONEYPOTS" -eq 1 ]]; then
  say "Deploying honeypots…"; source "$LIB_DIR/lib/honeypot.sh"; honeypot_deploy_all
fi

# ---- firewall + modsec (last, with rollback) -------------------------
say "Applying firewall + ModSecurity virtual patches…"
sentry-apply
echo
ok "Install complete."
warn "IMPORTANT: confirm you still have SSH access in a NEW terminal, then run:"
echo "    sentry-apply --confirm      # cancels the ${ROLLBACK_SECONDS}s auto-rollback"
echo
say "Status any time:  sentry-ctl status    |   Catches:  sentry-ctl hits"
