#!/usr/bin/env bash
# cPanel Sentry — uninstaller. Reverses everything cleanly.
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${LIB_DIR:-/usr/local/cpanel-sentry}"
source "$LIB_DIR/lib/common.sh" 2>/dev/null || source "$SRC/lib/common.sh"
sentry_load_conf; need_root

warn "This will remove honeypots, the block engine, the portal and Sentry files."
read -r -p "Restore the firewall ruleset to the pre-Sentry backup too? [y/N]: " rfw

# honeypots (signature-safe removal)
source "$LIB_DIR/lib/honeypot.sh" 2>/dev/null && honeypot_remove_all || true

# cron + services
( crontab -l 2>/dev/null | grep -v 'cpanel-sentry' ) | crontab - 2>/dev/null || true
if command -v systemctl >/dev/null; then
  systemctl disable --now cpanel-sentry-portal >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/cpanel-sentry-portal.service; systemctl daemon-reload || true
fi

# modsec rule
rm -f /etc/apache2/conf.d/999-cpanel-sentry.conf /usr/local/apache/conf/includes/999-cpanel-sentry.conf /etc/httpd/conf.d/999-cpanel-sentry.conf 2>/dev/null || true
apachectl configtest >/dev/null 2>&1 && { systemctl reload httpd 2>/dev/null || systemctl reload apache2 2>/dev/null || true; }

# firewall
if [[ "${rfw:-n}" =~ ^[Yy] ]] && [[ -f "$STATE_DIR/pre-sentry.rules" ]]; then
  iptables-restore < "$STATE_DIR/pre-sentry.rules" && ok "firewall restored to pre-Sentry state"
  sentry_persist
else
  warn "Firewall rules left in place. Edit with iptables and re-persist if needed."
fi

# binaries + files
for b in sentry-apply sentry-ctl sentry-blocklistd sentry-portal-pass; do rm -f "/usr/local/bin/$b"; done
rm -rf "$LIB_DIR"
read -r -p "Also delete state + logs ($STATE_DIR, $LOG_DIR, /etc/cpanel-sentry)? [y/N]: " rdel
if [[ "${rdel:-n}" =~ ^[Yy] ]]; then rm -rf "$STATE_DIR" "$LOG_DIR" /etc/cpanel-sentry; fi
ok "Uninstalled."
