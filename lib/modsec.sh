#!/usr/bin/env bash
# cPanel Sentry — ModSecurity virtual-patch rules for the CMS exploits
# most commonly used to breach shared cPanel boxes. Purely defensive:
# it blocks known exploit request shapes and direct webshell hits.

ms_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$ms_here/common.sh"

modsec_apply() {
  need_root; sentry_load_conf
  local conf_dir rule
  for conf_dir in /etc/apache2/conf.d /usr/local/apache/conf/includes /etc/httpd/conf.d; do
    [[ -d "$conf_dir" ]] && break
  done
  [[ -d "$conf_dir" ]] || { warn "Apache conf dir not found; skipping ModSecurity rules."; return 0; }
  rule="$conf_dir/999-cpanel-sentry.conf"

  cat > "$rule" <<'CONF'
# cPanel Sentry virtual patches (defensive). IDs 2600000+.
<IfModule mod_security2.c>
    # Joomla JCE editor file-upload RCE
    SecRule QUERY_STRING "@rx option=com_jce" "id:2600001,phase:2,t:lowercase,t:urlDecodeUni,chain,deny,status:403,log,msg:'Sentry: JCE exploit attempt'"
        SecRule QUERY_STRING "@rx task=(profiles\.import|folderrename|upload)" "t:lowercase,t:urlDecodeUni"
    # SP Page Builder unauthenticated upload (CVE-2024-51256)
    SecRule QUERY_STRING "@rx option=com_sppagebuilder" "id:2600002,phase:2,t:lowercase,t:urlDecodeUni,chain,deny,status:403,log,msg:'Sentry: SP Page Builder upload'"
        SecRule QUERY_STRING "@rx (uploadcustomicon|ajax|upload)" "t:lowercase,t:urlDecodeUni"
    # AcyMailing upload/import abuse
    SecRule QUERY_STRING "@rx option=com_acym" "id:2600003,phase:2,t:lowercase,t:urlDecodeUni,chain,deny,status:403,log,msg:'Sentry: AcyMailing abuse'"
        SecRule QUERY_STRING "@rx (upload|import)" "t:lowercase,t:urlDecodeUni"
    # Direct hits to common dropped webshell filenames
    SecRule REQUEST_FILENAME "@rx /(anonymousfox|up_[0-9]+|sh?e?11|priv(te)?|filefuns|binlookup|wso|c99|r57|alfa|xleet)\.(php|pht|phtml|php[0-9]|suspected)$" "id:2600004,phase:1,deny,status:403,log,msg:'Sentry: known webshell filename'"
    # PHP execution inside upload/media/tmp dirs (webshell staging)
    SecRule REQUEST_FILENAME "@rx /(wp-content/uploads|images|media|tmp|cache|\.well-known)/.*\.(php|pht|phtml|php[0-9])$" "id:2600005,phase:1,deny,status:403,log,msg:'Sentry: PHP in upload path'"
</IfModule>
CONF

  if apachectl configtest 2>&1 | grep -qi "Syntax OK"; then
    systemctl reload httpd 2>/dev/null || systemctl reload apache2 2>/dev/null \
      || /usr/local/cpanel/scripts/restartsrv_httpd 2>/dev/null || true
    ok "ModSecurity virtual patches installed -> $rule"
  else
    err "Apache config test failed; removing Sentry rule to stay safe."
    rm -f "$rule"; return 1
  fi
}
