#!/usr/bin/env bash
# cPanel Sentry — honeypot deployment.
#
# Deploys fake wp-login.php / administrator/index.php traps to account
# docroots. It NEVER overwrites a valid CMS login: a trap is written only
# when no file already exists at that path. Real WordPress/Joomla installs
# are therefore left completely untouched.
#
# Each trap writes hits into <docroot>/.sentry/spool (inside the account
# home, so PHP open_basedir is respected). The root daemon consumes them.

hp_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$hp_here/common.sh"

SENTRY_SIG="cPanel Sentry — honeypot trap"

# Gather every docroot: public_html + any documentroot in cPanel userdata.
hp_list_docroots() {
  local u f dr
  for d in "$HOME_ROOT"/*/public_html; do [[ -d "$d" ]] && echo "$d"; done
  if [[ -d /var/cpanel/userdata ]]; then
    for u in /var/cpanel/userdata/*; do
      [[ -d "$u" ]] || continue
      for f in "$u"/*; do
        [[ -f "$f" ]] || continue
        dr=$(grep -m1 '^documentroot:' "$f" 2>/dev/null | awk '{print $2}')
        [[ -n "$dr" && -d "$dr" ]] && echo "$dr"
      done
    done
  fi
}

hp_owner_of() { stat -c '%U' "$1" 2>/dev/null; }

# Is there a REAL WordPress serving from this docroot?
hp_has_real_wordpress() {
  local d="$1"
  [[ -f "$d/wp-login.php" && -f "$d/wp-includes/version.php" ]] && ! grep -q "$SENTRY_SIG" "$d/wp-login.php" 2>/dev/null
}
# Is there a REAL Joomla admin here?
hp_has_real_joomla() {
  local d="$1"
  [[ -f "$d/administrator/index.php" && -f "$d/configuration.php" ]] && ! grep -q "$SENTRY_SIG" "$d/administrator/index.php" 2>/dev/null
}

hp_write_trap() {   # $1=target_php  $2=type(wordpress|joomla)  $3=rel_path_to_.sentry
  local target="$1" type="$2" rel="$3"
  cat > "$target" <<PHP
<?php
/* $SENTRY_SIG ($type). Auto-generated. Safe to delete. */
\$SENTRY_TRAP_TYPE = '$type';
require __DIR__ . '/$rel/.sentry/trap.php';
PHP
}

hp_deploy_one() {
  local docroot="$1" owner sdir
  owner="$(hp_owner_of "$docroot")"; [[ -n "$owner" && "$owner" != root ]] || return 0
  sdir="$docroot/.sentry"
  mkdir -p "$sdir/spool"
  cp -f "$LIB_DIR/honeypot/trap.php"                       "$sdir/trap.php"
  cp -f "$LIB_DIR/honeypot/templates/sentry_wp_view.php"   "$sdir/sentry_wp_view.php"
  cp -f "$LIB_DIR/honeypot/templates/sentry_joomla_view.php" "$sdir/sentry_joomla_view.php"
  cp -f "$WHITELIST_FILE" "$sdir/whitelist.txt" 2>/dev/null || : > "$sdir/whitelist.txt"

  local made=0
  # ---- WordPress trap (only if no real WP AND no existing wp-login) ----
  if ! hp_has_real_wordpress "$docroot" && [[ ! -e "$docroot/wp-login.php" ]]; then
    hp_write_trap "$docroot/wp-login.php" wordpress "."
    # /wp-admin/ probe catcher (only if wp-admin absent)
    if [[ ! -e "$docroot/wp-admin" ]]; then
      mkdir -p "$docroot/wp-admin"
      hp_write_trap "$docroot/wp-admin/index.php" wordpress ".."
    fi
    made=1
  fi
  # ---- Joomla trap (only if no real Joomla admin) --------------------
  if ! hp_has_real_joomla "$docroot" && [[ ! -e "$docroot/administrator/index.php" ]]; then
    mkdir -p "$docroot/administrator"
    hp_write_trap "$docroot/administrator/index.php" joomla ".."
    made=1
  fi

  chown -R "$owner":"$owner" "$sdir" 2>/dev/null
  [[ -f "$docroot/wp-login.php" ]] && grep -q "$SENTRY_SIG" "$docroot/wp-login.php" && chown "$owner":"$owner" "$docroot/wp-login.php"
  [[ -d "$docroot/wp-admin" ]] && chown -R "$owner":"$owner" "$docroot/wp-admin" 2>/dev/null
  [[ -d "$docroot/administrator" ]] && chown -R "$owner":"$owner" "$docroot/administrator" 2>/dev/null

  if [[ "$made" -eq 1 ]]; then
    grep -qxF "$sdir" "$STATE_DIR/honeypots.manifest" 2>/dev/null || echo "$sdir" >> "$STATE_DIR/honeypots.manifest"
    ok "honeypot -> $docroot (owner $owner)"
  else
    # still register .sentry for whitelist sync even if traps were skipped
    grep -qxF "$sdir" "$STATE_DIR/honeypots.manifest" 2>/dev/null || echo "$sdir" >> "$STATE_DIR/honeypots.manifest"
    say "skipped traps for $docroot (real CMS present) — left admin paths untouched"
  fi
}

honeypot_deploy_all() {
  need_root; sentry_load_conf
  mkdir -p "$STATE_DIR"; : > "$STATE_DIR/honeypots.manifest"
  local d seen=""
  while read -r d; do
    [[ -z "$d" ]] && continue
    case " $seen " in *" $d "*) continue;; esac
    seen="$seen $d"
    hp_deploy_one "$d"
  done < <(hp_list_docroots | sort -u)
  ok "Honeypot deployment complete. Manifest: $STATE_DIR/honeypots.manifest"
}

# Remove every Sentry honeypot file (identified by signature) — safe: it
# only deletes files that contain the Sentry signature, never real ones.
honeypot_remove_all() {
  need_root; sentry_load_conf
  local sdir base f
  [[ -f "$STATE_DIR/honeypots.manifest" ]] || { warn "no manifest"; return 0; }
  while read -r sdir; do
    [[ -d "$sdir" ]] || continue
    base="$(dirname "$sdir")"
    for f in "$base/wp-login.php" "$base/wp-admin/index.php" "$base/administrator/index.php"; do
      [[ -f "$f" ]] && grep -q "$SENTRY_SIG" "$f" 2>/dev/null && { rm -f "$f"; ok "removed $f"; }
    done
    # drop dirs only if we created them and they are now empty
    [[ -d "$base/wp-admin" ]] && rmdir "$base/wp-admin" 2>/dev/null
    [[ -d "$base/administrator" ]] && rmdir "$base/administrator" 2>/dev/null
    rm -rf "$sdir"
  done < "$STATE_DIR/honeypots.manifest"
  : > "$STATE_DIR/honeypots.manifest"
  ok "Honeypots removed."
}
