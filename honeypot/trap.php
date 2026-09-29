<?php
/**
 * cPanel Sentry — honeypot trap core (defensive).
 *
 * Included by the fake wp-login.php / administrator/index.php that Sentry
 * deploys ONLY to accounts which do not run a real WordPress/Joomla there.
 * It records the probing IP (and any credentials the bot submits) to a
 * spool the root-side daemon consumes to auto-block, then serves a
 * realistic-looking login that never succeeds.
 *
 * Whitelisted IPs (your admins) are passed through untouched so no
 * legitimate person is ever trapped.
 *
 * Set $SENTRY_TRAP_TYPE = 'wordpress' | 'joomla' before including.
 */

if (!isset($SENTRY_TRAP_TYPE)) { $SENTRY_TRAP_TYPE = 'wordpress'; }

$SENTRY_SPOOL     = '/var/lib/cpanel-sentry/spool';
$SENTRY_WHITELIST = '/var/lib/cpanel-sentry/whitelist.txt';

/* ---- resolve real client IP (behind Cloudflare/proxy if present) ---- */
function sentry_client_ip() {
    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $k) {
        if (!empty($_SERVER[$k])) {
            $ip = trim(explode(',', $_SERVER[$k])[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

$sentry_ip = sentry_client_ip();

/* ---- whitelist passthrough: never trap your own team --------------- */
if (is_readable($SENTRY_WHITELIST)) {
    $wl = file($SENTRY_WHITELIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (in_array($sentry_ip, $wl, true)) {
        // Behave as if nothing special is here.
        header('HTTP/1.1 404 Not Found');
        echo "Not Found";
        exit;
    }
}

/* ---- record the hit ------------------------------------------------ */
$record = [
    'ts'     => date('c'),
    'ip'     => $sentry_ip,
    'type'   => $SENTRY_TRAP_TYPE,
    'host'   => $_SERVER['HTTP_HOST'] ?? '',
    'uri'    => $_SERVER['REQUEST_URI'] ?? '',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'ua'     => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 300),
    'user'   => '',
    'pass'   => '',
];
if (($record['method'] === 'POST')) {
    // Capture attempted credentials (evidence of brute force). Truncated.
    $u = $_POST['log'] ?? $_POST['username'] ?? $_POST['user'] ?? '';
    $p = $_POST['pwd'] ?? $_POST['passwd'] ?? $_POST['password'] ?? $_POST['pass'] ?? '';
    $record['user'] = substr((string)$u, 0, 128);
    $record['pass'] = substr((string)$p, 0, 128);
}

@mkdir($SENTRY_SPOOL, 01733, true);
$fn = $SENTRY_SPOOL . '/' . date('Ymd-His') . '-' . bin2hex(random_bytes(4)) . '.json';
@file_put_contents($fn, json_encode($record) . "\n", LOCK_EX);
@chmod($fn, 0644);

/* ---- serve a believable, never-succeeding login -------------------- */
// Small random delay: slows brute-force bots (tarpit) without hurting UX.
usleep(random_int(400000, 1200000));
http_response_code(200);
header('Content-Type: text/html; charset=UTF-8');

$is_post = ($record['method'] === 'POST');
if ($SENTRY_TRAP_TYPE === 'joomla') {
    require __DIR__ . '/sentry_joomla_view.php';
} else {
    require __DIR__ . '/sentry_wp_view.php';
}
exit;
