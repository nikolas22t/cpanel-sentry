<?php
/**
 * cPanel Sentry — admin portal (single file).
 * Runs as root behind `php -S 127.0.0.1:<port>` (systemd unit), reached via
 * an SSH tunnel. Password-protected. All IP inputs are strictly validated
 * before ever touching the shell (no injection).
 */
session_start();
$CONF = '/etc/cpanel-sentry/sentry.conf';
function cfg($k,$d=''){ static $c=null; global $CONF; if($c===null){$c=[];foreach(@file($CONF)?:[] as $l){if(preg_match('/^\s*([A-Z_]+)="?([^"#]*)"?/',$l,$m))$c[$m[1]]=trim($m[2]);}} return $c[$k]??$d; }
$BRAND   = cfg('BRAND_NAME','cPanel Sentry');
$STATE   = cfg('STATE_DIR','/var/lib/cpanel-sentry');
$LOGD    = cfg('LOG_DIR','/var/log/cpanel-sentry');
$PASSFILE= '/etc/cpanel-sentry/portal.pass';
$CTL     = (cfg('LIB_DIR','/usr/local/cpanel-sentry')).'/bin/sentry-ctl';

/* ---------- auth ---------- */
$stored = is_readable($PASSFILE) ? trim(file_get_contents($PASSFILE)) : '';
if (isset($_POST['login_pass'])) {
    if ($stored && password_verify($_POST['login_pass'], $stored)) { $_SESSION['ok']=1; }
    else { $login_err = 'Wrong password.'; }
}
if (isset($_GET['logout'])) { session_destroy(); header('Location: '.strtok($_SERVER['REQUEST_URI'],'?')); exit; }
$authed = !empty($_SESSION['ok']);

/* ---------- helpers ---------- */
function vip($ip){ return filter_var($ip, FILTER_VALIDATE_IP) !== false; }
function ctl($args){ global $CTL; $out=[]; exec($CTL.' '.$args.' 2>&1', $out); return implode("\n",$out); }

/* ---------- actions (POST) ---------- */
$flash='';
if ($authed && $_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['action'])) {
    $ip = $_POST['ip'] ?? '';
    if (in_array($_POST['action'],['block','unblock','allow','unallow'],true) && vip($ip)) {
        ctl($_POST['action'].' '.escapeshellarg($ip));
        $flash = ucfirst($_POST['action'])." $ip done.";
    } else { $flash='Invalid IP.'; }
}

/* ---------- data ---------- */
function readlist($f){ return is_readable($f) ? array_values(array_filter(array_map('trim', file($f)))) : []; }
$blocked = readlist("$STATE/blocklist.txt");
$allowed = readlist("$STATE/whitelist.txt");
$hits=[]; $hf="$LOGD/hits.log";
if (is_readable($hf)) {
    $lines = array_slice(file($hf, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES), -200);
    foreach (array_reverse($lines) as $l){ $j=json_decode($l,true); if($j) $hits[]=$j; }
}
$fw = trim(shell_exec("iptables -S 2>/dev/null | grep '^-P INPUT' | awk '{print $3}'") ?: 'unknown');
?><!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?=htmlspecialchars($BRAND)?></title>
<style>
:root{--bg:#0f1720;--card:#17212b;--line:#243240;--tx:#e6edf3;--mut:#8899a6;--acc:#2f81f7;--red:#f85149;--grn:#3fb950;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
header{background:var(--card);border-bottom:1px solid var(--line);padding:14px 22px;display:flex;align-items:center;justify-content:space-between}
header h1{font-size:17px;margin:0}header .tag{color:var(--mut);font-size:12px}
.wrap{max-width:1050px;margin:22px auto;padding:0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px}
.stat b{display:block;font-size:26px}.stat span{color:var(--mut);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;margin-bottom:20px;overflow:hidden}
.card h2{font-size:14px;margin:0;padding:12px 16px;border-bottom:1px solid var(--line);background:#1b2732}
table{width:100%;border-collapse:collapse}td,th{padding:8px 16px;text-align:left;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--mut);font-weight:600}tr:last-child td{border-bottom:0}
code{color:#79c0ff}.mut{color:var(--mut)}
button,input[type=submit]{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:7px 12px;cursor:pointer;font-size:13px}
button.red{background:var(--red)}button.grn{background:var(--grn)}
input[type=text],input[type=password]{background:#0d1117;border:1px solid var(--line);color:var(--tx);border-radius:6px;padding:8px 10px;font-size:14px}
.flash{background:#1f6feb22;border:1px solid var(--acc);padding:10px 14px;border-radius:6px;margin-bottom:16px}
.login{max-width:320px;margin:12% auto;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:26px}
.login h1{font-size:18px;margin:0 0 4px}.login p{color:var(--mut);margin:0 0 18px;font-size:13px}
.login input{width:100%;margin-bottom:12px}.err{color:var(--red);font-size:13px;margin-bottom:10px}
form.inline{display:inline}
</style></head><body>
<?php if(!$authed): ?>
  <div class="login">
    <h1><?=htmlspecialchars($BRAND)?></h1><p><?=htmlspecialchars(cfg('BRAND_TAG','Server protection'))?></p>
    <?php if(!empty($login_err))echo '<div class="err">'.htmlspecialchars($login_err).'</div>';?>
    <?php if(!$stored)echo '<div class="err">No portal password set. Run: sentry-portal-pass</div>';?>
    <form method="post"><input type="password" name="login_pass" placeholder="Portal password" autofocus>
    <input type="submit" value="Sign in"></form>
  </div>
<?php else: ?>
  <header><div><h1><?=htmlspecialchars($BRAND)?></h1><div class="tag"><?=htmlspecialchars(cfg('BRAND_TAG',''))?></div></div>
    <a href="?logout=1"><button class="red">Log out</button></a></header>
  <div class="wrap">
    <?php if($flash)echo '<div class="flash">'.htmlspecialchars($flash).'</div>';?>
    <div class="grid">
      <div class="stat"><b><?=($fw==='DROP'?'ON':'OPEN')?></b><span>Firewall (INPUT=<?=htmlspecialchars($fw)?>)</span></div>
      <div class="stat"><b><?=count($blocked)?></b><span>Blocked IPs</span></div>
      <div class="stat"><b><?=count($allowed)?></b><span>Whitelisted IPs</span></div>
      <div class="stat"><b><?=count($hits)?></b><span>Recent honeypot hits</span></div>
    </div>

    <div class="card"><h2>Honeypot catches (latest 200)</h2>
      <table><tr><th>Time</th><th>IP</th><th>Type</th><th>Host / URI</th><th>Tried user:pass</th><th></th></tr>
      <?php if(!$hits):?><tr><td colspan="6" class="mut">No hits yet.</td></tr><?php endif;?>
      <?php foreach($hits as $h): $ip=$h['ip']??''; ?>
        <tr>
          <td class="mut"><?=htmlspecialchars($h['ts']??'')?></td>
          <td><code><?=htmlspecialchars($ip)?></code></td>
          <td><?=htmlspecialchars($h['type']??'')?></td>
          <td class="mut"><?=htmlspecialchars(($h['host']??'').($h['uri']??''))?></td>
          <td class="mut"><?=htmlspecialchars(trim(($h['user']??'').':'.($h['pass']??''),':'))?></td>
          <td>
            <?php if(vip($ip) && !in_array($ip,$blocked,true)):?>
            <form class="inline" method="post"><input type="hidden" name="action" value="block"><input type="hidden" name="ip" value="<?=htmlspecialchars($ip)?>"><button class="red">Block</button></form>
            <?php endif;?>
          </td>
        </tr>
      <?php endforeach;?>
      </table>
    </div>

    <div class="card"><h2>Blocked IPs</h2>
      <table><tr><th>IP</th><th></th></tr>
      <?php foreach($blocked as $ip):?><tr><td><code><?=htmlspecialchars($ip)?></code></td>
        <td><form class="inline" method="post"><input type="hidden" name="action" value="unblock"><input type="hidden" name="ip" value="<?=htmlspecialchars($ip)?>"><button>Unblock</button></form>
        <form class="inline" method="post"><input type="hidden" name="action" value="allow"><input type="hidden" name="ip" value="<?=htmlspecialchars($ip)?>"><button class="grn">Whitelist</button></form></td></tr>
      <?php endforeach; if(!$blocked)echo '<tr><td colspan=2 class="mut">None.</td></tr>';?>
      </table>
    </div>

    <div class="card"><h2>Whitelist (never blocked / honeypots pass through)</h2>
      <table><tr><th>IP</th><th></th></tr>
      <?php foreach($allowed as $ip):?><tr><td><code><?=htmlspecialchars($ip)?></code></td>
        <td><form class="inline" method="post"><input type="hidden" name="action" value="unallow"><input type="hidden" name="ip" value="<?=htmlspecialchars($ip)?>"><button class="red">Remove</button></form></td></tr>
      <?php endforeach; if(!$allowed)echo '<tr><td colspan=2 class="mut">None.</td></tr>';?>
      <tr><td colspan="2"><form method="post"><input type="hidden" name="action" value="allow"><input type="text" name="ip" placeholder="add IP to whitelist"> <input type="submit" value="Add"></form></td></tr>
      </table>
    </div>
    <p class="mut">CLI: <code>sentry-ctl status</code> · <code>sentry-ctl hits</code> · <code>sentry-apply</code></p>
  </div>
<?php endif; ?>
</body></html>
