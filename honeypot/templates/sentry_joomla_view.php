<?php
/**
 * cPanel Sentry — fake Joomla administrator login view (honeypot).
 * Mimics the Joomla admin login. Always returns a warning; never authenticates.
 * $is_post is provided by trap.php.
 */
$err = !empty($is_post);
?><!DOCTYPE html>
<html lang="en-gb" dir="ltr">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<title>Administration - Log in</title>
<style>
*{box-sizing:border-box;}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#1c3d5c;background:linear-gradient(135deg,#1c3d5c,#0e2233);margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;color:#fff;}
.card{width:340px;background:#fff;color:#333;border-radius:6px;padding:28px 26px;box-shadow:0 10px 40px rgba(0,0,0,.35);}
.brand{text-align:center;margin-bottom:18px;font-size:22px;font-weight:600;color:#1c3d5c;}
.brand small{display:block;font-size:12px;color:#888;font-weight:400;margin-top:4px;}
label{font-size:13px;color:#555;display:block;margin:12px 0 4px;}
.inp{position:relative;}
input[type=text],input[type=password]{width:100%;padding:10px 12px;border:1px solid #ccc;border-radius:4px;font-size:15px;}
button{margin-top:20px;width:100%;background:#2a69a3;color:#fff;border:0;border-radius:4px;padding:11px;font-size:15px;cursor:pointer;}
.alert{background:#fbeae5;border:1px solid #e0b4b4;color:#a94442;padding:10px 12px;border-radius:4px;font-size:13px;margin-bottom:12px;}
.foot{text-align:center;margin-top:16px;font-size:12px;color:#999;}
</style>
</head>
<body>
  <div class="card">
    <div class="brand">Administration<small>Content Management System</small></div>
    <?php if ($err): ?><div class="alert">Warning: Username and password do not match or you do not have an account yet.</div><?php endif; ?>
    <form method="post" action="">
      <label for="mod-login-username">Username</label>
      <div class="inp"><input id="mod-login-username" type="text" name="username" autocomplete="username" /></div>
      <label for="mod-login-password">Password</label>
      <div class="inp"><input id="mod-login-password" type="password" name="passwd" autocomplete="current-password" /></div>
      <button type="submit">Log in</button>
    </form>
    <div class="foot">&copy; <?php echo date('Y'); ?> All rights reserved.</div>
  </div>
</body>
</html>
