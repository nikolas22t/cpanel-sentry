<?php
/**
 * cPanel Sentry — fake WordPress login view (honeypot).
 * Mimics the standard wp-login screen. Always returns an auth error.
 * $is_post is provided by trap.php.
 */
$err = !empty($is_post);
?><!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex, nofollow" />
<title>Log In &lsaquo; WordPress</title>
<style>
* { box-sizing: border-box; }
body { background:#f0f0f1; color:#3c434a; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; margin:0; padding:0; }
#login { width:320px; padding:8% 0 0; margin:auto; }
h1 a { background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 122 122"><circle cx="61" cy="61" r="60" fill="%23464b50"/><text x="61" y="82" font-size="70" fill="white" text-anchor="middle" font-family="Georgia">W</text></svg>');
  background-size:84px; background-position:center top; background-repeat:no-repeat; color:#3c434a; height:84px; font-size:20px; font-weight:400; line-height:1.3; margin:0 auto 25px; padding:0; text-decoration:none; width:84px; display:block; text-indent:-9999px; }
form { background:#fff; margin-top:20px; margin-left:0; padding:26px 24px; font-weight:400; overflow:hidden; border:1px solid #c3c4c7; box-shadow:0 1px 3px rgba(0,0,0,.04); }
label { font-size:14px; line-height:1.5; display:inline-block; margin-bottom:3px; }
input[type=text],input[type=password]{ font-size:24px; line-height:1.33; width:100%; padding:3px 5px; margin:2px 0 16px; border:1px solid #8c8f94; border-radius:0; }
.button-primary{ background:#2271b1; border-color:#2271b1; color:#fff; text-decoration:none; text-shadow:none; font-size:13px; line-height:2.15384615; min-height:32px; padding:0 12px; cursor:pointer; border-width:1px; border-style:solid; border-radius:3px; width:100%; }
#login_error{ border-left:4px solid #d63638; padding:12px; margin-left:0; margin-bottom:20px; background:#fff; box-shadow:0 1px 3px rgba(0,0,0,.04); font-size:14px; }
p#nav,p#backtoblog{ font-size:13px; padding:0 24px; margin:24px 0; text-align:center;} a{ color:#50575e; text-decoration:none;}
</style>
</head>
<body class="login">
<div id="login">
  <h1><a href="#">Powered by WordPress</a></h1>
  <?php if ($err): ?>
  <div id="login_error"><strong>Error:</strong> The password you entered is incorrect. <a href="#">Lost your password?</a></div>
  <?php endif; ?>
  <form name="loginform" method="post" action="">
    <p>
      <label for="user_login">Username or Email Address</label>
      <input type="text" name="log" id="user_login" autocapitalize="off" autocomplete="username" value="" />
    </p>
    <p>
      <label for="user_pass">Password</label>
      <input type="password" name="pwd" id="user_pass" autocomplete="current-password" />
    </p>
    <p><input type="checkbox" name="rememberme" value="forever" /> Remember Me</p>
    <p class="submit"><input type="submit" name="wp-submit" class="button-primary" value="Log In" /></p>
  </form>
  <p id="nav"><a href="#">Register</a> | <a href="#">Lost your password?</a></p>
  <p id="backtoblog"><a href="#">&larr; Go to site</a></p>
</div>
</body>
</html>
