# cPanel Sentry

**A customer-safe hardening & honeypot toolkit for cPanel/WHM servers.**

Born from a real mass-compromise cleanup, cPanel Sentry packages the defensive
measures that actually stop shared-hosting attackers into one interactive
installer — **without ever blocking your customers' websites, mail, FTP, DNS,
or cPanel access.**

> Free & open source (MIT). White-label ready — set your own brand name in the installer.

---

## What it does

| Module | What you get |
|---|---|
| **SSH allowlist** | Locks SSH (port 22) — inbound *and* outbound — to the IPs you specify. Optional lockdown of WHM/cPanel panel ports too. |
| **Customer-safe firewall** | Switches `iptables` INPUT to default-DROP while **auto-detecting and allowing every live service port** (HTTP/S, SMTP/IMAP/POP, FTP + passive, DNS, all cPanel/WHM/webmail/webdisk ports). Closes exposed internals (e.g. rpcbind) and any future backdoor/bind-shell port. Applied behind a **timed auto-rollback** so you can't lock yourself out. |
| **CMS virtual patches** | ModSecurity rules blocking the exploits most used to breach cPanel boxes: **JCE**, **SP Page Builder** (CVE-2024-51256), **AcyMailing**, XML-RPC abuse, and direct hits to known webshell filenames / PHP execution in upload dirs. |
| **Login honeypots** | Deploys fake `wp-login.php` / Joomla `administrator` traps **only where no real login exists** — valid WordPress/Joomla admin paths are detected and never touched. Every probe is logged (IP, host, attempted credentials). |
| **Auto-block engine** | Non-whitelisted IPs that hit a honeypot are blocked at the firewall automatically (configurable threshold / window / TTL). |
| **Admin portal** | A password-protected dashboard (localhost + SSH tunnel) to view catches and manage the allow/block lists. Plus a `sentry-ctl` CLI. |

## Install

```bash
git clone https://github.com/nikolas22t/cpanel-sentry.git
cd cpanel-sentry
sudo bash install.sh
```

The installer asks for everything (nothing is hard-coded):

- **Whitelist IPs/CIDRs** for SSH (your current SSH IP is auto-detected and suggested)
- Whether to lock SSH / panel ports to that allowlist
- Whether to enable the default-DROP firewall, plus any **extra ports** to keep open
- **Auto-rollback** seconds (lock-out safety net)
- Auto-block **threshold / window / TTL**
- Whether to deploy **honeypots**, and the account **home root**
- Whether to install the **portal**, its **install directory**, **URL path**, and **port**
- Your **brand name / tagline** (white-label)

After it runs, confirm SSH still works in a **new** terminal, then:

```bash
sudo sentry-apply --confirm     # cancels the auto-rollback, keeps the ruleset
```

## Everyday use

```bash
sentry-ctl status                # overview
sentry-ctl hits 50               # last 50 honeypot catches
sentry-ctl block   1.2.3.4       # manual block
sentry-ctl unblock 1.2.3.4
sentry-ctl allow   1.2.3.4       # whitelist (also unblocks; honeypots pass it through)
sentry-apply                     # re-apply firewall/rules after editing the config
```

Portal (from your workstation):

```bash
ssh -L 8443:127.0.0.1:8443 root@your-server
# then open http://127.0.0.1:8443/
```

## Why it won't break customer sites

- The firewall **detects every actively-listening service** and allows it, on top of the standard cPanel port list — so nothing customer-facing is dropped.
- Passive FTP keeps working via the kernel **conntrack FTP helper**.
- `OUTPUT`/`FORWARD` stay `ACCEPT` — mail delivery, updates, and Docker are unaffected.
- A **timed auto-rollback** reverts the ruleset unless you explicitly confirm.
- Honeypots are written **only to paths with no existing login file**; a real `wp-login.php` or Joomla `administrator/index.php` is never overwritten (verified by signature check).

## Uninstall

```bash
sudo bash uninstall.sh
```

Removes honeypots (signature-verified, so only Sentry's own files are deleted), the cron job, portal service, and ModSecurity rules — and can restore the pre-Sentry firewall backup.

## Requirements

- cPanel/WHM on RHEL/AlmaLinux/CloudLinux 8/9 (works on most iptables + Apache/ModSecurity setups)
- `iptables` / `iptables-services`, `php` (for the portal & honeypots)

## Security notes

- The portal runs as root bound to `127.0.0.1` and is reached over your (already IP-locked) SSH tunnel; all IP inputs are strictly validated before touching the shell.
- Honeypots never authenticate anyone and record only what a probing client sends. Whitelisted IPs are passed through untouched.
- This is defensive tooling for **servers you own/administer**.

## License

MIT — see [LICENSE](LICENSE). Contributions welcome.
