# Getting started with NetGuard

Step-by-step guides. Pick the one that fits you:

1. [I want to install NetGuard on my Windows PC or server](#1-install-netguard-windows)
2. [Someone invited me to their NetGuard dashboard](#2-you-were-invited)
3. [I'm the owner and want to invite someone](#3-invite-someone-owners)
4. [First-day checklist (after installing)](#4-first-day-checklist)
5. [Everyday use](#5-everyday-use)
6. [Help, I'm locked out](#6-locked-out)

For details on every feature, see the [README](README.md).

---

## 1. Install NetGuard (Windows)

**You need:**
* Windows 10/11 or Windows Server 2016+ and an administrator account.
* **Python 3.8 or newer, installed for all users.** In the python.org installer, choose *Customize installation* and tick **Install Python for all users**. NetGuard's dashboard runs as the Windows SYSTEM account, which can't use a Python installed only for your user.
* An internet connection (setup downloads one Python package, `cryptography`).
* A phone with an authenticator app: Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden or similar.

**Steps:**
1. On this GitHub page, click the green **Code** button, then **Download ZIP**.
2. Extract the ZIP to a permanent folder, e.g. `C:\NetGuard`. Don't run it from the Downloads folder or from inside the ZIP.
3. Double-click **`Setup.cmd`**.
   * If Windows says the file is blocked: right-click `Setup.cmd`, choose **Properties**, tick **Unblock**, then **OK**, and try again.
   * If you see "Windows protected your PC": click **More info**, then **Run anyway**.
4. Click **Yes** on the administrator prompt.
5. Choose what the dashboard may do on this machine:
   * **1, Safe mode** (press Enter): recommended for a personal PC. You can trust programs, kill or quarantine processes, run audits and backups. Hardening fixes and firewall changes are refused.
   * **2, Full control:** also allows hardening fixes and blocking IPs or ports. Each one still needs your click and confirmation.
6. Wait for **"NetGuard is installed"**. The dashboard opens in your browser, and the **one-time password** is shown and copied to the clipboard.
7. **First sign-in:**
   1. Username **`admin`**; paste the one-time password.
   2. Choose your own password: **12 or more characters**. A short sentence is easy to remember.
   3. **Set up 2-factor:** in your authenticator app, tap **Add account**, then **Enter a setup key**, and type the key shown on screen (time-based). Then type the **6-digit code** the app shows and click **Turn on 2-factor & sign in**.
8. Done. Now go through the [first-day checklist](#4-first-day-checklist).

NetGuard starts automatically with Windows. Running `Setup.cmd` again is safe: it upgrades and keeps your password, alerts and settings.

**Linux servers** are monitored by installing just the agent there and pointing it at your dashboard. See *Install agents* in the [README](README.md#2-install-agents).

---

## 2. You were invited

Someone sent you a NetGuard invite link. The link works **once** and expires after **48 hours**.

1. **Install Tailscale** on your laptop or phone (https://tailscale.com/download). Accept the Tailscale invite you got by email and sign in. This is what lets you reach the dashboard privately. If you'll only ever use the dashboard on the owner's own PC, skip this step.
2. **Install an authenticator app** on your phone: Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden or similar.
3. **Open the invite link.** It shows who invited you, your role and which servers you can see:
   * **viewer:** can look, can't change anything
   * **admin:** can act on alerts, backups and the vault
   * **owner:** everything, including managing people
4. **Create your account:** choose a username (lowercase letters, numbers, `.` `-` `_`, e.g. `ravi`), your name, and a password of **12+ characters**, typed twice.
5. **Set up 2-factor:** in the authenticator app, tap **Add account**, then **Enter a setup key**, and type the key shown. Enter the **6-digit code** and click **Turn on 2-factor & sign in**.
6. You're in. **Bookmark the address** (it looks like `https://<name>.<tailnet>.ts.net`).

Next time: open the bookmark, then enter your username, password and the 6-digit code from the app.

---

## 3. Invite someone (owners)

1. **If they're not at your PC, set up remote access first** (once):
   1. Install Tailscale on the dashboard PC and sign in.
   2. In the Tailscale admin console, open **DNS** and turn on **MagicDNS** and **HTTPS Certificates**.
   3. Run `Setup.cmd` again and answer **Y** at *Remote access*. Note the `https://…ts.net` address it prints.
   4. In the Tailscale admin console, go to **Users**, then **Invite**, and invite their email (or share just this machine).
2. **Open the dashboard at the `https://…ts.net` address**, not 127.0.0.1, so the invite link works for them.
3. Go to **People**, click **Invite someone**, and choose:
   * **Role:** viewer, admin or owner.
   * **Servers:** all, or only specific ones.
4. **Copy the link** and send it **privately**, e.g. in a direct message, never in a group chat. Then point them to [section 2](#2-you-were-invited).

To change someone's role or servers, use **People → Edit**. To cut off access immediately, use **Disable** or **Remove**: they're signed out everywhere.

---

## 4. First-day checklist

About 15 minutes; do it in this order.

1. **Get alerts on your phone** (owners)
   * Go to **Settings → Notifications → Add channel**. Telegram, Discord, Teams and email all work; Telegram is the quickest.
   * Save it, click **Send test**, and check your phone.
2. **Back up the server**
   * Go to **Backups → New backup job**.
   * **Server:** the machine. **What:** tick *Server configuration*, add important folders (one per line), and tick *Website files* if it's a web server. Databases must first be added in the **Vault**.
   * **Where:** a folder on another drive or a USB stick (e.g. `E:\Backups`), and ideally cloud storage too (add it in the Vault first).
   * **Save, then copy the recovery key it shows to somewhere safe and offline**, like a password manager or a printout. Without it, the backups can't be opened.
   * The first backup starts within about 2 minutes. Check **Last backup** in the table.
3. **Keep the master key safe** (owners)
   * Copy `C:\ProgramData\NetGuard-Dashboard\netguard.key` to the same safe place as the recovery key. Windows asks for admin rights to open that folder.
   * Then go to **Risk** and click **"I have stored netguard.key and all backup recovery keys offline"**.
4. **Set recovery goals**
   * Go to **DR plans → Create plan** for each server.
   * **RPO** = how many hours of data you can afford to lose; **RTO** = how quickly it must work again. Example for a personal PC: Tier 3, RPO 24 h, RTO 8 h.
   * Print the runbook and keep it with the offline keys.
5. **Go through the alerts**
   * Click each alert. Read *What this means / how to decide*, then choose:
     * **Fix the cause**, e.g. *Apply fix*, which needs full-control mode.
     * **Contain the threat:** quarantine, kill or block.
     * **It's legitimate:** trust the program, accept the port, or accept the risk with a reason.
     * **Not a real problem:** mark it a false positive.
6. **Work down the Risk tab**: it lists what's still weak, most serious first, with what to do. Fix items, or **Accept…** them with a reason.
7. **Invite a second owner** ([section 3](#3-invite-someone-owners)), so you're not the only person who can manage NetGuard.

---

## 5. Everyday use

| I want to… | Do this |
|---|---|
| Open the dashboard | On the dashboard PC: **http://127.0.0.1:8787**. From anywhere (with Tailscale): your `https://…ts.net` address |
| Sign in | Username, then password, then the 6-digit code from the authenticator app |
| Sign out | Click your name (top right), then **Sign out**. You're also signed out after 8 h without activity |
| See what needs attention | **Alerts** (newest problems), **Risk** (overall weak spots), the daily summary message |
| Check backups | **Backups**: last backup and last test restore for every job |
| Restore files | **Backups → Restore…**: files go into a new folder; nothing is overwritten |
| Change my password | Your name (top right) → **Change password** |
| See where I'm signed in | Your name (top right) → **My signed-in devices** |
| Upgrade NetGuard | Download the new version, extract it over the old folder, run **`Setup.cmd`** |
| Remove NetGuard | Double-click **`Uninstall.cmd`** |

---

## 6. Locked out

| Problem | Fix |
|---|---|
| Forgot my password or lost my phone (not the only owner) | Ask an owner: **People → Reset sign-in** gives you a new link. You set a new password and 2-factor again |
| I'm the owner and locked out | On the dashboard PC, run **`Show-Login.cmd -ResetPassword`** and click **Yes**. Sign in with the one-time password it prints, then set a new password and 2-factor |
| "Account locked" | 5 wrong passwords or codes lock the account for 15 minutes. Wait, or ask an owner to reset it |
| "That code didn't match" | Use the newest code, and make sure the phone's clock is set automatically |
| Lost the one-time password from setup | Double-click **`Show-Login.cmd`** |
| Dashboard doesn't open | Run **`Setup.cmd`** again; if something is wrong it shows the reason |
| Need a backup but NetGuard is gone | `python tools\ng-decrypt.py BACKUP.ngbk out.zip --key <recovery key>`, then extract `out.zip` |
