# NetGuard: server hardening and network monitoring

These scripts harden and monitor Linux and Windows servers. A web dashboard shows the alerts, explains each one and lets you decide what to do: resolve it, suppress it as a false positive, or run a fix on the server.

```
             ┌────────────── dashboard (server.py, port 8787) ──────────────┐
             │  alerts · playbooks · approve fixes · suppress · audit log   │
             └───────▲──────────────────────────────────────▲──────────────┘
       report + get  │ approved commands       report + get │ approved commands
             ┌───────┴────────┐                     ┌───────┴────────┐
             │ Linux agent    │                     │ Windows agent  │
             │ netguard_agent │                     │ NetGuard-Agent │
             │  └ harden.sh   │                     │  └ Harden-...  │
             └────────────────┘                     └────────────────┘
```

Agents only make outbound HTTPS calls. The dashboard never connects to your servers. Remediation runs **only** after you click it in the dashboard. It runs at the agent's next check-in (60 s or less), and the agent validates every command again before running it.

There is nothing to install with pip: everything uses the Python 3.6+ standard library, or PowerShell 5.1+.

| Folder | What's in it |
|---|---|
| `dashboard/` | `server.py` (API, SQLite, auth) and `static/` (the UI) |
| `hardening/linux/harden.sh` | 49 checks: SSH, firewall, fail2ban, automatic updates, auditd, sysctl, permissions, accounts, sudo, services |
| `hardening/windows/Harden-Server.ps1` | 24 checks: firewall, SMBv1 and signing, RDP NLA, LLMNR, WDigest, LSA, NTLMv1, audit policy, Defender, TLS, PowerShell logging and more |
| `agents/linux/` | `netguard_agent.py` and `install.sh` (installs a systemd service) |
| `agents/windows/` | `NetGuard-Agent.ps1` and `Install-Agent.ps1` (installs a scheduled task that runs as SYSTEM every minute) |

---

## Quick install on one Windows PC (dashboard + agent)

**Double-click `Setup.cmd`** and approve the administrator (UAC) prompt. Setup:

1. asks for **safe mode** (the default) or **full control**. In safe mode you can trust or accept, kill, quarantine or restore, run audits and undo; hardening fixes and new firewall blocks are refused
2. installs the dashboard (`C:\Program Files\NetGuard`, starts at boot, http://127.0.0.1:8787, this PC only)
3. installs the agent (a SYSTEM task that runs every minute) and connects it to the dashboard
4. waits for the PC to report in, shows the login (the password is copied to the clipboard) and opens the dashboard

The password is also stored in `C:\ProgramData\NetGuard-Dashboard\config.json` (readable by admins only). Running `Setup.cmd` again is safe: it upgrades the files and keeps your password and alerts.
**Uninstall:** double-click `Uninstall.cmd`. Add `-RemoveData` from a terminal to delete alerts and hardening backups too.

## People, sign-in and remote access

**Accounts.** Everyone signs in with their own username, password (12+ characters, stored as a PBKDF2 hash) and a **2-factor code** from an authenticator app. 2-factor is required for every account.

| Role | Can |
|---|---|
| owner | everything, including inviting and removing people, and hiding an alert on every server |
| admin | view and act on alerts (fix, quarantine, block, undo, hide on one server) |
| viewer | read-only |

Each person can be limited to **specific servers**. They won't see other servers, their alerts or their audit entries. Every action in the audit log carries the person's name.

* **First sign-in after installing or upgrading:** user `admin` with the one-time password printed by setup (`Show-Login.cmd` shows it again). You're then asked to choose your own password and set up 2-factor, and the one-time password is erased from `config.json`.
* **Adding admins:** go to People, then **Invite someone**. Pick a role and servers, then send the link privately. It works once and expires after 48 h.
* **Lost phone or forgotten password:** an owner clicks **Reset sign-in** to send a new link. If *you* are the owner and locked out, run `Show-Login.cmd -ResetPassword` on the server (as administrator). It prints a one-time password and signs that account out everywhere.
* **Protections:**
  * 5 wrong passwords or codes lock the account for 15 minutes
  * 2-factor codes can't be reused
  * sessions end after 8 h idle or 7 days at most
  * owners can sign out any device (People, then Signed-in devices)
  * cookies are HttpOnly and SameSite=Strict, and every change requires a CSRF header

**Reach it from anywhere, privately (Tailscale).** The dashboard keeps listening on `127.0.0.1` only. Tailscale publishes it **only to devices in your Tailscale network**, with a real HTTPS certificate, and opens nothing to the internet.

1. Install Tailscale on the dashboard PC (https://tailscale.com/download) and sign in.
2. In the Tailscale admin console, open **DNS** and turn on **MagicDNS** and **HTTPS Certificates**.
3. Run `Setup.cmd` again and answer **Y** at *Remote access*. You get an address like `https://my-pc.tail1234.ts.net`.
4. Install Tailscale on your phone or laptop with the same account to use it from anywhere.
5. **Other admins:** invite them to your tailnet (Tailscale admin console, then **Users**, then **Invite**, or share just this machine). Then send them a NetGuard invite link **created while you're on the Tailscale address**, so the link uses it.
6. **Agents on other servers:** install Tailscale there too and point the agent at the same address (`Install-Agent.ps1 -Server https://my-pc.tail1234.ts.net -Token <agent token>`).

## 0. Try it without a server (local lab)

The lab uses your PC as the "Windows server" and WSL Ubuntu as the "Linux server", and runs the dashboard locally. Nothing is installed as a service.

```powershell
# from an elevated PowerShell (Run as administrator) in this folder
.\lab\Start-Lab.ps1            # dashboard + Windows agent + Linux agent in WSL; opens the browser
.\lab\Start-Decoys.ps1         # 10 minutes of harmless fake threats on both "servers"
.\lab\Stop-Lab.ps1             # stop everything (-Reset also wipes the lab's alerts and config)
```

* Log in as `admin`. The password is printed by `Start-Lab.ps1` and stored in `lab\.labdata\config.json`.
* Decoys trigger:
  * a fake `svchost.exe` and a look-alike `scvhost.exe`
  * an unsigned listener
  * PowerShell holding a port
  * in WSL: a fake `sshd` from `/tmp`, a fake `[kworker]`, a fileless process, `nc` holding a port, and an unpackaged server
  * hardening findings on both hosts
* Practise with them: open an alert, read the playbook, then Kill, Trust, Accept, Suppress or Resolve.
* **Safety:** on Windows the lab agent can only accept or trust listeners, kill processes and run audits. Hardening fixes and firewall actions are refused, so you can't change your real PC by accident. Pass `-AllowWindowsFixes` to change that. In WSL every action is allowed: it's a sandbox, and `wsl --unregister` resets it.
* Without elevation, Windows hides service-process paths, so many system listeners show as "unknown". Run elevated for realistic results.
* To test **Apply fix** for real, use a throwaway VM (Hyper-V, VMware or VirtualBox with Windows Server Evaluation or Ubuntu Server) and install the agent there with the normal installer.

## 1. Start the dashboard

```bash
cd dashboard
python3 server.py
```

On first run it creates `config.json` with a random **admin password** and **agent token**, and prints both. Open http://127.0.0.1:8787 and log in as `admin`.

To accept connections from agents on other machines, set `"listen_host": "0.0.0.0"` in `config.json`. **Use TLS**: either set `tls_cert` and `tls_key`, or put the dashboard behind nginx or Caddy. Basic auth and the agent token are sent in clear text over plain HTTP. On Linux, `netguard-dashboard.service` runs the dashboard as a locked-down service.

`config.json` options: `listen_host`, `listen_port`, `admin_user`, `admin_password`, `agent_token`, `db_path`, `offline_after_seconds` (default 300, after which an "agent offline" alert is raised), `tls_cert`, `tls_key`.

## 2. Install agents

**Linux** (as root; needs `python3` and `ss`):
```bash
sudo ./agents/linux/install.sh --server https://dashboard.example.com:8787 --token <agent_token> --trusted 10.0.0.5
```

**Windows** (elevated PowerShell):
```powershell
.\agents\windows\Install-Agent.ps1 -Server https://dashboard.example.com:8787 -Token <agent_token> -TrustedIps 10.0.0.5
```

`--trusted` / `-TrustedIps` lists IPs or CIDRs that should never raise alerts and can never be blocked: your admin workstation, VPN, load balancer and monitoring. The installers also copy the hardening script next to the agent.

The **first run records the current listening ports as the baseline**. After that, any new listener raises an alert.

To try it without installing anything:
```powershell
.\agents\windows\NetGuard-Agent.ps1 -ConfigPath .\my-agent.json -DryRun   # prints the report
```
```bash
python3 agents/linux/netguard_agent.py --config my-agent.json --once --dry-run
```

## 3. Handling alerts

Click any alert to open its panel. It shows:

* **What this means / how to decide**: a short playbook for that alert type, covering what it means, what to check and what your options are.
* **Evidence**: remote IP, process, PID, executable path, command line, ports, usernames tried and so on.
* **Remediate on host**: one-click fixes suggested for this alert. You confirm each one, and you can add a note.
* **Decide**:
  * **Acknowledge**: you are investigating.
  * **Resolve**: done. If the condition is still present, the agent raises a new alert.
  * **Suppress**: a known false positive. You can scope it to this alert or the whole rule, on this host or all hosts, for 1, 7 or 30 days or forever.
* **History**: every decision and command, with who did it and when. Everything is also in the **Audit log** tab.

A successful remediation resolves its alert automatically. Condition alerts (a hardening check, firewall off, disk full and so on) also resolve automatically once the agent reports that the condition has cleared.

### Detections

| Rule | Severity | Linux source | Windows source |
|---|---|---|---|
| `new_listener` | high/critical | `ss` compared with the baseline | `Get-NetTCPConnection` / `Get-NetUDPEndpoint` compared with the baseline |
| `suspicious_port` | high | connections on 4444, 6667, 31337 and similar | same |
| `blocklisted_ip` | critical | `/etc/netguard/blocklist.txt` | `C:\ProgramData\NetGuard\blocklist.txt` |
| `auth_bruteforce` | high | sshd failures (auth.log, secure or journald) | Security log 4625 (RDP, SMB, network) |
| `login_after_bruteforce` | critical | successful login from a brute-forcing IP | 4624 type 3/10 from a brute-forcing IP |
| `port_scan` | medium | ufw/kernel drop log and SYN-RECV | `pfirewall.log` drops and SynReceived |
| `connection_flood` | medium | 200 or more connections from one IP | same |
| `bandwidth_spike` | medium | `/proc/net/dev` | `Get-NetAdapterStatistics` |
| `resource_pressure` | medium/high | CPU (sustained), memory, disk | same |
| `firewall_disabled` | critical | ufw/firewalld/nft/iptables | firewall profiles |
| `defender_disabled` | high | n/a | Defender real-time protection |
| `hardening_drift` | per check | `harden.sh` audit every 6 h | `Harden-Server.ps1` audit every 6 h |
| `agent_offline` | high | raised by the dashboard | same |

Thresholds are set under `thresholds` in the agent config.

### Process trust on Windows (allowlist and signature checks)

The Windows agent decides whether the executable behind every listening port, and behind every process with a Windows system name, is authentic. Each one gets a trust level:

| Trust | Meaning | Result |
|---|---|---|
| `system` | A core Windows process (svchost, lsass, services, csrss, spoolsv, MsMpEng and ~40 more), running from **its expected path** with a **valid Microsoft signature** | Its listeners are accepted automatically |
| `allowlisted` | Matches an entry in `process_allowlist` or one you trusted from the dashboard. Signed files are pinned to their publisher; unsigned files are pinned to their SHA256 | Accepted automatically. Alerts again if the file changes |
| `trusted_signer` | Valid signature from a publisher in `trusted_signers`, or from Microsoft when `trust_microsoft_signed` is on | Accepted automatically |
| `signed` | Valid signature from a publisher you haven't trusted | low/medium alert |
| `lolbin` | A Microsoft tool attackers often abuse (powershell, rundll32, mshta and so on) | high alert. **Can never be allowlisted** |
| `unsigned` | No signature | medium/high alert |
| `bad_signature` | The file was modified after signing, or the certificate is untrusted or revoked | critical |
| `masquerade` | Has a Windows system name but runs from the wrong folder or isn't Microsoft-signed | critical (`process_masquerade`) |
| `unknown` | The path can't be read because the agent isn't running as SYSTEM | high alert asking you to run the agent as SYSTEM |

`process_masquerade` also catches the following, scanning **all** running processes, not only network ones:

* `lsass`, `services` or `svchost` started by the wrong parent process
* more than one `lsass.exe`
* look-alike names such as `scvhost.exe` or `lsas.exe`

Alerts include the signer, the certificate thumbprint and the SHA256, with a VirusTotal link. A port that's already in the baseline still raises an alert (`untrusted_listener`) if the process serving it is unsigned, has a bad signature, or is a LOLBin. `kill_process` will kill an *impostor* `svchost`, but refuses to kill the genuine signed one.

Agent config:
```json
"trust_microsoft_signed": true,
"trusted_signers": ["VMware, Inc.", "NVIDIA Corporation"],
"process_allowlist": [
  { "name": "nginx", "path": "C:\\nginx\\nginx.exe", "sha256": "<hash>" },
  { "name": "myapp", "path": "C:\\Apps\\myapp\\*.exe", "signer": "My Company Ltd" }
]
```
Normally you don't edit this by hand. Click **Trust process** on an alert, and the agent pins the executable's current signer, or its hash if it's unsigned.

### Process trust on Linux (package verification)

Linux has no Authenticode. Instead, the agent asks the package manager who owns each binary, then checks the running file against the checksum recorded at install time: `dpkg` md5sums on Debian and Ubuntu, `rpm` file digests on RHEL, Rocky, Alma, Fedora and SUSE. The file is read through `/proc/<pid>/exe`, so the check sees the code actually running, even when it's deleted or inside a container. Results are cached for 24 h per file (path, inode, size and mtime). A cycle typically takes about 0.1 to 0.4 s.

| Trust | Meaning | Result |
|---|---|---|
| `system` | A core daemon (sshd, systemd*, cron, dbus, auditd, rsyslogd, chronyd and so on) at its expected path, from a package, checksum OK | Accepted automatically |
| `package` | Owned by an installed package and the checksum matches. Turn this off with `"trust_packaged": false` | Accepted automatically |
| `allowlisted` | You trusted it from the dashboard or through `process_allowlist`; pinned to its SHA256 | Accepted automatically. Alerts again if the file changes |
| `unpackaged` | Not owned by any package (/opt apps, Go binaries, node installed with nvm) | medium/high alert, with a **Trust process** button |
| `container` | Runs in another mount namespace, so the host's package database doesn't apply | low/medium alert |
| `deleted` | The binary was replaced or deleted after start. **Usually a package upgrade**: restart the service. Malware also does this to hide | high |
| `lolbin` | A shell, nc, ncat, socat, busybox or openssl holding a port | high. Can't be allowlisted |
| `modified` | Package-owned, but the checksum **doesn't match**: the file was tampered with | critical |
| `fileless` | Runs from `memfd:` (anonymous memory) | critical |
| `masquerade` | Any of the following | critical |

`masquerade` covers:
* a core daemon name running from the wrong path, or not owned by any package
* a userland process disguised as a kernel thread (`[kworker/0:1]`)

`process_masquerade` also flags look-alike names (`sshdd`, `crnod`) and anything executing from `/tmp`, `/dev/shm` or `/var/tmp`. `kill_process` kills impostors but refuses the genuine sshd, systemd, dbus, journald and similar.

Run the agent as **root** (the installer does). Without root, `ss` can't show which process owns another user's socket.

### Remediation actions (allow-list)

The alert panel groups the actions that fit each alert under **Fix the cause**, **Contain the threat**, **It's legitimate** and **Not a real problem**. Each option says what will happen before you click it:

* Hardening alerts show exactly what the fix changes, what it could affect, and whether it needs a reboot.
* Actions a host doesn't allow (safe mode) are shown greyed out with the reason. The server enforces this too.
* Every reversible action records an **Undo** in "Actions taken": unblock IP, unblock port, restore a quarantined file, restore the pre-fix settings.
* **Accept the risk** hides a condition alert for that host permanently and requires a written reason. **Mark resolved** on a condition that's still true explains that the alert will come back.

| Action | Linux | Windows | Guards |
|---|---|---|---|
| `block_ip` / `unblock_ip` | ufw, firewalld or iptables | `NetGuard-Block-In/Out-<ip>` rules | refuses loopback, trusted IPs, the dashboard's own IP, and any IP with a live SSH/RDP/WinRM session (it could be you). Optional `hours`: the block is removed automatically when it expires |
| `block_port` / `unblock_port` | firewall deny | inbound block rule | refuses the SSH, RDP and WinRM ports |
| `quarantine_file` / `restore_quarantine` | kills every process running the file and moves it to `<state_dir>/quarantine` (mode 000) | the same, into `C:\ProgramData\NetGuard\quarantine` | refuses Microsoft-signed files in `C:\Windows`, unmodified package files, genuine core daemons and trusted programs |
| `harden_restore` | `harden.sh --restore <backup>` | `Harden-Server.ps1 -Restore <backup>` | the backup must be inside NetGuard's backup folder. This is the undo for `harden_fix` |
| `kill_process` | SIGTERM, then SIGKILL | `Stop-Process` | refuses if the PID now belongs to a different process name; refuses PID 1; refuses the *genuine* core processes (verified) but kills impostors |
| `allow_process` | trusts the executable, pinned to its SHA256 | trusts the executable, pinned to its signer or SHA256 | refuses core system names and LOLBins |
| `accept_listener` | adds the port to the baseline | same | n/a |
| `harden_fix` | `harden.sh --apply --only <id>` | `Harden-Server.ps1 -Mode Apply -Only <id>` | the hardening script's own guards and backups |
| `run_hardening_audit` | re-audits now | same | n/a |

## 4. Hardening scripts (standalone)

Both scripts **audit by default and change nothing**.

```bash
sudo ./hardening/linux/harden.sh                       # audit
sudo ./hardening/linux/harden.sh --apply               # asks y/N for each failing check
sudo ./hardening/linux/harden.sh --apply --only fail2ban_active,ssh_x11_forwarding --yes
sudo ./hardening/linux/harden.sh --list
sudo ./hardening/linux/harden.sh --restore /var/backups/netguard-hardening/<timestamp>
```
```powershell
.\hardening\windows\Harden-Server.ps1                  # audit
.\hardening\windows\Harden-Server.ps1 -Mode Apply      # asks y/N for each failing check
.\hardening\windows\Harden-Server.ps1 -Mode Apply -Only smb1_disabled,rdp_nla -Yes
.\hardening\windows\Harden-Server.ps1 -Restore C:\ProgramData\NetGuard\hardening-backups\<timestamp>
```

Safety built in:

* **Backups.** Linux copies every file before changing it. Windows writes the old registry, service, SMB, audit-policy, firewall and password-policy values to `rollback.json`. Use `--restore` / `-Restore` to undo.
* **Lock-out guards:**
  * `ssh_password_auth` is refused unless some user has `authorized_keys`.
  * `ssh_root_login` is refused unless a non-root sudo/wheel user exists.
  * Enabling the firewall first allows SSH and every port that is currently listening.
  * On Windows, enabling the firewall adds allow rules for RDP and WinRM first.
* **sshd and sudoers changes are validated before they take effect.** sshd changes are checked with `sshd -t` and rolled back if invalid; sudoers changes are checked with `visudo -c`.
* `--json` / `-Json` writes a machine-readable report. The agents use this.

**Review these checks before applying them:** `ssh_password_auth`, `legacy_tls_disabled` (old clients), `smb_signing` (very old clients), `ntlmv1_disabled` (legacy apps), `print_spooler_disabled` (print servers) and `optional_services` (rpcbind, if you use NFS). `lsa_protection`, `uac_enabled` and `legacy_tls_disabled` need a reboot.

## Notes and limits

* The Windows `audit_policy` check matches English `auditpol` output. On other display languages it reports as failing even when correct.
* On domain-joined Windows servers, password and audit policy usually come from Group Policy. Fix them there rather than with `harden_fix`.
* Agents must run as root or SYSTEM. Without it, process names, auth logs and every remediation are unavailable.
* Uninstall: `install.sh --uninstall` or `Install-Agent.ps1 -Uninstall`.
