#!/usr/bin/env python3
"""
NetGuard Linux monitoring agent (Python 3.6+, standard library only).

Every cycle it:
  1. collects sockets (ss), auth logs, firewall drop logs, /proc counters
  2. evaluates detection rules and builds alerts
  3. POSTs a report to the dashboard and receives any remediation commands
     you approved there, executes them (allow-listed + validated) and reports
     the result back.
  4. periodically runs the hardening audit (harden.sh --json -)

Run:  netguard_agent.py --config /etc/netguard/agent.json --daemon
      netguard_agent.py --config ... --once --dry-run     (print report, don't send)
Must run as root for firewall changes, auth logs and process names.
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

AGENT_VERSION = "1.0.0"

DEFAULTS = {
    "server_url": "http://127.0.0.1:8787",
    "agent_token": "",
    "host_name": "",
    "verify_tls": True,
    "ca_file": "",
    "interval_seconds": 60,
    "state_dir": "/var/lib/netguard",
    "harden_script": "/opt/netguard/harden.sh",
    "hardening_interval_minutes": 360,
    "blocklist_file": "/etc/netguard/blocklist.txt",
    "trusted_ips": [],
    "trust_packaged": True,      # auto-trust listeners whose binary is owned by a package and passes its checksum
    "process_allowlist": [],     # [{"name": "node", "path": "/opt/app/bin/node", "sha256": "..."}]
    "suspicious_ports": [23, 1337, 2323, 4444, 4445, 5554, 5555, 6666, 6667, 6668, 6669, 7777, 9001, 12345, 31337, 54321],
    "thresholds": {
        "auth_failures": 10,          # failed logins from one IP ...
        "auth_window_seconds": 600,   # ... within this window
        "port_scan_ports": 15,        # distinct ports hit by one IP in one cycle
        "conn_per_ip": 200,           # concurrent connections from one IP
        "rx_mbps": 500, "tx_mbps": 500,
        "cpu_pct": 90, "cpu_cycles": 5,   # sustained for N cycles
        "mem_pct": 90, "disk_pct": 90,
    },
}

STOP = False


def log(msg):
    sys.stderr.write("%s netguard-agent: %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg))
    sys.stderr.flush()


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace")
    except FileNotFoundError:
        return 127, "%s: not found" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "%s: timed out" % cmd[0]


def have(binary):
    return shutil.which(binary) is not None


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
class State:
    def __init__(self, path):
        self.path = path
        self.data = {}
        if os.path.exists(path):
            try:
                with open(path) as f:
                    self.data = json.load(f)
            except (OSError, ValueError):
                log("state file unreadable, starting fresh")

    def get(self, k, default=None):
        return self.data.get(k, default)

    def __setitem__(self, k, v):
        self.data[k] = v

    def __getitem__(self, k):
        return self.data[k]

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f)
        os.replace(tmp, self.path)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def split_addr(a):
    """'0.0.0.0:22' / '[::1]:631' / '127.0.0.53%lo:53' / '*:22' -> (ip, port)"""
    if a.startswith("["):
        ip, _, port = a[1:].partition("]:")
    else:
        ip, _, port = a.rpartition(":")
    ip = ip.split("%")[0]
    if ip.startswith("::ffff:"):
        ip = ip[7:]
    try:
        port = int(port)
    except ValueError:
        port = 0
    return ip, port


def is_local(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a.is_unspecified
    except ValueError:
        return ip in ("*", "")


PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')


def parse_ss():
    rc, out = run(["ss", "-H", "-tunap"])
    socks = []
    if rc != 0:
        log("ss failed: %s" % out.strip())
        return socks
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        proto, st, local, peer = parts[0], parts[1], parts[4], parts[5]
        proc = " ".join(parts[6:])
        m = PROC_RE.search(proc)
        lip, lport = split_addr(local)
        pip, pport = split_addr(peer)
        socks.append({"proto": proto, "state": st, "lip": lip, "lport": lport, "pip": pip, "pport": pport,
                      "process": m.group(1) if m else "", "pid": int(m.group(2)) if m else 0})
    return socks


def exe_of(pid):
    try:
        return os.readlink("/proc/%d/exe" % pid)
    except OSError:
        return ""


def cmdline_of(pid):
    try:
        with open("/proc/%d/cmdline" % pid, "rb") as f:
            return f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()[:300]
    except OSError:
        return ""


def load_networks(items):
    nets = []
    for i in items:
        i = i.strip()
        if not i or i.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(i.split()[0], strict=False))
        except ValueError:
            pass
    return nets


def in_nets(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets if n.version == a.version)


class LogTail:
    """Reads new lines from a log file since last call (handles rotation)."""

    def __init__(self, state, key, path):
        self.state, self.key, self.path = state, key, path

    def read(self):
        if not os.path.exists(self.path):
            return []
        st = os.stat(self.path)
        pos = self.state.get(self.key) or {}
        if not pos:  # first run: start at the end, don't alert on history
            self.state[self.key] = {"inode": st.st_ino, "offset": st.st_size}
            return []
        offset = pos.get("offset", 0)
        if pos.get("inode") != st.st_ino or st.st_size < offset:
            offset = 0  # rotated / truncated
        with open(self.path, "rb") as f:
            f.seek(offset)
            data = f.read(20 * 1024 * 1024)
            self.state[self.key] = {"inode": st.st_ino, "offset": f.tell()}
        return data.decode("utf-8", "replace").splitlines()


def journal_lines(state, key, args):
    """New journald messages since the last call, for the given journalctl filters."""
    now_us = int(time.time() * 1e6)
    last = state.get(key)
    state[key] = now_us
    if not last:
        return []
    rc, out = run(["journalctl", "--no-pager", "-o", "json", "--since", "@%d" % (last // 1000000)] + args, timeout=60)
    lines = []
    if rc != 0:
        return lines
    for row in out.splitlines():
        try:
            e = json.loads(row)
        except ValueError:
            continue
        ts = int(e.get("__REALTIME_TIMESTAMP", 0))
        if last < ts <= now_us:
            msg = e.get("MESSAGE", "")
            if isinstance(msg, list):  # binary message
                msg = bytes(msg).decode("utf-8", "replace")
            lines.append(msg)
    return lines


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Process trust: core-daemon allowlist + package-manager integrity checks
# ---------------------------------------------------------------------------
import fnmatch
import hashlib

# Core daemons and the ONLY paths they may run from (names are /proc/<pid>/comm, max 15 chars).
CORE_LINUX = {
    "systemd": ["/usr/lib/systemd/systemd", "/lib/systemd/systemd"],
    "sshd": ["/usr/sbin/sshd"],
    "sshd-session": ["/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session", "/usr/sbin/sshd-session"],
    "sshd-auth": ["/usr/lib/openssh/sshd-auth", "/usr/libexec/openssh/sshd-auth"],
    "cron": ["/usr/sbin/cron"], "crond": ["/usr/sbin/crond"],
    "rsyslogd": ["/usr/sbin/rsyslogd"], "auditd": ["/usr/sbin/auditd", "/sbin/auditd"],
    "dbus-daemon": ["/usr/bin/dbus-daemon"], "dbus-broker": ["/usr/bin/dbus-broker"],
    "dbus-broker-lau": ["/usr/bin/dbus-broker-launch"],
    "chronyd": ["/usr/sbin/chronyd"], "polkitd": ["/usr/lib/polkit-1/polkitd", "/usr/libexec/polkitd"],
    "agetty": ["/usr/sbin/agetty", "/sbin/agetty"], "login": ["/usr/bin/login", "/bin/login"],
    "fail2ban-server": ["/usr/bin/python3*"], "unattended-upgr": ["/usr/bin/python3*"],
}
SYSTEMD_PATHS = ["/usr/lib/systemd/*", "/lib/systemd/*", "/usr/bin/systemd*", "/bin/systemd*", "/usr/libexec/systemd*"]
KTHREAD_RE = re.compile(r"^(kworker|ksoftirqd|kthreadd|migration|rcu_|kswapd|watchdog|cpuhp|kcompactd|khugepaged|jbd2|irq/|kdevtmpfs|ksmd|oom_reaper|writeback|kblockd|scsi_)")
LOLBINS_LINUX = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "ash", "busybox", "nc", "ncat", "netcat", "nc.openbsd",
                 "nc.traditional", "socat", "telnet", "openssl", "cryptcat", "xterm"}
LOOKALIKE_LINUX = ["sshd", "systemd", "crond", "rsyslogd", "dbus-daemon", "kthreadd", "kworker", "auditd", "agetty",
                   "polkitd", "chronyd", "journald", "udevd", "nginx", "apache2", "httpd", "mysqld", "postgres", "containerd", "dockerd"]
SUPPORTED_ACTIONS = ["block_ip", "unblock_ip", "block_port", "unblock_port", "kill_process", "quarantine_file",
                     "restore_quarantine", "allow_process", "harden_fix", "harden_restore", "run_hardening_audit", "accept_listener"]
HARDEN_BACKUP_ROOT = "/var/backups/netguard-hardening"
PROTECTED_LINUX = {"systemd", "sshd", "dbus-daemon", "dbus-broker", "systemd-journal", "systemd-logind", "auditd", "rsyslogd",
                   "systemd-udevd", "systemd-network", "systemd-resolve", "containerd", "dockerd"}
TRUSTED_LINUX = ("system", "package", "allowlisted")
SUSPICIOUS_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/dev/mqueue/")


def damerau(a, b):
    """Optimal-string-alignment distance (adjacent swaps count as one edit)."""
    a, b = a.lower(), b.lower()
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def read_proc(pid, name, binary=False):
    try:
        with open("/proc/%d/%s" % (pid, name), "rb") as f:
            data = f.read()
        return data if binary else data.decode("utf-8", "replace")
    except OSError:
        return None


class ProcessTrust:
    def __init__(self, agent):
        self.agent = agent
        self.cfg = agent.cfg
        self.cache = {}                       # per-cycle, by pid
        self.pkg_cache = agent.state.get("pkg_cache") or {}   # persistent, by file identity
        try:
            self.my_mnt = os.readlink("/proc/self/ns/mnt")
        except OSError:
            self.my_mnt = None

    def reset(self):
        self.cache = {}

    def save(self):
        now = time.time()
        keep = {k: v for k, v in self.pkg_cache.items() if now - v.get("checked", 0) < 86400}
        self.agent.state["pkg_cache"] = keep if len(keep) < 800 else {}

    # ---- file integrity ----------------------------------------------------
    def _digests(self, pid):
        """md5+sha256 of the running image, read via /proc/<pid>/exe (works for deleted and container files)."""
        md5, sha = hashlib.md5(), hashlib.sha256()
        try:
            with open("/proc/%d/exe" % pid, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    md5.update(chunk)
                    sha.update(chunk)
        except OSError:
            return "", ""
        return md5.hexdigest(), sha.hexdigest()

    def package_check(self, pid, path):
        """-> dict(package, status ok|modified|unverified|none, sha256). Cached per file identity for 24h."""
        try:
            st = os.stat("/proc/%d/exe" % pid)
            key = "%s|%d|%d|%d" % (path, st.st_ino, st.st_size, int(st.st_mtime))
        except OSError:
            key = None
        c = self.pkg_cache.get(key) if key else None
        if c and time.time() - c.get("checked", 0) < 86400:
            return c
        md5h, shah = self._digests(pid)
        res = {"package": "", "status": "none", "sha256": shah, "checked": time.time()}
        if have("dpkg-query"):
            cands = [path] + ([path[4:]] if path.startswith("/usr/") else [])   # pre-merged-/usr db entries
            for cand in cands:
                rc, out = run(["dpkg-query", "-S", cand], timeout=20)
                if rc != 0 or ": " not in out:
                    continue
                pkg = out.splitlines()[0].rsplit(": ", 1)[0].split(",")[0].strip()
                res["package"] = pkg
                res["status"] = "unverified"
                base = pkg.split(":")[0]
                for f in ("/var/lib/dpkg/info/%s.md5sums" % pkg, "/var/lib/dpkg/info/%s.md5sums" % base):
                    try:
                        with open(f) as fh:
                            for line in fh:
                                parts = line.split(None, 1)
                                if len(parts) == 2 and parts[1].strip() == cand.lstrip("/"):
                                    res["status"] = "ok" if parts[0] == md5h else "modified"
                                    break
                    except OSError:
                        continue
                    if res["status"] != "unverified":
                        break
                break
        elif have("rpm"):
            rc, out = run(["rpm", "-qf", path], timeout=20)
            if rc == 0 and "not owned" not in out:
                pkg = out.splitlines()[0].strip()
                res["package"], res["status"] = pkg, "unverified"
                rc, out = run(["rpm", "-q", "--qf", "[%{FILENAMES}\t%{FILEDIGESTS}\n]", pkg], timeout=30)
                for line in out.splitlines():
                    fn, _, dig = line.partition("\t")
                    if fn == path and dig:
                        want = dig.strip().lower()
                        got = shah if len(want) == 64 else md5h if len(want) == 32 else ""
                        res["status"] = "ok" if got and got == want else "modified" if got else "unverified"
                        break
        if key:
            self.pkg_cache[key] = res
        return res

    def allowlisted(self, name, path, pid):
        for e in list(self.cfg.get("process_allowlist") or []) + list(self.agent.state.get("process_allowlist") or []):
            if not e or e.get("name") != name:
                continue
            if e.get("path") and not fnmatch.fnmatch(path, e["path"]):
                continue
            if e.get("sha256"):
                if self._digests(pid)[1] == e["sha256"].lower():
                    return "allowlisted (SHA256 pinned)"
                continue
            return "allowlisted"
        return None

    @staticmethod
    def expected_paths(comm):
        if comm in CORE_LINUX:
            return CORE_LINUX[comm]
        if comm.startswith("systemd-") or comm == "(sd-pam)":
            return SYSTEMD_PATHS
        return None

    # ---- main classification ---------------------------------------------
    def info(self, pid):
        if pid in self.cache:
            return self.cache[pid]
        t = {"trust": "unknown", "reason": "", "package": "", "sha256": "", "exe": "", "comm": "", "ppid": 0}
        comm = (read_proc(pid, "comm") or "").strip()
        stat = read_proc(pid, "stat") or ""
        try:
            t["ppid"] = int(stat.rsplit(")", 1)[1].split()[1])
        except (IndexError, ValueError):
            pass
        t["comm"] = comm
        raw_cmd = read_proc(pid, "cmdline", binary=True) or b""
        argv0 = raw_cmd.split(b"\0", 1)[0].decode("utf-8", "replace")
        cmdline = raw_cmd.replace(b"\0", b" ").decode("utf-8", "replace").strip()
        try:
            exe = os.readlink("/proc/%d/exe" % pid)
        except FileNotFoundError:
            exe = None            # kernel thread (or process already gone)
        except PermissionError:
            t["reason"] = "cannot read /proc/%d/exe - run the agent as root" % pid
            self.cache[pid] = t
            return t
        except OSError:
            exe = None
        t["exe"] = exe or ""

        if exe is None:
            if pid == 2 or t["ppid"] == 2 or not cmdline:
                t["trust"], t["reason"] = "system", "kernel thread"
            else:
                t["reason"] = "executable not readable"
            self.cache[pid] = t
            return t

        # Userland process dressed up as a kernel thread: "[kworker/0:1]" etc.
        if (len(argv0) > 2 and argv0.startswith("[") and argv0.endswith("]")) or KTHREAD_RE.match(comm):
            t["trust"] = "masquerade"
            t["reason"] = "disguised as kernel thread '%s' but is a userland process running %s" % (argv0 if argv0.startswith("[") else comm, exe)
            t["sha256"] = self._digests(pid)[1]
            self.cache[pid] = t
            return t

        deleted = exe.endswith(" (deleted)")
        path = exe[:-10] if deleted else exe
        if path.startswith("/memfd:") or path.startswith("memfd:"):
            t["trust"], t["reason"] = "fileless", "runs from an anonymous memory file (%s) - classic fileless malware technique" % exe
            t["sha256"] = self._digests(pid)[1]
            self.cache[pid] = t
            return t
        try:
            in_container = self.my_mnt is not None and os.readlink("/proc/%d/ns/mnt" % pid) != self.my_mnt
        except OSError:
            in_container = False

        expected = self.expected_paths(comm)
        if expected and not in_container and not any(fnmatch.fnmatch(path, p) for p in expected):
            t["trust"] = "masquerade"
            t["reason"] = "named like system daemon '%s' but runs from %s (expected %s)" % (comm, path, " or ".join(expected))
            t["sha256"] = self._digests(pid)[1]
        elif deleted:
            t["trust"] = "deleted"
            t["reason"] = ("binary %s was deleted/replaced after the process started. Usually a package upgrade "
                           "(restart the service), but also used by malware to hide" % path)
            t["sha256"] = self._digests(pid)[1]
        elif in_container:
            t["trust"], t["reason"] = "container", "runs inside a container (%s); host package database does not apply" % path
            t["sha256"] = self._digests(pid)[1]
        else:
            allow = None if expected else self.allowlisted(comm, path, pid)
            base = os.path.basename(path)
            if allow:
                t["trust"], t["reason"] = "allowlisted", allow
            elif not expected and (comm in LOLBINS_LINUX or base in LOLBINS_LINUX):
                t["trust"], t["reason"] = "lolbin", "%s is a shell/network tool; holding a port or masquerading this way is a classic backdoor pattern" % base
                t["sha256"] = self._digests(pid)[1]
            else:
                pk = self.package_check(pid, path)
                t["package"], t["sha256"] = pk["package"], pk["sha256"]
                if pk["status"] == "modified":
                    t["trust"] = "modified"
                    t["reason"] = "%s belongs to package '%s' but its checksum does NOT match the package database - file was tampered with" % (path, pk["package"])
                elif pk["status"] in ("ok", "unverified"):
                    t["trust"] = "system" if expected else "package"
                    t["reason"] = "file from package '%s'%s" % (pk["package"], ", checksum verified" if pk["status"] == "ok" else " (no checksum in package db)")
                elif expected:
                    t["trust"] = "masquerade"
                    t["reason"] = "system daemon '%s' at %s is not owned by any installed package" % (comm, path)
                else:
                    t["trust"], t["reason"] = "unpackaged", "%s is not owned by any installed package" % path
        if t["trust"] in ("package", "system") and not self.cfg.get("trust_packaged", True):
            t["trust"] = "unpackaged" if t["trust"] == "package" else t["trust"]
        self.cache[pid] = t
        return t

    @staticmethod
    def evidence(t):
        ev = {"trust": t["trust"], "trust_reason": t["reason"]}
        if t.get("package"):
            ev["package"] = t["package"]
        if t.get("sha256") and t["trust"] not in ("system", "package"):
            ev["sha256"] = t["sha256"]
        return ev

    @staticmethod
    def lookalike(comm):
        if len(comm) < 4 or comm in CORE_LINUX or comm.startswith("systemd"):
            return None
        for target in LOOKALIKE_LINUX:
            if target != comm and abs(len(target) - len(comm)) <= 1 and damerau(comm, target) <= 1:
                return target
        return None


class Agent:
    def __init__(self, cfg, dry_run=False):
        self.cfg = cfg
        self.th = dict(DEFAULTS["thresholds"], **cfg.get("thresholds", {}))
        self.dry = dry_run
        self.host = cfg.get("host_name") or socket.gethostname()
        os.makedirs(cfg["state_dir"], exist_ok=True)
        self.state = State(os.path.join(cfg["state_dir"], "agent-state.json"))
        self.trusted = load_networks(cfg.get("trusted_ips", []))
        self.alerts = []
        self.conditions = set()  # fingerprints of condition-type alerts currently true
        self.hardening_summary = None
        self.trust = ProcessTrust(self)

    # ---- alert helper -----------------------------------------------------
    def alert(self, rule, severity, fingerprint, title, details="", evidence=None, suggested=None, condition=False):
        self.alerts.append({"rule": rule, "severity": severity, "fingerprint": fingerprint, "title": title,
                            "details": details, "evidence": evidence or {}, "suggested": suggested or []})
        if condition:
            self.conditions.add(fingerprint)

    def blocklist(self):
        p = self.cfg.get("blocklist_file")
        if p and os.path.exists(p):
            with open(p) as f:
                return load_networks(f.readlines())
        return []

    # ---- rules -------------------------------------------------------------
    def rule_sockets(self, socks):
        listeners = {}
        for s in socks:
            if (s["proto"] == "tcp" and s["state"] == "LISTEN") or (s["proto"] == "udp" and s["state"] == "UNCONN"):
                key = "%s:%d" % (s["proto"], s["lport"])
                listeners.setdefault(key, s)
        baseline = self.state.get("listen_baseline")
        if baseline is None:
            self.state["listen_baseline"] = sorted(listeners)
            log("baseline created with %d listeners" % len(listeners))
            baseline = list(listeners)
        auto = []
        for key, s in sorted(listeners.items()):
            exposed = not is_local(s["lip"]) or s["lip"] in ("0.0.0.0", "::", "*")
            t = self.trust.info(s["pid"]) if s["pid"] else {"trust": "unknown", "reason": "no owning process visible (run as root)", "exe": ""}
            exe = t.get("exe", "")
            path = exe[:-10] if exe.endswith(" (deleted)") else exe
            ev = {"port": s["lport"], "protocol": s["proto"], "bind": s["lip"], "process": s["process"],
                  "pid": s["pid"], "exe": exe, "cmdline": cmdline_of(s["pid"]) if s["pid"] else ""}
            ev.update(ProcessTrust.evidence(t))
            sug = []
            if s["pid"] and path.startswith("/") and t["trust"] in ("masquerade", "modified", "unpackaged", "deleted"):
                sug.append({"action": "quarantine_file", "params": {"pid": s["pid"], "name": s["process"], "path": path},
                            "label": "Quarantine %s (kill + move file, restorable)" % s["process"]})
            if path.startswith("/") and t["trust"] not in ("masquerade", "lolbin", "modified", "fileless") and \
                    not ProcessTrust.expected_paths(s["process"]):
                sug.append({"action": "allow_process", "params": {"name": s["process"], "path": path},
                            "label": "Trust %s (pin SHA256)" % s["process"]})
            if exposed:
                sug.append({"action": "block_port", "params": {"port": s["lport"], "protocol": s["proto"]},
                            "label": "Block inbound %s/%d at firewall" % (s["proto"], s["lport"])})
            if s["pid"]:
                sug.append({"action": "kill_process", "params": {"pid": s["pid"], "name": s["process"]},
                            "label": "Kill %s (pid %d)" % (s["process"], s["pid"])})

            if key in baseline:
                # Known port - but is the binary behind it still authentic?
                if t["trust"] in ("unpackaged", "modified", "deleted", "lolbin", "fileless"):
                    sev = {"modified": "critical", "fileless": "critical", "lolbin": "high", "deleted": "medium"}.get(
                        t["trust"], "medium" if exposed else "low")
                    self.alert("untrusted_listener", sev, "untrusted:%s:%s" % (key, path),
                               "%s/%d served by %s: %s" % (s["proto"].upper(), s["lport"], s["process"], t["trust"]),
                               "%s. Verify the file, then trust or remove it." % t["reason"], ev, sug, condition=True)
                continue
            if t["trust"] in TRUSTED_LINUX:
                auto.append(key)
                log("auto-accepted listener %s (%s, %s)" % (key, s["process"], t["reason"]))
                continue
            sev = {"masquerade": "critical", "modified": "critical", "fileless": "critical", "lolbin": "high",
                   "deleted": "high"}.get(t["trust"])
            if not sev:
                if t["trust"] == "container":
                    sev = "medium" if exposed else "low"
                elif t["trust"] == "unpackaged":
                    sev = "high" if exposed else "medium"
                else:
                    sev = "high" if exposed else "low"
            if path.startswith(SUSPICIOUS_DIRS):
                sev = "critical"
            sug.insert(0, {"action": "accept_listener", "params": {"port": s["lport"], "protocol": s["proto"]},
                           "label": "Accept this port only (keep checking the binary)"})
            self.alert("new_listener", sev, "listener:%s" % key,
                       "New %s listener on port %d (%s, %s)" % (s["proto"].upper(), s["lport"], s["process"] or "unknown", t["trust"]),
                       "Bound to %s. Not in this host's baseline. %s." % (s["lip"], t["reason"]), ev, sug, condition=True)
        if auto:
            self.state["listen_baseline"] = sorted(set(self.state.get("listen_baseline") or []) | set(auto))

        susp = set(int(p) for p in self.cfg.get("suspicious_ports", DEFAULTS["suspicious_ports"]))
        bad_nets = self.blocklist()
        per_ip = {}
        for s in socks:
            if s["state"] not in ("ESTAB", "SYN-SENT", "SYN-RECV") or is_local(s["pip"]):
                continue
            if in_nets(s["pip"], self.trusted):
                continue
            per_ip[s["pip"]] = per_ip.get(s["pip"], 0) + 1
            ev = {"remote_ip": s["pip"], "remote_port": s["pport"], "local_port": s["lport"],
                  "process": s["process"], "pid": s["pid"], "exe": exe_of(s["pid"]) if s["pid"] else "",
                  "cmdline": cmdline_of(s["pid"]) if s["pid"] else ""}
            if s["pid"] and (s["pport"] in susp or s["lport"] in susp or bad_nets):
                ev.update(ProcessTrust.evidence(self.trust.info(s["pid"])))
            sug = [{"action": "block_ip", "params": {"ip": s["pip"]}, "label": "Block %s" % s["pip"]}]
            if s["pid"]:
                sug.append({"action": "kill_process", "params": {"pid": s["pid"], "name": s["process"]},
                            "label": "Kill %s (pid %d)" % (s["process"], s["pid"])})
            if bad_nets and in_nets(s["pip"], bad_nets):
                self.alert("blocklisted_ip", "critical", "blocklist:%s" % s["pip"],
                           "Connection with blocklisted IP %s" % s["pip"],
                           "%s (pid %s) <-> %s:%s" % (s["process"], s["pid"], s["pip"], s["pport"]), ev, sug)
            if s["pport"] in susp or s["lport"] in susp:
                port = s["pport"] if s["pport"] in susp else s["lport"]
                self.alert("suspicious_port", "high", "susp:%s:%d:%s" % (s["pip"], port, s["process"]),
                           "Connection on suspicious port %d with %s" % (port, s["pip"]),
                           "Process %s; ports like %d are common for reverse shells / C2." % (s["process"] or "?", port),
                           dict(ev, port=port), sug)
        for ip, n in per_ip.items():
            if n >= self.th["conn_per_ip"]:
                self.alert("connection_flood", "medium", "flood:%s" % ip,
                           "%d concurrent connections from %s" % (n, ip), "",
                           {"remote_ip": ip, "connections": n},
                           [{"action": "block_ip", "params": {"ip": ip}, "label": "Block %s" % ip}])
        return listeners, per_ip

    def rule_processes(self):
        """Scan ALL processes for fake system daemons, fake kernel threads, fileless and look-alike binaries."""
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            pid = int(d)
            comm = (read_proc(pid, "comm") or "").strip()
            if not comm:
                continue
            raw = read_proc(pid, "cmdline", binary=True) or b""
            fake_kthread = raw.startswith(b"[") or KTHREAD_RE.match(comm)
            core = ProcessTrust.expected_paths(comm) is not None
            look = ProcessTrust.lookalike(comm)
            if not (fake_kthread or core or look):
                # cheap check for fileless / deleted binaries on every process
                try:
                    exe = os.readlink("/proc/%d/exe" % pid)
                except OSError:
                    continue
                if not (exe.startswith(("/memfd:", "memfd:")) or exe.startswith(SUSPICIOUS_DIRS)):
                    continue
            t = self.trust.info(pid)
            ev = {"process": comm, "pid": pid, "exe": t.get("exe", ""), "parent_pid": t.get("ppid"),
                  "cmdline": cmdline_of(pid)}
            ev.update(ProcessTrust.evidence(t))
            kill = [{"action": "kill_process", "params": {"pid": pid, "name": comm}, "label": "Kill %s (pid %d)" % (comm, pid)}]
            path = t.get("exe", "").replace(" (deleted)", "")
            if path.startswith("/") and not t.get("exe", "").endswith(" (deleted)") and t["trust"] in ("masquerade", "modified", "unpackaged"):
                kill.insert(0, {"action": "quarantine_file", "params": {"pid": pid, "name": comm, "path": path},
                                "label": "Quarantine %s (kill + move file, restorable)" % comm})
            if t["trust"] in ("masquerade", "fileless", "modified"):
                shown = raw.split(b"\0", 1)[0].decode("utf-8", "replace") if raw.startswith(b"[") else comm
                title = {"masquerade": "Fake system process: %s (pid %d)", "fileless": "Fileless process: %s (pid %d)",
                         "modified": "Tampered system binary: %s (pid %d)"}[t["trust"]] % (shown, pid)
                self.alert("process_masquerade", "critical", "masq:%s:%s" % (comm, path), title, t["reason"], ev, kill, condition=True)
            elif look and t["trust"] not in TRUSTED_LINUX:
                self.alert("process_masquerade", "high", "lookalike:%s:%s" % (comm, path),
                           "'%s' imitates '%s' (pid %d)" % (comm, look, pid),
                           "Process name is one edit away from a well-known daemon. %s." % t["reason"], dict(ev, imitates=look), kill, condition=True)
            elif path.startswith(SUSPICIOUS_DIRS) and t["trust"] not in TRUSTED_LINUX:
                self.alert("process_masquerade", "high", "tmpexec:%s:%s" % (comm, path),
                           "Process running from %s: %s (pid %d)" % (os.path.dirname(path), comm, pid),
                           "Binaries executed from world-writable temp directories are a common dropper pattern. %s." % t["reason"],
                           ev, kill, condition=True)

    def rule_auth(self):
        if os.path.exists("/var/log/auth.log"):
            lines = LogTail(self.state, "tail_auth", "/var/log/auth.log").read()
        elif os.path.exists("/var/log/secure"):
            lines = LogTail(self.state, "tail_secure", "/var/log/secure").read()
        elif have("journalctl"):
            lines = journal_lines(self.state, "j_auth", ["_COMM=sshd", "_COMM=sshd-session"])
        else:
            return
        fail_re = re.compile(r"(?:Failed \S+ for (?:invalid user )?(\S+)|Invalid user (\S*)) from ([0-9a-fA-F:.]+)")
        ok_re = re.compile(r"Accepted (\S+) for (\S+) from ([0-9a-fA-F:.]+)")
        now = time.time()
        win = self.th["auth_window_seconds"]
        fails = {ip: [t for t in ts if now - t < win] for ip, ts in (self.state.get("auth_fails") or {}).items()}
        users = self.state.get("auth_users") or {}
        bruteforcers = {ip: t for ip, t in (self.state.get("bruteforcers") or {}).items() if now - t < 86400}
        for line in lines:
            m = fail_re.search(line)
            if m:
                ip = m.group(3)
                fails.setdefault(ip, []).append(now)
                u = users.setdefault(ip, [])
                name = m.group(1) or m.group(2) or "?"
                if name not in u and len(u) < 20:
                    u.append(name)
                continue
            m = ok_re.search(line)
            if m and m.group(3) in bruteforcers:
                ip = m.group(3)
                self.alert("login_after_bruteforce", "critical", "login_after_bf:%s:%s" % (ip, m.group(2)),
                           "Successful SSH login for '%s' from brute-forcing IP %s" % (m.group(2), ip),
                           "Method: %s. This IP had many failed attempts earlier." % m.group(1),
                           {"remote_ip": ip, "user": m.group(2), "method": m.group(1), "log": line[-300:]},
                           [{"action": "block_ip", "params": {"ip": ip}, "label": "Block %s" % ip}])
        for ip, ts in list(fails.items()):
            if not ts:
                fails.pop(ip, None)
                users.pop(ip, None)
                continue
            if len(ts) >= self.th["auth_failures"] and not in_nets(ip, self.trusted):
                bruteforcers[ip] = now
                self.alert("auth_bruteforce", "high", "bruteforce:ssh:%s" % ip,
                           "SSH brute force from %s (%d failures)" % (ip, len(ts)),
                           "%d failed logins in the last %d min." % (len(ts), win // 60),
                           {"remote_ip": ip, "failures": len(ts), "usernames": users.get(ip, []), "service": "ssh"},
                           [{"action": "block_ip", "params": {"ip": ip}, "label": "Block %s" % ip}])
        self.state["auth_fails"] = fails
        self.state["auth_users"] = {ip: u for ip, u in users.items() if ip in fails}
        self.state["bruteforcers"] = bruteforcers

    def rule_firewall_log(self, socks):
        """Port-scan detection from firewall drop logs (ufw/firewalld/iptables LOG) + SYN-RECV."""
        lines = []
        if os.path.exists("/var/log/ufw.log"):
            lines = LogTail(self.state, "tail_ufw", "/var/log/ufw.log").read()
        elif os.path.exists("/var/log/kern.log"):
            lines = LogTail(self.state, "tail_kern", "/var/log/kern.log").read()
        elif have("journalctl"):
            lines = journal_lines(self.state, "j_kern", ["-k"])
        hits = {}
        rx = re.compile(r"SRC=([0-9a-fA-F:.]+) .*?DPT=(\d+)")
        for line in lines:
            m = rx.search(line)
            if m:
                hits.setdefault(m.group(1), set()).add(int(m.group(2)))
        for s in socks:
            if s["state"] == "SYN-RECV" and not is_local(s["pip"]):
                hits.setdefault(s["pip"], set()).add(s["lport"])
        for ip, ports in hits.items():
            if len(ports) >= self.th["port_scan_ports"] and not in_nets(ip, self.trusted):
                self.alert("port_scan", "medium", "scan:%s" % ip,
                           "Port scan from %s (%d ports)" % (ip, len(ports)), "",
                           {"remote_ip": ip, "ports": sorted(ports)[:50], "distinct_ports": len(ports)},
                           [{"action": "block_ip", "params": {"ip": ip}, "label": "Block %s" % ip}])

    def rule_resources(self):
        m = {}
        # CPU from /proc/stat delta
        with open("/proc/stat") as f:
            vals = [int(x) for x in f.readline().split()[1:]]
        idle, total = vals[3] + (vals[4] if len(vals) > 4 else 0), sum(vals)
        prev = self.state.get("cpu_prev")
        self.state["cpu_prev"] = [idle, total]
        if prev and total > prev[1]:
            m["cpu_pct"] = round(100.0 * (1 - (idle - prev[0]) / float(total - prev[1])), 1)
        # memory
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                mem[k] = int(v.split()[0])
        if mem.get("MemTotal"):
            m["mem_pct"] = round(100.0 * (1 - mem.get("MemAvailable", mem.get("MemFree", 0)) / float(mem["MemTotal"])), 1)
        # disk (real filesystems)
        worst, worst_mnt = 0.0, ""
        seen = set()
        with open("/proc/mounts") as f:
            for line in f:
                dev, mnt, fs = line.split()[:3]
                if fs not in ("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs") or dev in seen:
                    continue
                seen.add(dev)
                try:
                    st = os.statvfs(mnt)
                except OSError:
                    continue
                if st.f_blocks:
                    pct = 100.0 * (1 - st.f_bavail / float(st.f_blocks))
                    if pct > worst:
                        worst, worst_mnt = pct, mnt
        m["disk_pct"] = round(worst, 1)
        # network throughput
        rx = tx = 0
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, data = line.split(":", 1)
                if name.strip() == "lo":
                    continue
                d = data.split()
                rx += int(d[0])
                tx += int(d[8])
        now = time.time()
        pn = self.state.get("net_prev")
        self.state["net_prev"] = [now, rx, tx]
        if pn and now > pn[0] and rx >= pn[1] and tx >= pn[2]:
            dt = now - pn[0]
            m["rx_mbps"] = round((rx - pn[1]) * 8 / dt / 1e6, 2)
            m["tx_mbps"] = round((tx - pn[2]) * 8 / dt / 1e6, 2)
            for d in ("rx", "tx"):
                if m[d + "_mbps"] >= self.th[d + "_mbps"]:
                    self.alert("bandwidth_spike", "medium", "bw:%s" % d,
                               "%s throughput %.0f Mbps" % ("Inbound" if d == "rx" else "Outbound", m[d + "_mbps"]),
                               "Threshold %s Mbps." % self.th[d + "_mbps"], {"direction": d, "mbps": m[d + "_mbps"]},
                               condition=True)
        # alerts
        hot = self.state.get("cpu_hot", 0)
        hot = hot + 1 if m.get("cpu_pct", 0) >= self.th["cpu_pct"] else 0
        self.state["cpu_hot"] = hot
        if hot >= self.th["cpu_cycles"]:
            top = run(["ps", "-eo", "pid,comm,%cpu", "--sort=-%cpu", "--no-headers"])[1].splitlines()[:5]
            self.alert("resource_pressure", "medium", "res:cpu", "CPU at %s%% for %d cycles" % (m["cpu_pct"], hot),
                       "Unexpected sustained CPU can indicate a crypto-miner.",
                       {"cpu_pct": m["cpu_pct"], "top_processes": [t.strip() for t in top]},
                       [{"action": "kill_process", "params": {"pid": int(t.split()[0]), "name": t.split()[1]},
                         "label": "Kill %s (pid %s)" % (t.split()[1], t.split()[0])} for t in top[:1] if len(t.split()) >= 2],
                       condition=True)
        if m.get("mem_pct", 0) >= self.th["mem_pct"]:
            self.alert("resource_pressure", "medium", "res:mem", "Memory at %s%%" % m["mem_pct"], "",
                       {"mem_pct": m["mem_pct"]}, condition=True)
        if m["disk_pct"] >= self.th["disk_pct"]:
            self.alert("resource_pressure", "high" if m["disk_pct"] >= 97 else "medium", "res:disk",
                       "Disk %s at %s%%" % (worst_mnt, m["disk_pct"]), "Full disks stop logging and break services.",
                       {"mount": worst_mnt, "disk_pct": m["disk_pct"]}, condition=True)
        return m

    def rule_firewall_state(self):
        if os.geteuid() != 0:
            return
        if have("ufw") and "Status: active" in run(["ufw", "status"])[1]:
            return
        if run(["systemctl", "is-active", "--quiet", "firewalld"])[0] == 0:
            return
        if have("nft") and re.search(r"hook input .*policy drop", run(["nft", "list", "ruleset"])[1]):
            return
        if have("iptables") and "-P INPUT DROP" in run(["iptables", "-S", "INPUT"])[1]:
            return
        self.alert("firewall_disabled", "critical", "firewall_off", "Host firewall is not active",
                   "No ufw/firewalld/nftables/iptables default-deny policy found.", {},
                   [{"action": "harden_fix", "params": {"check_id": "firewall_active"}, "label": "Enable firewall (keeps SSH + current listeners open)"}],
                   condition=True)

    def rule_hardening(self, force=False):
        script = self.cfg.get("harden_script")
        last = self.state.get("harden_last", 0)
        due = force or time.time() - last >= self.cfg["hardening_interval_minutes"] * 60
        cached = self.state.get("harden_fails") or []
        if due and script and os.path.exists(script):
            rc, out = run(["bash", script, "--audit", "--json", "-"], timeout=300)
            try:
                rep = json.loads(out[out.index("{"):])
            except ValueError:
                log("hardening audit output not JSON: %s" % out[-300:])
                rep = None
            if rep:
                self.state["harden_last"] = time.time()
                res = rep.get("results", [])
                applicable = [r for r in res if r["status"] != "n/a"]
                self.hardening_summary = {"total": len(applicable), "ts": time.time(),
                                          "passed": sum(1 for r in applicable if r["status"] == "pass")}
                cached = [r for r in res if r["status"] == "fail"]
                self.state["harden_fails"] = cached
                for r in cached:
                    ev = {"check_id": r["id"], "current": r["detail"]}
                    if r.get("change"):
                        ev["fix_changes"] = r["change"]
                    if r.get("risk"):
                        ev["fix_risk"] = r["risk"]
                    if r.get("fixable"):
                        ev["fix_reboot"] = "yes" if r.get("reboot") else "no"
                    label = "Apply fix" + (" (reboot needed)" if r.get("reboot") else "")
                    self.alert("hardening_drift", r["severity"], "harden:%s" % r["id"],
                               "Hardening: %s" % r["title"], r["detail"], ev,
                               [{"action": "harden_fix", "params": {"check_id": r["id"]}, "label": label}]
                               if r.get("fixable") else [], condition=True)
                return
        for r in cached:  # not re-sent between audits, but keep them "active"
            self.conditions.add("harden:%s" % r["id"])

    # ---- remediation ------------------------------------------------------
    def _fw(self):
        if have("ufw") and "Status: active" in run(["ufw", "status"])[1]:
            return "ufw"
        if run(["systemctl", "is-active", "--quiet", "firewalld"])[0] == 0:
            return "firewalld"
        return "iptables"

    def expire_blocks(self):
        tb = self.state.get("timed_blocks") or {}
        now = time.time()
        for ip, until in list(tb.items()):
            if until <= now:
                try:
                    self.execute({"action": "unblock_ip", "params": {"ip": ip}}, internal=True)
                    log("timed block for %s expired - removed" % ip)
                except Exception as e:
                    log("could not remove expired block %s: %s" % (ip, e))
                tb.pop(ip, None)
        self.state["timed_blocks"] = tb

    def execute(self, cmd, internal=False):
        self.undo = None
        a, p = cmd["action"], cmd.get("params") or {}
        allowed = self.cfg.get("allowed_actions")
        if allowed is not None and a not in allowed and not internal:
            raise PermissionError("action '%s' is disabled on this host by allowed_actions in the agent config" % a)
        if a == "block_ip" or a == "unblock_ip":
            net = ipaddress.ip_network(str(p["ip"]), strict=False)
            ip = str(net) if net.num_addresses > 1 else str(net.network_address)
            if net.is_loopback:
                raise ValueError("refusing loopback")
            if a == "block_ip":
                if in_nets(ip.split("/")[0], self.trusted):
                    raise ValueError("%s is in trusted_ips; refusing" % ip)
                server_ip = self._server_ip()
                if server_ip and ipaddress.ip_address(server_ip) in net:
                    raise ValueError("%s would cut the agent off from the dashboard (%s)" % (ip, server_ip))
                for s in parse_ss():
                    if s["state"] == "ESTAB" and s["process"] in ("sshd", "sshd-session") and s["pip"] and \
                            not is_local(s["pip"]) and ipaddress.ip_address(s["pip"]) in net:
                        raise ValueError("an SSH session from %s is active (could be you). Block manually if intended." % s["pip"])
            fw, add = self._fw(), a == "block_ip"
            v6 = net.version == 6
            if fw == "ufw":
                cmds = [["ufw", "insert", "1", "deny", "from", ip, "comment", "netguard"]] if add else [["ufw", "delete", "deny", "from", ip]]
            elif fw == "firewalld":
                fam = "ipv6" if v6 else "ipv4"
                rule = 'rule family="%s" source address="%s" drop' % (fam, ip)
                op = "--add-rich-rule" if add else "--remove-rich-rule"
                cmds = [["firewall-cmd", "--permanent", op, rule], ["firewall-cmd", "--reload"]]
            else:
                ipt = "ip6tables" if v6 else "iptables"
                flag = "-I" if add else "-D"
                cmds = [[ipt, flag, "INPUT", "-s", ip, "-j", "DROP"], [ipt, flag, "OUTPUT", "-d", ip, "-j", "DROP"]]
            res = self._run_all(cmds, "%s %s via %s" % ("blocked" if add else "unblocked", ip, fw))
            tb = self.state.get("timed_blocks") or {}
            if add:
                self.undo = {"action": "unblock_ip", "params": {"ip": ip}, "label": "Unblock %s" % ip}
                hours = int(p.get("hours") or 0)
                if hours > 0:
                    tb[ip] = time.time() + hours * 3600
                    res = res.replace("blocked %s" % ip, "blocked %s for %d h (removed automatically after that)" % (ip, hours), 1)
            else:
                tb.pop(ip, None)
            self.state["timed_blocks"] = tb
            return res
        if a == "block_port":
            port, proto = int(p["port"]), str(p["protocol"])
            if proto not in ("tcp", "udp") or not 1 <= port <= 65535:
                raise ValueError("bad port/protocol")
            if port == self._ssh_port() and proto == "tcp":
                raise ValueError("refusing to block the SSH port")
            fw = self._fw()
            if fw == "ufw":
                cmds = [["ufw", "insert", "1", "deny", "%d/%s" % (port, proto)]]
            elif fw == "firewalld":
                cmds = [["firewall-cmd", "--permanent", "--remove-port=%d/%s" % (port, proto)],
                        ["firewall-cmd", "--permanent", "--add-rich-rule",
                         'rule port port="%d" protocol="%s" drop' % (port, proto)], ["firewall-cmd", "--reload"]]
            else:
                cmds = [["iptables", "-I", "INPUT", "-p", proto, "--dport", str(port), "-j", "DROP"]]
            res = self._run_all(cmds, "blocked inbound %d/%s via %s" % (port, proto, fw), tolerate_first=(fw == "firewalld"))
            self.undo = {"action": "unblock_port", "params": {"port": port, "protocol": proto}, "label": "Unblock %s/%d" % (proto, port)}
            return res
        if a == "unblock_port":
            port, proto = int(p["port"]), str(p["protocol"])
            if proto not in ("tcp", "udp") or not 1 <= port <= 65535:
                raise ValueError("bad port/protocol")
            fw = self._fw()
            if fw == "ufw":
                cmds = [["ufw", "delete", "deny", "%d/%s" % (port, proto)]]
            elif fw == "firewalld":
                cmds = [["firewall-cmd", "--permanent", "--remove-rich-rule",
                         'rule port port="%d" protocol="%s" drop' % (port, proto)], ["firewall-cmd", "--reload"]]
            else:
                cmds = [["iptables", "-D", "INPUT", "-p", proto, "--dport", str(port), "-j", "DROP"]]
            return self._run_all(cmds, "removed block for %d/%s via %s" % (port, proto, fw))
        if a == "quarantine_file":
            pid, name, path = int(p["pid"]), str(p["name"]), str(p["path"])
            real = os.path.realpath(path)
            if not os.path.isfile(real):
                raise ValueError("file not found: %s" % path)
            if ProcessTrust.expected_paths(name) and self.trust.info(pid)["trust"] == "system":
                raise ValueError("refusing: %s is the genuine system binary" % path)
            if real.startswith(("/usr/", "/bin/", "/sbin/", "/lib")):
                pk = self.trust.package_check(pid, real) if os.path.exists("/proc/%d" % pid) else {"status": "none"}
                if pk.get("status") == "ok":
                    raise ValueError("refusing: %s belongs to package %s and is unmodified" % (real, pk.get("package")))
            sha = hashlib.sha256()
            with open(real, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    sha.update(chunk)
            sha = sha.hexdigest()
            killed = []
            for d in os.listdir("/proc"):
                if d.isdigit() and int(d) > 1:
                    try:
                        if os.readlink("/proc/%s/exe" % d).replace(" (deleted)", "") == real:
                            os.kill(int(d), signal.SIGKILL)
                            killed.append(int(d))
                    except OSError:
                        pass
            qdir = os.path.join(self.cfg["state_dir"], "quarantine")
            os.makedirs(qdir, mode=0o700, exist_ok=True)
            qid = "%s-%d" % (sha[:12], int(time.time()))
            dest = os.path.join(qdir, qid + ".bin")
            shutil.move(real, dest)
            os.chmod(dest, 0)
            with open(os.path.join(qdir, qid + ".json"), "w") as f:
                json.dump({"id": qid, "name": name, "original_path": real, "sha256": sha, "quarantined": time.time()}, f)
            self.undo = {"action": "restore_quarantine", "params": {"id": qid}, "label": "Restore %s to %s" % (name, real)}
            return ("killed pid(s) %s; moved %s to quarantine as %s (SHA256 %s, permissions removed). It can no longer run. "
                    "Restore it from the action history if this was a mistake." % (killed, real, qid, sha))
        if a == "restore_quarantine":
            qid = str(p["id"])
            if not re.match(r"^[a-f0-9]{12}-\d+$", qid):
                raise ValueError("bad quarantine id")
            qdir = os.path.join(self.cfg["state_dir"], "quarantine")
            with open(os.path.join(qdir, qid + ".json")) as f:
                meta = json.load(f)
            dst = meta["original_path"]
            if os.path.exists(dst):
                raise ValueError("a file already exists at %s; not overwriting" % dst)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(os.path.join(qdir, qid + ".bin"), dst)
            os.chmod(dst, 0o755)
            os.remove(os.path.join(qdir, qid + ".json"))
            return "restored %s (mode 755; it is not started again automatically)" % dst
        if a == "kill_process":
            pid, name = int(p["pid"]), str(p["name"])
            if pid <= 1:
                raise ValueError("refusing to kill pid %d" % pid)
            try:
                with open("/proc/%d/comm" % pid) as f:
                    comm = f.read().strip()
            except OSError:
                return "process %d already gone" % pid
            if comm != name[:15]:
                raise ValueError("pid %d is now '%s', not '%s'; refusing (pid reused?)" % (pid, comm, name))
            self.trust.cache.pop(pid, None)
            t = self.trust.info(pid)
            if comm in PROTECTED_LINUX and t["trust"] in ("system", "unknown"):
                raise ValueError("refusing: %s (pid %d) is %s - %s" % (comm, pid,
                                 "the genuine binary" if t["trust"] == "system" else "unverifiable", t["reason"]))
            exe = exe_of(pid)
            os.kill(pid, signal.SIGTERM)
            for _ in range(20):
                time.sleep(0.25)
                if not os.path.exists("/proc/%d" % pid):
                    return "terminated %s (pid %d, exe %s, trust=%s, sha256=%s)" % (name, pid, exe, t["trust"], t.get("sha256", ""))
            os.kill(pid, signal.SIGKILL)
            return "killed %s (pid %d, exe %s) with SIGKILL" % (name, pid, exe)
        if a == "allow_process":
            name, path = str(p["name"]), str(p["path"])
            if not os.path.isabs(path) or not os.path.isfile(path):
                raise ValueError("file not found: %s" % path)
            if ProcessTrust.expected_paths(name):
                raise ValueError("%s is a core system daemon; it is verified by path + package checksum and cannot be allowlisted" % name)
            if name in LOLBINS_LINUX or os.path.basename(path) in LOLBINS_LINUX:
                raise ValueError("%s is a shell/network tool; allowlisting it would trust anything it runs. Use 'Accept this port only'." % name)
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            entry = {"name": name, "path": path, "sha256": h.hexdigest(), "added": time.time()}
            lst = [e for e in (self.state.get("process_allowlist") or []) if not (e.get("name") == name and e.get("path") == path)]
            self.state["process_allowlist"] = lst + [entry]
            return ("allowlisted %s at %s pinned to SHA256 %s - it will alert again if the file changes. "
                    "Its listeners are accepted on the next cycle." % (name, path, entry["sha256"]))
        if a == "accept_listener":
            key = "%s:%d" % (p["protocol"], int(p["port"]))
            b = set(self.state.get("listen_baseline") or [])
            b.add(key)
            self.state["listen_baseline"] = sorted(b)
            return "added %s to listener baseline" % key
        if a == "harden_fix":
            cid = str(p["check_id"])
            if not re.match(r"^[A-Za-z0-9_.\-]+$", cid):
                raise ValueError("bad check id")
            rc, out = run(["bash", self.cfg["harden_script"], "--apply", "--yes", "--only", cid, "--json", "-"], timeout=900)
            try:
                rep = json.loads(out[out.index('{"tool"'):])
                st = rep["results"][0]["status"] if rep["results"] else "unknown"
                detail = rep["results"][0]["detail"] if rep["results"] else ""
            except (ValueError, KeyError, IndexError):
                st, detail = "unknown", ""
            self.state["harden_last"] = 0  # re-audit this cycle
            log_part = out[:out.find('{"tool"')] if '{"tool"' in out else out
            if st not in ("fixed", "pass"):
                raise RuntimeError("check %s -> %s. %s\n%s" % (cid, st, detail, log_part[-2000:]))
            try:
                if rep.get("backup_dir"):
                    self.undo = {"action": "harden_restore", "params": {"backup": rep["backup_dir"]},
                                 "label": "Undo: restore previous settings"}
            except NameError:
                pass
            return "check %s -> %s. %s\n%s" % (cid, st, detail, log_part[-2000:])
        if a == "harden_restore":
            b = os.path.realpath(str(p["backup"]))
            if not b.startswith(HARDEN_BACKUP_ROOT + "/") or not os.path.isdir(b):
                raise ValueError("backup must be a directory under %s" % HARDEN_BACKUP_ROOT)
            rc, out = run(["bash", self.cfg["harden_script"], "--restore", b], timeout=300)
            self.state["harden_last"] = 0
            if rc != 0:
                raise RuntimeError(out[-2000:])
            return "restored settings from %s\n%s" % (b, out[-2000:])
        if a == "run_hardening_audit":
            self.state["harden_last"] = 0
            return "audit scheduled for this cycle"
        raise ValueError("unsupported action %s" % a)

    def _run_all(self, cmds, ok_msg, tolerate_first=False):
        out_all = []
        for i, c in enumerate(cmds):
            rc, out = run(c)
            out_all.append("$ %s\n%s" % (" ".join(c), out.strip()))
            if rc != 0 and not (tolerate_first and i == 0):
                raise RuntimeError("\n".join(out_all))
        return ok_msg + "\n" + "\n".join(out_all)

    def _ssh_port(self):
        rc, out = run(["sshd", "-T"])
        m = re.search(r"^port (\d+)", out, re.M)
        return int(m.group(1)) if m else 22

    def _server_ip(self):
        try:
            host = urllib.parse.urlparse(self.cfg["server_url"]).hostname
            return socket.gethostbyname(host)
        except (OSError, ValueError):
            return None

    # ---- transport --------------------------------------------------------
    def _ctx(self):
        if not self.cfg["server_url"].startswith("https"):
            return None
        if not self.cfg.get("verify_tls", True):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx
        return ssl.create_default_context(cafile=self.cfg.get("ca_file") or None)

    def post(self, path, payload):
        req = urllib.request.Request(self.cfg["server_url"].rstrip("/") + path, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json", "X-Agent-Token": self.cfg["agent_token"],
                                              "User-Agent": "netguard-agent/" + AGENT_VERSION}, method="POST")
        with urllib.request.urlopen(req, timeout=30, context=self._ctx()) as r:
            return json.loads(r.read().decode())

    # ---- main cycle -------------------------------------------------------
    def primary_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return ""

    def cycle(self, force_audit=False):
        self.alerts, self.conditions, self.hardening_summary = [], set(), None
        self.trust.reset()
        if not self.dry:
            self.expire_blocks()
        socks = parse_ss()
        listeners, per_ip = self.rule_sockets(socks)
        for fn in (self.rule_processes, self.rule_auth, lambda: self.rule_firewall_log(socks), self.rule_firewall_state):
            try:
                fn()
            except Exception as e:
                log("rule error: %r" % e)
        metrics = self.rule_resources()
        metrics["listening"] = len(listeners)
        metrics["established"] = sum(1 for s in socks if s["state"] == "ESTAB")
        self.rule_hardening(force=force_audit)

        prev = set(self.state.get("conditions") or [])
        cleared = sorted(prev - self.conditions)
        report = {"host": self.host, "os": self._os_name(), "ip": self.primary_ip(), "agent_version": AGENT_VERSION,
                  "metrics": metrics, "alerts": self.alerts, "cleared": cleared}
        if self.hardening_summary:
            report["hardening"] = self.hardening_summary
        report["capabilities"] = {"supported": SUPPORTED_ACTIONS, "allowed_actions": self.cfg.get("allowed_actions")}
        if self.dry:
            print(json.dumps(report, indent=2))
            self.trust.save()
            self.state.save()
            return
        try:
            resp = self.post("/api/agent/report", report)
        except Exception as e:  # URLError, HTTPError, InvalidURL, bad JSON, ...
            log("report failed: %r" % e)
            self.trust.save()
            self.state.save()  # keep log offsets; conditions are re-sent next time
            return
        self.state["conditions"] = sorted(self.conditions)
        rerun_audit = False
        for cmd in resp.get("commands", []):
            try:
                out = self.execute(cmd)
                status = "done"
            except Exception as e:
                out, status = "%s: %s" % (type(e).__name__, e), "failed"
                self.undo = None
            log("command %s %s -> %s" % (cmd["id"], cmd["action"], status))
            rerun_audit = rerun_audit or cmd["action"] in ("harden_fix", "run_hardening_audit")
            try:
                result = {"host": self.host, "id": cmd["id"], "status": status, "output": out[:8000]}
                if self.undo:
                    result["undo"] = self.undo
                self.post("/api/agent/command_result", result)
            except (urllib.error.URLError, OSError) as e:
                log("could not report command result: %s" % e)
        self.trust.save()
        self.state.save()
        if rerun_audit:
            self.cycle(force_audit=True)

    def _os_name(self):
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
        return "Linux"


def main():
    ap = argparse.ArgumentParser(description="NetGuard Linux agent")
    ap.add_argument("--config", default="/etc/netguard/agent.json")
    ap.add_argument("--once", action="store_true", help="run one cycle and exit (cron)")
    ap.add_argument("--daemon", action="store_true", help="loop forever (systemd)")
    ap.add_argument("--dry-run", action="store_true", help="print the report instead of sending it")
    args = ap.parse_args()

    cfg = dict(DEFAULTS)
    with open(args.config) as f:
        cfg.update(json.load(f))
    if not cfg.get("agent_token") and not args.dry_run:
        sys.exit("agent_token missing in %s" % args.config)
    if os.geteuid() != 0:
        log("warning: not root - process names, auth logs and remediation will be limited")

    agent = Agent(cfg, dry_run=args.dry_run)

    def _stop(*_):
        global STOP
        STOP = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    if not args.daemon:
        agent.cycle()
        return
    log("started, reporting to %s every %ss" % (cfg["server_url"], cfg["interval_seconds"]))
    while not STOP:
        t0 = time.time()
        try:
            agent.cycle()
        except Exception as e:
            log("cycle error: %r" % e)
        while not STOP and time.time() - t0 < cfg["interval_seconds"]:
            time.sleep(1)


if __name__ == "__main__":
    main()
