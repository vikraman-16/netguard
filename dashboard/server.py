#!/usr/bin/env python3
"""
NetGuard dashboard server.

Receives reports from the Linux / Windows monitoring agents, stores alerts in
SQLite, serves the web dashboard, and queues remediation commands that you
approve in the UI. Agents pick those commands up on their next check-in.

Standard library only (Python 3.8+). Run:
    python server.py                 # uses ./config.json (created on first run)
    python server.py --config /etc/netguard/config.json
"""
import argparse
import base64
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auth import INVITE_TTL, SESSION_MAX, AuthError, AuthManager  # noqa: E402

VERSION = "1.1.0"
SESSION_COOKIE = "ng_session"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["open", "acknowledged", "resolved", "suppressed"]

DEFAULT_CONFIG = {
    "listen_host": "127.0.0.1",
    "listen_port": 8787,
    "admin_user": "admin",
    "admin_password": None,          # generated on first run
    "agent_token": None,             # generated on first run
    "db_path": "netguard.db",
    "offline_after_seconds": 300,
    "tls_cert": "",
    "tls_key": "",
}

# --------------------------------------------------------------------------
# Remediation actions. The dashboard only queues actions from this list, and
# the agents re-validate every parameter before executing anything.
# --------------------------------------------------------------------------
NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


def _valid_ip(v):
    try:
        ip = ipaddress.ip_network(str(v), strict=False)
    except ValueError:
        raise ValueError("invalid IP address / CIDR")
    if ip.is_loopback:
        raise ValueError("refusing to act on a loopback address")
    if ip.num_addresses > 65536:
        raise ValueError("network too large (max /16)")
    return str(v)


def _valid_port(v):
    p = int(v)
    if not 1 <= p <= 65535:
        raise ValueError("port out of range")
    return p


def _valid_proto(v):
    v = str(v).lower()
    if v not in ("tcp", "udp"):
        raise ValueError("protocol must be tcp or udp")
    return v


def _valid_name(v):
    v = str(v)
    if not NAME_RE.match(v):
        raise ValueError("invalid name")
    return v


PROC_RE = re.compile(r"^[A-Za-z0-9 _.()+\-]{1,128}$")
PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\|/)[^\x00-\x1f\"<>|*?]{1,1020}$")


def _valid_procname(v):
    v = str(v)
    if not PROC_RE.match(v):
        raise ValueError("invalid process name")
    return v


def _valid_path(v):
    v = str(v)
    if not PATH_RE.match(v):
        raise ValueError("invalid executable path (must be absolute, no wildcards/quotes)")
    return v


def _valid_hours(v):
    h = int(v)
    if not 0 <= h <= 8760:
        raise ValueError("hours must be 0 (permanent) .. 8760")
    return h


ACTIONS = {
    "block_ip": {"label": "Block IP at host firewall", "params": {"ip": _valid_ip}, "optional": {"hours": _valid_hours}},
    "unblock_ip": {"label": "Remove IP block", "params": {"ip": _valid_ip}},
    "block_port": {"label": "Block inbound port", "params": {"port": _valid_port, "protocol": _valid_proto}},
    "unblock_port": {"label": "Remove port block", "params": {"port": _valid_port, "protocol": _valid_proto}},
    "kill_process": {"label": "Kill process", "params": {"pid": lambda v: int(v), "name": _valid_procname}},
    "quarantine_file": {"label": "Kill and quarantine executable",
                        "params": {"pid": lambda v: int(v), "name": _valid_procname, "path": _valid_path}},
    "restore_quarantine": {"label": "Restore file from quarantine", "params": {"id": _valid_name}},
    "allow_process": {"label": "Trust process (pinned to signer or hash)", "params": {"name": _valid_procname, "path": _valid_path}},
    "harden_fix": {"label": "Apply hardening fix", "params": {"check_id": _valid_name}},
    "harden_restore": {"label": "Undo hardening fix (restore backup)", "params": {"backup": _valid_path}},
    "run_hardening_audit": {"label": "Run hardening audit now", "params": {}},
    "accept_listener": {"label": "Accept listener into baseline", "params": {"port": _valid_port, "protocol": _valid_proto}},
}


def scope_sql(scope, col="host"):
    """SQL fragment limiting rows to the hosts a user may see (scope None = all)."""
    if scope is None:
        return "1=1", []
    if not scope:
        return "0=1", []
    return "%s IN (%s)" % (col, ",".join("?" * len(scope))), list(scope)


def validate_action(action, params):
    spec = ACTIONS.get(action)
    if not spec:
        raise ValueError("unknown action: %s" % action)
    params = params or {}
    out = {}
    for key, fn in spec["params"].items():
        if key not in params:
            raise ValueError("missing parameter: %s" % key)
        out[key] = fn(params[key])
    for key, fn in spec.get("optional", {}).items():
        if params.get(key) not in (None, ""):
            out[key] = fn(params[key])
    return out


# --------------------------------------------------------------------------
# Config / DB
# --------------------------------------------------------------------------
def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    created = False
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cfg.update(json.load(f))
    if cfg.get("admin_password") is None:
        cfg["admin_password"] = secrets.token_urlsafe(14)
        created = True
    if not cfg.get("agent_token"):
        cfg["agent_token"] = secrets.token_urlsafe(32)
        created = True
    if created:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        print("[netguard] wrote %s with new credentials:" % path)
        print("           admin user     : %s" % cfg["admin_user"])
        print("           admin password : %s  (one-time: you'll set your own + 2-factor at first sign-in)" % cfg["admin_password"])
        print("           agent token    : %s" % cfg["agent_token"])
    if not os.path.isabs(cfg["db_path"]):
        cfg["db_path"] = os.path.join(os.path.dirname(os.path.abspath(path)), cfg["db_path"])
    return cfg


SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    name TEXT PRIMARY KEY,
    os TEXT, ip TEXT, agent_version TEXT,
    first_seen REAL, last_seen REAL,
    metrics TEXT DEFAULT '{}',
    hardening TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    rule TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    details TEXT DEFAULT '',
    evidence TEXT DEFAULT '{}',
    suggested TEXT DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'open',
    count INTEGER NOT NULL DEFAULT 1,
    first_seen REAL, last_seen REAL,
    updated_at REAL,
    resolved_at REAL, resolved_by TEXT, note TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts(host, fingerprint, status);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, severity);
CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT,                -- NULL = all hosts
    rule TEXT NOT NULL,
    fingerprint TEXT,         -- NULL = whole rule
    reason TEXT DEFAULT '',
    created_by TEXT, created_at REAL, expires_at REAL
);
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    alert_id INTEGER,
    action TEXT NOT NULL,
    params TEXT DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',   -- pending/sent/done/failed/cancelled
    created_by TEXT, created_at REAL,
    sent_at REAL, finished_at REAL,
    output TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL, user TEXT, alert_id INTEGER, host TEXT,
    action TEXT, detail TEXT
);
"""


class DB:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        # migrations for databases created by older versions
        for table, col, ddl in (("hosts", "capabilities", "TEXT DEFAULT '{}'"), ("commands", "undo", "TEXT DEFAULT ''")):
            cols = [r[1] for r in self.conn.execute("PRAGMA table_info(%s)" % table)]
            if col not in cols:
                self.conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, ddl))
        self.conn.commit()

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur.lastrowid

    def audit(self, user, action, detail="", alert_id=None, host=None):
        self.x("INSERT INTO audit(ts,user,alert_id,host,action,detail) VALUES(?,?,?,?,?,?)",
               (time.time(), user, alert_id, host, action, detail))


def decode_alert(a):
    if not a:
        return a
    for k, default in (("evidence", {}), ("suggested", [])):
        try:
            a[k] = json.loads(a.get(k) or "null") or default
        except ValueError:
            a[k] = default
    return a


# --------------------------------------------------------------------------
# Core logic
# --------------------------------------------------------------------------
class NetGuard:
    def __init__(self, cfg, config_path=None):
        self.cfg = cfg
        self.db = DB(cfg["db_path"])
        self.auth = AuthManager(self.db, cfg, config_path)

    # ---- suppression -----------------------------------------------------
    def is_suppressed(self, host, rule, fingerprint):
        now = time.time()
        row = self.db.one(
            """SELECT id FROM suppressions
               WHERE rule=? AND (host IS NULL OR host=?)
                 AND (fingerprint IS NULL OR fingerprint=?)
                 AND (expires_at IS NULL OR expires_at > ?) LIMIT 1""",
            (rule, host, fingerprint, now))
        return row is not None

    # ---- agent ingest ----------------------------------------------------
    def ingest(self, report):
        now = time.time()
        host = _valid_name(report.get("host", ""))
        existing = self.db.one("SELECT name FROM hosts WHERE name=?", (host,))
        metrics = json.dumps(report.get("metrics") or {})
        if existing:
            self.db.x("UPDATE hosts SET os=?, ip=?, agent_version=?, last_seen=?, metrics=? WHERE name=?",
                      (report.get("os", ""), report.get("ip", ""), report.get("agent_version", ""), now, metrics, host))
        else:
            self.db.x("INSERT INTO hosts(name,os,ip,agent_version,first_seen,last_seen,metrics) VALUES(?,?,?,?,?,?,?)",
                      (host, report.get("os", ""), report.get("ip", ""), report.get("agent_version", ""), now, now, metrics))
            self.db.audit("agent", "host_registered", "new host checked in", host=host)
        if report.get("hardening"):
            self.db.x("UPDATE hosts SET hardening=? WHERE name=?", (json.dumps(report["hardening"]), host))
        caps = report.get("capabilities")
        if isinstance(caps, dict):
            allowed = caps.get("allowed_actions")
            clean = {"supported": [a for a in caps.get("supported") or [] if a in ACTIONS],
                     "allowed_actions": None if allowed is None else [a for a in allowed if a in ACTIONS]}
            self.db.x("UPDATE hosts SET capabilities=? WHERE name=?", (json.dumps(clean), host))

        # agent is back -> auto-resolve its offline alert
        self.db.x("""UPDATE alerts SET status='resolved', resolved_at=?, resolved_by='system',
                     note='agent checked in again', updated_at=?
                     WHERE host=? AND rule='agent_offline' AND status IN ('open','acknowledged')""",
                  (now, now, host))

        new_count = 0
        for a in report.get("alerts") or []:
            if self._upsert_alert(host, a, now):
                new_count += 1

        # Alerts the agent says are no longer true (e.g. hardening check now passing)
        for fp in report.get("cleared") or []:
            self.db.x("""UPDATE alerts SET status='resolved', resolved_at=?, resolved_by='agent',
                         note='condition cleared on host', updated_at=?
                         WHERE host=? AND fingerprint=? AND status IN ('open','acknowledged')""",
                      (now, now, host, str(fp)))

        # Hand pending commands to the agent
        cmds = self.db.q("SELECT id, action, params, alert_id FROM commands WHERE host=? AND status='pending' ORDER BY id",
                         (host,))
        for c in cmds:
            c["params"] = json.loads(c["params"] or "{}")
            self.db.x("UPDATE commands SET status='sent', sent_at=? WHERE id=?", (now, c["id"]))
        return {"ok": True, "new_alerts": new_count, "commands": cmds, "server_time": now}

    def _upsert_alert(self, host, a, now):
        rule = _valid_name(a.get("rule", "unknown"))
        sev = a.get("severity", "medium")
        if sev not in SEVERITIES:
            sev = "medium"
        fp = str(a.get("fingerprint") or rule)[:300]
        title = str(a.get("title", rule))[:300]
        details = str(a.get("details", ""))[:4000]
        evidence = json.dumps(a.get("evidence") or {})[:20000]
        suggested = []
        for s in a.get("suggested") or []:
            try:
                p = validate_action(s.get("action"), s.get("params") or {})
                suggested.append({"action": s["action"], "params": p,
                                  "label": str(s.get("label") or ACTIONS[s["action"]]["label"])[:120]})
            except (ValueError, TypeError, KeyError):
                continue
        suggested = json.dumps(suggested)

        if self.is_suppressed(host, rule, fp):
            return False

        cur = self.db.one("""SELECT id FROM alerts WHERE host=? AND fingerprint=?
                             AND status IN ('open','acknowledged') ORDER BY id DESC LIMIT 1""", (host, fp))
        if cur:
            self.db.x("""UPDATE alerts SET count=count+1, last_seen=?, severity=?, title=?, details=?,
                         evidence=?, suggested=?, updated_at=? WHERE id=?""",
                      (now, sev, title, details, evidence, suggested, now, cur["id"]))
            return False
        self.db.x("""INSERT INTO alerts(host,rule,fingerprint,severity,title,details,evidence,suggested,
                     status,count,first_seen,last_seen,updated_at)
                     VALUES(?,?,?,?,?,?,?,?,'open',1,?,?,?)""",
                  (host, rule, fp, sev, title, details, evidence, suggested, now, now, now))
        return True

    def command_result(self, host, body):
        cid = int(body.get("id"))
        status = body.get("status")
        if status not in ("done", "failed"):
            raise ValueError("status must be done or failed")
        cmd = self.db.one("SELECT * FROM commands WHERE id=? AND host=?", (cid, host))
        if not cmd:
            raise ValueError("unknown command")
        now = time.time()
        output = str(body.get("output", ""))[:20000]
        undo = ""
        u = body.get("undo")
        if status == "done" and isinstance(u, dict):
            try:
                undo = json.dumps({"action": u["action"], "params": validate_action(u["action"], u.get("params") or {}),
                                   "label": str(u.get("label") or ACTIONS[u["action"]]["label"])[:120]})
            except (ValueError, TypeError, KeyError):
                undo = ""
        self.db.x("UPDATE commands SET status=?, finished_at=?, output=?, undo=? WHERE id=?", (status, now, output, undo, cid))
        self.db.audit("agent", "command_" + status, "%s: %s" % (cmd["action"], output[:500]),
                      alert_id=cmd["alert_id"], host=host)
        # A successful remediation resolves the linked alert automatically.
        if status == "done" and cmd["alert_id"] and cmd["action"] not in (
                "run_hardening_audit", "unblock_ip", "unblock_port", "harden_restore", "restore_quarantine"):
            self.db.x("""UPDATE alerts SET status='resolved', resolved_at=?, resolved_by=?, updated_at=?,
                         note=? WHERE id=? AND status IN ('open','acknowledged')""",
                      (now, cmd["created_by"], now, "remediated: " + cmd["action"], cmd["alert_id"]))
        return {"ok": True}

    # ---- offline watchdog ----------------------------------------------
    def watchdog(self):
        while True:
            try:
                limit = time.time() - int(self.cfg["offline_after_seconds"])
                for h in self.db.q("SELECT name, last_seen FROM hosts WHERE last_seen < ?", (limit,)):
                    self._upsert_alert(h["name"], {
                        "rule": "agent_offline", "severity": "high",
                        "fingerprint": "agent_offline",
                        "title": "Agent has not checked in",
                        "details": "No report from %s since %s. The host may be down, the agent stopped, "
                                   "or network/firewall is blocking it." % (
                                       h["name"], time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["last_seen"]))),
                        "evidence": {"last_seen": h["last_seen"]},
                    }, time.time())
            except Exception as e:  # keep the watchdog alive
                print("[watchdog] %s" % e, file=sys.stderr)
            time.sleep(30)

    # ---- UI-facing (every method takes the caller's host scope: None = all) ----
    @staticmethod
    def _in_scope(host, scope):
        return scope is None or host in scope

    def _check_host(self, host, scope):
        if not self._in_scope(host, scope):
            raise LookupError("not found")

    def summary(self, scope=None):
        f, fa = scope_sql(scope)
        by_sev = {s: 0 for s in SEVERITIES}
        for r in self.db.q("SELECT severity, COUNT(*) n FROM alerts WHERE status IN ('open','acknowledged') AND %s GROUP BY severity" % f, fa):
            by_sev[r["severity"]] = r["n"]
        by_status = {s: 0 for s in STATUSES}
        for r in self.db.q("SELECT status, COUNT(*) n FROM alerts WHERE %s GROUP BY status" % f, fa):
            by_status[r["status"]] = r["n"]
        limit = time.time() - int(self.cfg["offline_after_seconds"])
        hf, hfa = scope_sql(scope, "name")
        hosts = self.db.one("SELECT COUNT(*) total, SUM(CASE WHEN last_seen >= ? THEN 1 ELSE 0 END) online FROM hosts WHERE %s" % hf,
                            [limit] + hfa)
        day_ago = time.time() - 86400
        rules = self.db.q("""SELECT rule, COUNT(*) n FROM alerts WHERE first_seen >= ? AND %s
                             GROUP BY rule ORDER BY n DESC LIMIT 8""" % f, [day_ago] + fa)
        buckets = [0] * 24
        now = time.time()
        for r in self.db.q("SELECT first_seen FROM alerts WHERE first_seen >= ? AND %s" % f, [day_ago] + fa):
            idx = 23 - int((now - r["first_seen"]) // 3600)
            if 0 <= idx < 24:
                buckets[idx] += 1
        pending = self.db.one("SELECT COUNT(*) n FROM commands WHERE status IN ('pending','sent') AND %s" % f, fa)["n"]
        return {"by_severity": by_sev, "by_status": by_status,
                "hosts_total": hosts["total"] or 0, "hosts_online": hosts["online"] or 0,
                "top_rules_24h": rules, "timeline_24h": buckets, "pending_commands": pending,
                "server_time": now, "version": VERSION}

    def list_alerts(self, qs, scope=None):
        f, fa = scope_sql(scope)
        where, args = [f], list(fa)
        status = qs.get("status", ["active"])[0]
        if status == "active":
            where.append("status IN ('open','acknowledged')")
        elif status in STATUSES:
            where.append("status=?")
            args.append(status)
        sev = qs.get("severity", [""])[0]
        if sev in SEVERITIES:
            where.append("severity=?")
            args.append(sev)
        host = qs.get("host", [""])[0]
        if host:
            where.append("host=?")
            args.append(host)
        text = qs.get("q", [""])[0]
        if text:
            where.append("(title LIKE ? OR details LIKE ? OR rule LIKE ? OR evidence LIKE ?)")
            args += ["%" + text + "%"] * 4
        sql = "SELECT * FROM alerts WHERE " + " AND ".join(where)
        sql += """ ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                   WHEN 'low' THEN 3 ELSE 4 END, last_seen DESC LIMIT 500"""
        return [decode_alert(a) for a in self.db.q(sql, args)]

    def capabilities(self, host):
        row = self.db.one("SELECT capabilities FROM hosts WHERE name=?", (host,))
        try:
            return json.loads((row or {}).get("capabilities") or "{}")
        except ValueError:
            return {}

    def check_allowed(self, host, action):
        caps = self.capabilities(host)
        if caps.get("supported") and action not in caps["supported"]:
            raise ValueError("the agent on %s does not support '%s' (update the agent)" % (host, action))
        allowed = caps.get("allowed_actions")
        if allowed is not None and action not in allowed:
            raise ValueError("'%s' is disabled on %s (safe mode). Re-run setup with full control to allow it." % (action, host))

    def get_alert(self, aid, scope=None):
        a = decode_alert(self.db.one("SELECT * FROM alerts WHERE id=?", (aid,)))
        if not a or not self._in_scope(a["host"], scope):
            return None
        a["commands"] = self.db.q("SELECT * FROM commands WHERE alert_id=? ORDER BY id DESC", (aid,))
        for c in a["commands"]:
            c["undo"] = json.loads(c["undo"]) if c.get("undo") else None
        a["capabilities"] = self.capabilities(a["host"])
        a["history"] = self.db.q("SELECT * FROM audit WHERE alert_id=? ORDER BY id DESC LIMIT 100", (aid,))
        a["related"] = self.db.q("""SELECT id, title, severity, status, last_seen FROM alerts
                                    WHERE host=? AND fingerprint=? AND id<>? ORDER BY id DESC LIMIT 10""",
                                 (a["host"], a["fingerprint"], aid))
        return a

    def set_status(self, user, aid, status, note, scope=None):
        if status not in ("open", "acknowledged", "resolved"):
            raise ValueError("invalid status")
        a = self.db.one("SELECT * FROM alerts WHERE id=?", (aid,))
        if not a or not self._in_scope(a["host"], scope):
            raise LookupError("alert not found")
        now = time.time()
        if status == "resolved":
            self.db.x("UPDATE alerts SET status=?, resolved_at=?, resolved_by=?, note=?, updated_at=? WHERE id=?",
                      (status, now, user, note, now, aid))
        else:
            self.db.x("UPDATE alerts SET status=?, note=?, updated_at=?, resolved_at=NULL, resolved_by=NULL WHERE id=?",
                      (status, note, now, aid))
        self.db.audit(user, "status_" + status, note, alert_id=aid, host=a["host"])

    def take_action(self, user, aid, body, scope=None, is_owner=True):
        a = self.db.one("SELECT * FROM alerts WHERE id=?", (aid,))
        if not a or not self._in_scope(a["host"], scope):
            raise LookupError("alert not found")
        action = body.get("action")
        note = str(body.get("note", ""))[:1000]
        now = time.time()
        if action == "suppress":
            scope_kind = body.get("scope", "fingerprint_host")
            if scope_kind not in ("fingerprint_host", "rule_host", "fingerprint_all", "rule_all"):
                raise ValueError("bad suppression scope")
            if scope_kind.endswith("_all") and not is_owner:
                raise PermissionError("Only owners can hide alerts on every server.")
            host = None if scope_kind.endswith("_all") else a["host"]
            fp = None if scope_kind.startswith("rule") else a["fingerprint"]
            days = body.get("days")
            expires = now + float(days) * 86400 if days else None
            sid = self.db.x("""INSERT INTO suppressions(host,rule,fingerprint,reason,created_by,created_at,expires_at)
                               VALUES(?,?,?,?,?,?,?)""", (host, a["rule"], fp, note, user, now, expires))
            sql = "UPDATE alerts SET status='suppressed', updated_at=?, note=? WHERE rule=? AND status IN ('open','acknowledged')"
            args = [now, "suppressed: " + note, a["rule"]]
            if host:
                sql += " AND host=?"
                args.append(host)
            if fp:
                sql += " AND fingerprint=?"
                args.append(fp)
            self.db.x(sql, args)
            self.db.audit(user, "suppress", "scope=%s days=%s %s" % (scope_kind, days, note), alert_id=aid, host=a["host"])
            return {"ok": True, "suppression_id": sid}

        params = validate_action(action, body.get("params") or {})
        target_host = a["host"]
        self.check_allowed(target_host, action)
        cid = self.db.x("""INSERT INTO commands(host,alert_id,action,params,status,created_by,created_at)
                           VALUES(?,?,?,?,'pending',?,?)""",
                        (target_host, aid, action, json.dumps(params), user, now))
        if a["status"] == "open":
            self.db.x("UPDATE alerts SET status='acknowledged', updated_at=? WHERE id=?", (now, aid))
        self.db.audit(user, "queue_" + action, json.dumps(params) + (" | " + note if note else ""),
                      alert_id=aid, host=target_host)
        return {"ok": True, "command_id": cid}

    def host_action(self, user, host, body, scope=None):
        """Actions not tied to an alert (e.g. block an IP manually, run audit)."""
        if not self.db.one("SELECT name FROM hosts WHERE name=?", (host,)) or not self._in_scope(host, scope):
            raise LookupError("host not found")
        action = body.get("action")
        params = validate_action(action, body.get("params") or {})
        self.check_allowed(host, action)
        cid = self.db.x("""INSERT INTO commands(host,alert_id,action,params,status,created_by,created_at)
                           VALUES(?,NULL,?,?,'pending',?,?)""", (host, action, json.dumps(params), user, time.time()))
        self.db.audit(user, "queue_" + action, json.dumps(params), host=host)
        return {"ok": True, "command_id": cid}

    def undo_command(self, user, cid, note="", scope=None):
        c = self.db.one("SELECT * FROM commands WHERE id=?", (cid,))
        if not c or not self._in_scope(c["host"], scope):
            raise LookupError("command not found")
        if c["status"] != "done" or not c.get("undo"):
            raise ValueError("this command has nothing to undo")
        u = json.loads(c["undo"])
        params = validate_action(u["action"], u["params"])
        self.check_allowed(c["host"], u["action"])
        now = time.time()
        nid = self.db.x("""INSERT INTO commands(host,alert_id,action,params,status,created_by,created_at)
                           VALUES(?,?,?,?,'pending',?,?)""",
                        (c["host"], c["alert_id"], u["action"], json.dumps(params), user, now))
        self.db.x("UPDATE commands SET undo='' WHERE id=?", (cid,))   # each command can be undone once
        if c["alert_id"]:
            self.db.x("""UPDATE alerts SET status='open', resolved_at=NULL, resolved_by=NULL, updated_at=?, note=?
                         WHERE id=?""", (now, "reopened: undid " + c["action"], c["alert_id"]))
        self.db.audit(user, "undo_" + c["action"], "%s %s | %s" % (u["action"], json.dumps(params), note),
                      alert_id=c["alert_id"], host=c["host"])
        return {"ok": True, "command_id": nid}

    def cancel_command(self, user, cid, scope=None):
        c = self.db.one("SELECT * FROM commands WHERE id=?", (cid,))
        if not c or not self._in_scope(c["host"], scope):
            raise LookupError("command not found")
        self.db.x("UPDATE commands SET status='cancelled', finished_at=? WHERE id=? AND status='pending'", (time.time(), cid))
        self.db.audit(user, "cancel_command", "command %s" % cid, host=c["host"])

    def bulk(self, user, body, scope=None):
        ids = [int(i) for i in body.get("ids", [])][:500]
        status = body.get("status")
        note = str(body.get("note", ""))[:1000]
        for i in ids:
            self.set_status(user, i, status, note, scope)
        return {"ok": True, "updated": len(ids)}

    def hosts(self, scope=None):
        limit = time.time() - int(self.cfg["offline_after_seconds"])
        hf, hfa = scope_sql(scope, "name")
        out = []
        for h in self.db.q("SELECT * FROM hosts WHERE %s ORDER BY name" % hf, hfa):
            h["online"] = h["last_seen"] >= limit
            h["metrics"] = json.loads(h["metrics"] or "{}")
            h["hardening"] = json.loads(h["hardening"] or "{}")
            h["capabilities"] = json.loads(h.get("capabilities") or "{}")
            counts = self.db.q("""SELECT severity, COUNT(*) n FROM alerts WHERE host=?
                                  AND status IN ('open','acknowledged') GROUP BY severity""", (h["name"],))
            h["open_alerts"] = {c["severity"]: c["n"] for c in counts}
            out.append(h)
        return out

    def commands(self, scope=None):
        f, fa = scope_sql(scope)
        rows = self.db.q("SELECT * FROM commands WHERE %s ORDER BY id DESC LIMIT 300" % f, fa)
        for r in rows:
            r["undo"] = json.loads(r["undo"]) if r.get("undo") else None
        return rows

    def suppressions(self, scope=None):
        f, fa = scope_sql(scope)
        return self.db.q("SELECT * FROM suppressions WHERE host IS NULL OR %s ORDER BY id DESC" % f, fa)

    def delete_suppression(self, user, sid, scope=None, is_owner=True):
        s = self.db.one("SELECT * FROM suppressions WHERE id=?", (sid,))
        if not s:
            raise LookupError("not found")
        if s["host"] is None and not is_owner:
            raise PermissionError("Only owners can remove an all-servers suppression.")
        if s["host"] is not None and not self._in_scope(s["host"], scope):
            raise LookupError("not found")
        self.db.x("DELETE FROM suppressions WHERE id=?", (sid,))
        self.db.audit(user, "delete_suppression", "suppression %s (%s)" % (sid, s["rule"]), host=s["host"])

    def audit_log(self, scope=None):
        if scope is None:
            return self.db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 500")
        f, fa = scope_sql(scope)
        return self.db.q("SELECT * FROM audit WHERE %s ORDER BY id DESC LIMIT 500" % f, fa)


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "NetGuard/" + VERSION
    app = None  # type: NetGuard

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self._client_ip(), fmt % args))

    # ---- helpers --------------------------------------------------------
    def _send(self, code, payload, ctype="application/json", headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        self.send_header("Cache-Control", "no-store")
        if self._secure():
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, where):
        self.send_response(302)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 5 * 1024 * 1024:
            raise ValueError("body too large")
        raw = self.rfile.read(n) if n else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _client_ip(self):
        ip = self.client_address[0]
        # Behind a local reverse proxy (tailscale serve, nginx) the real client is in X-Forwarded-For.
        if ip in ("127.0.0.1", "::1"):
            xff = self.headers.get("X-Forwarded-For", "") if hasattr(self, "headers") and self.headers else ""
            if xff:
                ip = xff.split(",")[0].strip()
        return ip

    def _secure(self):
        if not getattr(self, "headers", None):
            return False
        host = (self.headers.get("Host") or "").split(":")[0]
        return bool(self.app.cfg.get("tls_cert")) or self.headers.get("X-Forwarded-Proto", "").lower() == "https" \
            or host.endswith(".ts.net")

    def _cookie(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == SESSION_COOKIE:
                return v
        return None

    def _session_cookie(self, token, max_age):
        attrs = "%s=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d" % (SESSION_COOKIE, token, max_age)
        if self._secure():
            attrs += "; Secure"
        return ("Set-Cookie", attrs)

    def _agent(self):
        tok = self.headers.get("X-Agent-Token", "")
        return hmac.compare_digest(tok, self.app.cfg["agent_token"])

    def _user(self, need="viewer", write=False, page=False):
        """Returns the signed-in user row, or sends 401/403 (or a redirect for pages) and returns None."""
        u, _ = self.app.auth.session_user(self._cookie())
        if not u:
            if page:
                self._redirect("/login")
            else:
                self._send(401, {"error": "Signed out. Please sign in again.", "login": True})
            return None
        # CSRF guard: browsers can't add custom headers cross-site without a CORS preflight.
        if write and self.headers.get("X-NetGuard") != "1":
            self._send(403, {"error": "missing X-NetGuard header"})
            return None
        if not AuthManager.can(u, need):
            self._send(403, {"error": "Your role (%s) can't do this; it needs %s." % (u["role"], need)})
            return None
        return u

    # ---- routing --------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path, qs = u.path, parse_qs(u.query)
        try:
            if path == "/healthz":
                return self._send(200, {"ok": True})
            if path in ("/login", "/login.html"):
                return self._static("login.html")
            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path in ("/", "/index.html"):
                if not self._user(page=True):
                    return
                return self._static("index.html")

            user = self._user()
            if not user:
                return
            scope = self.app.auth.scope(user)
            if path == "/api/me":
                return self._send(200, dict(self.app.auth.public(user), scope=scope))
            if path == "/api/summary":
                return self._send(200, self.app.summary(scope))
            if path == "/api/alerts":
                return self._send(200, self.app.list_alerts(qs, scope))
            m = re.match(r"^/api/alerts/(\d+)$", path)
            if m:
                a = self.app.get_alert(int(m.group(1)), scope)
                return self._send(200, a) if a else self._send(404, {"error": "not found"})
            if path == "/api/hosts":
                return self._send(200, self.app.hosts(scope))
            if path == "/api/commands":
                return self._send(200, self.app.commands(scope))
            if path == "/api/suppressions":
                return self._send(200, self.app.suppressions(scope))
            if path == "/api/audit":
                return self._send(200, self.app.audit_log(scope))
            if path == "/api/actions":
                return self._send(200, {k: v["label"] for k, v in ACTIONS.items()})
            if path == "/api/sessions":
                return self._send(200, self.app.auth.sessions(user))
            if path == "/api/users":
                if not AuthManager.can(user, "owner"):
                    return self._send(403, {"error": "Only owners can manage people."})
                return self._send(200, {"users": self.app.auth.list_users(),
                                        "hosts": [h["name"] for h in self.app.db.q("SELECT name FROM hosts ORDER BY name")]})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            # ---- agent endpoints ----
            if path.startswith("/api/agent/"):
                if not self._agent():
                    return self._send(401, {"error": "bad agent token"})
                body = self._body()
                if path == "/api/agent/report":
                    return self._send(200, self.app.ingest(body))
                if path == "/api/agent/command_result":
                    return self._send(200, self.app.command_result(_valid_name(body.get("host", "")), body))
                return self._send(404, {"error": "not found"})

            # ---- sign-in flow (no session yet; still CSRF-guarded) ----
            if path.startswith("/api/auth/") or path.startswith("/api/invite/"):
                if self.headers.get("X-NetGuard") != "1":
                    return self._send(403, {"error": "missing X-NetGuard header"})
                return self._auth_route(path, self._body())

            # ---- signed-in endpoints ----
            user = self._user(write=True)
            if not user:
                return
            body = self._body()
            auth = self.app.auth
            scope = auth.scope(user)
            name = user["username"]
            is_owner = AuthManager.can(user, "owner")

            if path == "/api/me/password":
                auth.change_password(user, body.get("current"), body.get("new"))
                return self._send(200, {"ok": True})
            m = re.match(r"^/api/sessions/(\d+)/revoke$", path)
            if m:
                auth.revoke_session(user, int(m.group(1)))
                return self._send(200, {"ok": True})

            # people management: owners only
            if path.startswith("/api/users"):
                if not is_owner:
                    return self._send(403, {"error": "Only owners can manage people."})
                if path == "/api/users/invite":
                    tok = auth.create_invite(user, body.get("role", "viewer"), body.get("hosts", "*"), body.get("note", ""))
                    return self._send(200, {"link_path": "/login#invite=" + tok, "expires_hours": INVITE_TTL // 3600})
                m = re.match(r"^/api/users/(\d+)/(update|reset|delete)$", path)
                if m:
                    uid, op = int(m.group(1)), m.group(2)
                    if op == "update":
                        return self._send(200, auth.update_user(user, uid, body))
                    if op == "delete":
                        auth.delete_user(user, uid)
                        return self._send(200, {"ok": True})
                    target = auth.user(uid)
                    if not target:
                        return self._send(404, {"error": "user not found"})
                    tok = auth.create_invite(user, target["role"], json.loads(target["hosts"]), "reset for " + target["username"],
                                             kind="reset", user_id=uid)
                    return self._send(200, {"link_path": "/login#reset=" + tok, "expires_hours": INVITE_TTL // 3600})
                return self._send(404, {"error": "not found"})

            # everything below changes things: admins and owners only
            if not AuthManager.can(user, "admin"):
                return self._send(403, {"error": "Your role (viewer) is read-only."})
            m = re.match(r"^/api/alerts/(\d+)/(status|action)$", path)
            if m:
                aid = int(m.group(1))
                if m.group(2) == "status":
                    self.app.set_status(name, aid, body.get("status"), str(body.get("note", ""))[:1000], scope)
                    return self._send(200, {"ok": True})
                return self._send(200, self.app.take_action(name, aid, body, scope, is_owner))
            if path == "/api/alerts/bulk":
                return self._send(200, self.app.bulk(name, body, scope))
            m = re.match(r"^/api/hosts/([A-Za-z0-9_.\-]+)/action$", path)
            if m:
                return self._send(200, self.app.host_action(name, m.group(1), body, scope))
            m = re.match(r"^/api/commands/(\d+)/undo$", path)
            if m:
                return self._send(200, self.app.undo_command(name, int(m.group(1)), str(body.get("note", ""))[:1000], scope))
            m = re.match(r"^/api/commands/(\d+)/cancel$", path)
            if m:
                self.app.cancel_command(name, int(m.group(1)), scope)
                return self._send(200, {"ok": True})
            m = re.match(r"^/api/suppressions/(\d+)/delete$", path)
            if m:
                self.app.delete_suppression(name, int(m.group(1)), scope, is_owner)
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})
        except AuthError as e:
            return self._send(400, {"error": str(e)})
        except PermissionError as e:
            return self._send(403, {"error": str(e)})
        except LookupError as e:
            return self._send(404, {"error": str(e)})
        except (ValueError, TypeError) as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": str(e)})

    def _auth_route(self, path, body):
        auth = self.app.auth
        ip, ua = self._client_ip(), self.headers.get("User-Agent", "")

        def signed_in(res):
            hdr = [self._session_cookie(res["session"], SESSION_MAX)]
            return self._send(200, {"ok": True, "user": res["user"]}, headers=hdr)

        if path == "/api/auth/login":
            return self._send(200, auth.login(body.get("username"), body.get("password"), ip))
        if path == "/api/auth/password":
            return self._send(200, auth.set_new_password(body.get("ticket"), body.get("new_password")))
        if path == "/api/auth/enroll/start":
            return self._send(200, auth.enroll_start(body.get("ticket")))
        if path == "/api/auth/enroll/finish":
            return signed_in(auth.enroll_finish(body.get("ticket"), body.get("code"), ip, ua))
        if path == "/api/auth/totp":
            return signed_in(auth.verify_totp(body.get("ticket"), body.get("code"), ip, ua))
        if path == "/api/auth/logout":
            auth.logout(self._cookie())
            return self._send(200, {"ok": True}, headers=[self._session_cookie("", 0)])
        if path == "/api/invite/info":
            _, info = auth.invite_info(body.get("token"))
            return self._send(200, info)
        if path == "/api/invite/accept":
            return self._send(200, auth.accept_invite(body.get("token"), body.get("username"),
                                                      body.get("display_name"), body.get("password")))
        return self._send(404, {"error": "not found"})

    def _static(self, rel):
        full = os.path.realpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(os.path.realpath(STATIC_DIR) + os.sep) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        with open(full, "rb") as f:
            return self._send(200, f.read(), ctype)


def main():
    ap = argparse.ArgumentParser(description="NetGuard dashboard server")
    ap.add_argument("--config", default=os.path.join(BASE_DIR, "config.json"))
    ap.add_argument("--host", help="override listen_host")
    ap.add_argument("--port", type=int, help="override listen_port")
    ap.add_argument("--reset-user", metavar="USERNAME",
                    help="reset (or create as owner) an account: prints a one-time password, clears its 2-factor setup, then exits")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.reset_user:
        db = DB(cfg["db_path"])
        pw = AuthManager(db, cfg, args.config).reset_from_cli(args.reset_user)
        print("Account '%s' reset. One-time password: %s" % (args.reset_user.lower(), pw))
        print("Sign in with it; you will be asked to choose a new password and set up 2-factor again.")
        return
    if args.host:
        cfg["listen_host"] = args.host
    if args.port:
        cfg["listen_port"] = args.port

    app = NetGuard(cfg, args.config)
    Handler.app = app
    threading.Thread(target=app.watchdog, daemon=True).start()

    httpd = ThreadingHTTPServer((cfg["listen_host"], int(cfg["listen_port"])), Handler)
    scheme = "http"
    if cfg.get("tls_cert") and cfg.get("tls_key"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cfg["tls_cert"], cfg["tls_key"])
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    elif cfg["listen_host"] not in ("127.0.0.1", "localhost", "::1"):
        print("[netguard] WARNING: listening on %s without TLS. Credentials travel in clear text; "
              "use Tailscale (tailscale serve), set tls_cert/tls_key, or put it behind a TLS reverse proxy." % cfg["listen_host"])
    print("[netguard] dashboard on %s://%s:%s  (db: %s)" % (scheme, cfg["listen_host"], cfg["listen_port"], cfg["db_path"]))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
