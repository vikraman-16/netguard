"""
NetGuard notifications: email (SMTP), Telegram, Discord, Microsoft Teams (Workflows webhook), generic webhook.
New alerts at or above each channel's minimum severity are sent right away (rate-limited), plus an optional
daily summary. Channel secrets (passwords, bot tokens, webhook URLs) are stored encrypted with the master key.
"""
import json
import queue
import smtplib
import ssl
import threading
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RATE_PER_HOUR = 20

# type -> (label, [(field, label, secret)])
CHANNEL_TYPES = {
    "email": ("Email (SMTP)", [("host", "SMTP server (e.g. smtp.gmail.com)", False), ("port", "Port (587 / 465 / 25)", False),
                               ("security", "Security: starttls, ssl or none", False), ("username", "Username", False),
                               ("password", "Password / app password", True), ("from", "From address", False),
                               ("to", "Send to (comma-separated)", False)]),
    "telegram": ("Telegram bot", [("bot_token", "Bot token (from @BotFather)", True), ("chat_id", "Chat ID", False)]),
    "discord": ("Discord webhook", [("webhook_url", "Webhook URL", True)]),
    "teams": ("Microsoft Teams (Workflows webhook)", [("webhook_url", "Workflow webhook URL", True)]),
    "webhook": ("Generic webhook (JSON POST)", [("url", "URL (https://...)", True), ("header", "Optional header, e.g. Authorization: Bearer xyz", True)]),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS notify_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, type TEXT NOT NULL, config TEXT NOT NULL,
    min_severity TEXT NOT NULL DEFAULT 'high', digest INTEGER NOT NULL DEFAULT 1, enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT, created_at REAL, last_status TEXT DEFAULT '', last_at REAL
);
CREATE TABLE IF NOT EXISTS notify_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, channel_id INTEGER, kind TEXT, alert_id INTEGER, ok INTEGER, detail TEXT
);
"""


class NotifyError(Exception):
    pass


class Notifier:
    def __init__(self, app):
        self.app = app
        self.db = app.db
        with self.db.lock:
            self.db.conn.executescript(SCHEMA)
            self.db.conn.commit()
        self.q = queue.Queue()
        self.sent = {}          # channel_id -> [timestamps]
        self.dropped = {}       # channel_id -> count over the rate limit
        threading.Thread(target=self._worker, daemon=True).start()

    # ---- configuration ----------------------------------------------------
    def _purpose(self, cid):
        return "notify:%d" % cid

    def _clean_config(self, ctype, cfg, old=None):
        if ctype not in CHANNEL_TYPES:
            raise ValueError("unknown channel type")
        out = {}
        for key, label, secret in CHANNEL_TYPES[ctype][1]:
            v = str((cfg or {}).get(key, "") or "").strip()
            if secret and not v and old:
                v = old.get(key, "")          # blank secret field on edit = keep the stored one
            out[key] = v
        if ctype == "email":
            if not out["host"] or not out["to"] or not out["from"]:
                raise ValueError("SMTP server, From and To are required")
            out["port"] = str(int(out["port"] or 587))
            if out["security"] not in ("starttls", "ssl", "none"):
                out["security"] = "starttls"
        elif ctype == "telegram":
            if not out["bot_token"] or not out["chat_id"]:
                raise ValueError("bot token and chat ID are required")
        else:
            url = out.get("webhook_url") or out.get("url")
            local = url.startswith(("http://127.0.0.1", "http://localhost"))   # local relays / testing
            if not (url.startswith("https://") or local):
                raise ValueError("the URL must start with https://")
        return out

    def list(self):
        out = []
        for c in self.db.q("SELECT * FROM notify_channels ORDER BY id"):
            cfg = self.app.keys.open(c["config"], self._purpose(c["id"]), as_json=True) or {}
            shown = {}
            for key, label, secret in CHANNEL_TYPES.get(c["type"], ("", []))[1]:
                v = cfg.get(key, "")
                shown[key] = ("set (…%s)" % v[-4:] if len(v) > 8 else "set") if (secret and v) else ("" if secret else v)
            c["config"] = shown
            out.append(c)
        return {"channels": out, "types": {k: {"label": v[0], "fields": [{"key": f[0], "label": f[1], "secret": f[2]} for f in v[1]]}
                                           for k, v in CHANNEL_TYPES.items()}}

    def save(self, user, body, cid=None):
        name = str(body.get("name") or "").strip()[:60] or "Channel"
        ctype = body.get("type")
        sev = body.get("min_severity", "high")
        if sev not in SEV_RANK:
            raise ValueError("bad severity")
        digest = 1 if body.get("digest", True) else 0
        enabled = 1 if body.get("enabled", True) else 0
        old = None
        if cid:
            row = self.db.one("SELECT * FROM notify_channels WHERE id=?", (cid,))
            if not row:
                raise LookupError("channel not found")
            ctype = row["type"]
            old = self.app.keys.open(row["config"], self._purpose(cid), as_json=True)
        cfg = self._clean_config(ctype, body.get("config"), old)
        if cid:
            self.db.x("UPDATE notify_channels SET name=?, config=?, min_severity=?, digest=?, enabled=? WHERE id=?",
                      (name, self.app.keys.seal(cfg, self._purpose(cid)), sev, digest, enabled, cid))
        else:
            cid = self.db.x("""INSERT INTO notify_channels(name,type,config,min_severity,digest,enabled,created_by,created_at)
                               VALUES(?,?,?,?,?,?,?,?)""", (name, ctype, "pending", sev, digest, enabled, user, time.time()))
            self.db.x("UPDATE notify_channels SET config=? WHERE id=?", (self.app.keys.seal(cfg, self._purpose(cid)), cid))
        self.db.audit(user, "notify_channel_saved", "%s (%s, %s+)" % (name, ctype, sev))
        return cid

    def delete(self, user, cid):
        self.db.x("DELETE FROM notify_channels WHERE id=?", (cid,))
        self.db.audit(user, "notify_channel_deleted", "channel %s" % cid)

    # ---- sending ----------------------------------------------------------
    def link(self, alert_id=None):
        base = (self.app.get_setting("dashboard_url") or self.app.cfg.get("remote_url") or
                "http://127.0.0.1:%s" % self.app.cfg.get("listen_port", 8787)).rstrip("/")
        return base + ("/#alert=%d" % alert_id if alert_id else "/")

    def _post_json(self, url, payload, headers=None):
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                     headers=dict({"Content-Type": "application/json", "User-Agent": "NetGuard"}, **(headers or {})))
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status
        except urllib.error.HTTPError as e:
            raise NotifyError("HTTP %d: %s" % (e.code, e.read()[:200].decode("utf-8", "replace")))
        except (urllib.error.URLError, OSError) as e:
            raise NotifyError(str(getattr(e, "reason", e)))

    def send(self, ch, subject, text, link, data=None):
        cfg = self.app.keys.open(ch["config"], self._purpose(ch["id"]), as_json=True)
        t = ch["type"]
        if t == "email":
            msg = EmailMessage()
            msg["Subject"], msg["From"], msg["To"] = subject, cfg["from"], cfg["to"]
            msg.set_content("%s\n\nOpen in NetGuard: %s\n" % (text, link))
            port = int(cfg["port"])
            try:
                if cfg["security"] == "ssl":
                    s = smtplib.SMTP_SSL(cfg["host"], port, timeout=20, context=ssl.create_default_context())
                else:
                    s = smtplib.SMTP(cfg["host"], port, timeout=20)
                    if cfg["security"] == "starttls":
                        s.starttls(context=ssl.create_default_context())
                if cfg.get("username"):
                    s.login(cfg["username"], cfg.get("password", ""))
                s.send_message(msg, to_addrs=[a.strip() for a in cfg["to"].split(",") if a.strip()])
                s.quit()
            except (smtplib.SMTPException, OSError) as e:
                raise NotifyError("email: %s" % e)
        elif t == "telegram":
            self._post_json("https://api.telegram.org/bot%s/sendMessage" % cfg["bot_token"],
                            {"chat_id": cfg["chat_id"], "text": "%s\n\n%s\n\n%s" % (subject, text, link)[:4000],
                             "disable_web_page_preview": True})
        elif t == "discord":
            self._post_json(cfg["webhook_url"], {"content": ("**%s**\n%s\n<%s>" % (subject, text, link))[:1900]})
        elif t == "teams":
            card = {"type": "AdaptiveCard", "version": "1.4", "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "body": [{"type": "TextBlock", "text": subject, "weight": "Bolder", "wrap": True},
                             {"type": "TextBlock", "text": text[:2000], "wrap": True}],
                    "actions": [{"type": "Action.OpenUrl", "title": "Open in NetGuard", "url": link}]}
            self._post_json(cfg["webhook_url"], {"type": "message", "attachments": [
                {"contentType": "application/vnd.microsoft.card.adaptive", "content": card}]})
        elif t == "webhook":
            headers = {}
            if cfg.get("header") and ":" in cfg["header"]:
                k, v = cfg["header"].split(":", 1)
                headers[k.strip()] = v.strip()
            self._post_json(cfg["url"], dict(data or {}, subject=subject, text=text, link=link), headers)

    def _deliver(self, ch, kind, subject, text, link, alert_id=None, data=None):
        try:
            self.send(ch, subject, text, link, data)
            ok, detail = 1, "sent"
        except Exception as e:
            ok, detail = 0, str(e)[:300]
        now = time.time()
        self.db.x("INSERT INTO notify_log(ts,channel_id,kind,alert_id,ok,detail) VALUES(?,?,?,?,?,?)",
                  (now, ch["id"], kind, alert_id, ok, detail))
        self.db.x("UPDATE notify_channels SET last_status=?, last_at=? WHERE id=?", ("ok" if ok else "error: " + detail, now, ch["id"]))
        return ok, detail

    def test(self, cid):
        ch = self.db.one("SELECT * FROM notify_channels WHERE id=?", (cid,))
        if not ch:
            raise LookupError("channel not found")
        ok, detail = self._deliver(ch, "test", "[NetGuard] Test message",
                                   "If you can read this, NetGuard can reach you on '%s'." % ch["name"], self.link())
        return {"ok": bool(ok), "detail": detail}

    # ---- events ----------------------------------------------------------
    def alert_created(self, alert_id):
        self.q.put(("alert", alert_id))

    def _worker(self):
        while True:
            kind, arg = self.q.get()
            try:
                if kind == "alert":
                    self._send_alert(arg)
            except Exception as e:      # never let a bad channel kill the worker
                print("[notify] %s" % e)

    def _send_alert(self, alert_id):
        a = self.db.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        if not a:
            return
        subject = "[NetGuard] %s on %s: %s" % (a["severity"].upper(), a["host"], a["title"])
        text = a["details"] or ""
        data = {"event": "alert", "alert": {k: a[k] for k in ("id", "host", "rule", "severity", "title", "details", "status")}}
        now = time.time()
        for ch in self.db.q("SELECT * FROM notify_channels WHERE enabled=1"):
            if SEV_RANK[a["severity"]] < SEV_RANK.get(ch["min_severity"], 3):
                continue
            recent = [t for t in self.sent.get(ch["id"], []) if now - t < 3600]
            if len(recent) >= RATE_PER_HOUR:
                self.dropped[ch["id"]] = self.dropped.get(ch["id"], 0) + 1
                if self.dropped[ch["id"]] == 1:      # tell them once per burst
                    self._deliver(ch, "rate_limit", "[NetGuard] Too many alerts",
                                  "More than %d alerts in the last hour. Further alerts are only in the dashboard and the daily summary."
                                  % RATE_PER_HOUR, self.link())
                continue
            self.dropped[ch["id"]] = 0
            recent.append(now)
            self.sent[ch["id"]] = recent
            self._deliver(ch, "alert", subject, text, self.link(alert_id), alert_id, data)

    # ---- daily summary ----------------------------------------------------
    def digest_text(self):
        s = self.app.summary(None)
        sev = s["by_severity"]
        lines = ["Open alerts: %d critical, %d high, %d medium, %d low" % (sev["critical"], sev["high"], sev["medium"], sev["low"] + sev["info"]),
                 "Servers online: %d of %d" % (s["hosts_online"], s["hosts_total"]),
                 "New alerts in the last 24 h: %d" % sum(s["timeline_24h"])]
        extra = getattr(self.app, "digest_extra", None)
        if extra:
            lines += extra()
        top = self.db.q("""SELECT host, severity, title FROM alerts WHERE status IN ('open','acknowledged')
                           AND severity IN ('critical','high') ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, last_seen DESC LIMIT 10""")
        if top:
            lines.append("")
            lines.append("Needs attention:")
            lines += ["- [%s] %s: %s" % (t["severity"].upper(), t["host"], t["title"]) for t in top]
        return "\n".join(lines)

    def send_digest(self):
        text = self.digest_text()
        for ch in self.db.q("SELECT * FROM notify_channels WHERE enabled=1 AND digest=1"):
            self._deliver(ch, "digest", "[NetGuard] Daily summary %s" % time.strftime("%Y-%m-%d"), text, self.link())
