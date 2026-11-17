"""
NetGuard risk register and disaster-recovery plans.

Risks = likelihood (1-5) x impact (1-5). Many are derived automatically from live data (open alerts, backup health,
hardening score, offline agents, missing DR plans, notification and key-management gaps); people add their own
and can formally accept an automatic risk (owners, with a reason and an expiry).
DR plans hold per-server recovery objectives (tier, RPO, RTO, contacts); their status is measured against real
backup ages and test-restore durations, and a recovery runbook is generated from what is actually backed up.
"""
import json
import re
import time

CATEGORIES = ("security", "availability", "data", "compliance", "operations", "people", "vendor", "other")
TREATMENTS = ("mitigate", "accept", "transfer", "avoid")
STATUSES = ("open", "in_progress", "closed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT DEFAULT '', title TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'other',
    likelihood INTEGER NOT NULL, impact INTEGER NOT NULL, owner TEXT DEFAULT '',
    treatment TEXT NOT NULL DEFAULT 'mitigate', status TEXT NOT NULL DEFAULT 'open', due TEXT DEFAULT '', notes TEXT DEFAULT '',
    created_by TEXT, created_at REAL, updated_by TEXT, updated_at REAL
);
CREATE TABLE IF NOT EXISTS risk_accepts (
    key TEXT PRIMARY KEY, reason TEXT NOT NULL, accepted_by TEXT, accepted_at REAL, until REAL
);
CREATE TABLE IF NOT EXISTS dr_plans (
    host TEXT PRIMARY KEY, tier INTEGER NOT NULL DEFAULT 2, rpo_hours INTEGER NOT NULL DEFAULT 24, rto_hours INTEGER NOT NULL DEFAULT 8,
    owner TEXT DEFAULT '', contacts TEXT DEFAULT '', dependencies TEXT DEFAULT '', notes TEXT DEFAULT '',
    updated_by TEXT, updated_at REAL
);
"""

TIER_LABEL = {1: "Tier 1 - critical", 2: "Tier 2 - important", 3: "Tier 3 - normal"}


def level(score):
    return "critical" if score >= 20 else "high" if score >= 12 else "medium" if score >= 6 else "low"


class RiskManager:
    def __init__(self, app):
        self.app = app
        self.db = app.db
        with self.db.lock:
            self.db.conn.executescript(SCHEMA)
            self.db.conn.commit()

    # ---- automatic risks ----------------------------------------------------
    def _r(self, key, host, title, category, likelihood, impact, detail, suggestion):
        s = likelihood * impact
        return {"key": key, "host": host, "title": title, "category": category, "likelihood": likelihood, "impact": impact,
                "score": s, "level": level(s), "detail": detail, "suggestion": suggestion, "source": "auto"}

    def auto_risks(self, scope=None):
        out = []
        hosts = self.app.hosts(scope)
        jobs = self.app.backups.list(scope)
        plans = {p["host"]: p for p in self.db.q("SELECT * FROM dr_plans")}
        for h in hosts:
            name = h["name"]
            oa = self.db.q("""SELECT severity, title FROM alerts WHERE host=? AND status IN ('open','acknowledged')
                              AND rule NOT LIKE 'backup%' AND rule NOT LIKE 'restore%' AND rule <> 'agent_offline'""", (name,))
            crit = [a["title"] for a in oa if a["severity"] == "critical"]
            high = [a["title"] for a in oa if a["severity"] == "high"]
            if crit:
                out.append(self._r("crit:" + name, name, "%d unresolved critical alert(s)" % len(crit), "security", 4, 5,
                                   "; ".join(crit[:3]), "Open the alerts and fix, contain or accept them."))
            if high:
                out.append(self._r("high:" + name, name, "%d unresolved high alert(s)" % len(high), "security", 3, 4,
                                   "; ".join(high[:3]), "Work through the high alerts or accept them with a reason."))
            if not h["online"]:
                out.append(self._r("offline:" + name, name, "Monitoring agent offline", "availability", 3, 4,
                                   "No report since %s." % time.strftime("%Y-%m-%d %H:%M", time.localtime(h["last_seen"])),
                                   "Check the server and the agent; while offline, nothing on it is watched."))
            hd = h.get("hardening") or {}
            if hd.get("total"):
                pct = 100.0 * hd["passed"] / hd["total"]
                if pct < 80:
                    out.append(self._r("harden:" + name, name, "Hardening score %d%%" % pct, "security", 4 if pct < 60 else 3, 3,
                                       "%d of %d checks pass." % (hd["passed"], hd["total"]), "Apply the safe hardening fixes or accept the rest."))
            hjobs = [j for j in jobs if j["host"] == name and j["enabled"]]
            if not hjobs:
                out.append(self._r("nobackup:" + name, name, "No backups configured", "data", 3, 5,
                                   "If this server's disk fails or ransomware hits, its data is gone.", "Create a backup job (Backups tab)."))
            for j in hjobs:
                for rule, sev, title, detail in j["health"]:
                    lk, im = (3, 4) if rule == "restore_untested" else (4, 5)
                    out.append(self._r("%s:%d" % (rule, j["id"]), name, title, "data", lk, im, detail,
                                       "Run the backup / test restore and fix what stopped it."))
            plan = plans.get(name)
            if not plan:
                out.append(self._r("noplan:" + name, name, "No disaster-recovery plan", "availability", 2, 4,
                                   "No agreed RPO/RTO, owner or contacts for this server.", "Fill in the DR plan (DR plans tab)."))
            else:
                if hjobs:
                    best = min(self._interval_h(j["spec"]["schedule"]) for j in hjobs)
                    if best > plan["rpo_hours"]:
                        out.append(self._r("rpo:" + name, name, "Backup schedule can't meet the RPO", "data", 3, 4,
                                           "Backups run every %g h but the RPO is %d h." % (best, plan["rpo_hours"]),
                                           "Back up more often or agree a longer RPO."))
                    durs = [j["last"]["test_ok"]["details"].get("duration_s", 0) for j in hjobs if j["last"]["test_ok"]]
                    if durs and sum(durs) / 3600.0 > plan["rto_hours"]:
                        out.append(self._r("rto:" + name, name, "Measured restore time exceeds the RTO", "availability", 3, 4,
                                           "Test restores took %.1f h in total; RTO is %d h." % (sum(durs) / 3600.0, plan["rto_hours"]),
                                           "Keep a faster local copy or agree a longer RTO."))
        if scope is None:
            out += self._org_risks()
        accepts = {a["key"]: a for a in self.db.q("SELECT * FROM risk_accepts WHERE until IS NULL OR until > ?", (time.time(),))}
        for r in out:
            a = accepts.get(r["key"])
            r["accepted"] = dict(a) if a else None
        return sorted(out, key=lambda r: (r["accepted"] is not None, -r["score"]))

    def _org_risks(self):
        out = []
        chans = self.db.one("SELECT COUNT(*) n FROM notify_channels WHERE enabled=1")["n"]
        if not chans:
            out.append(self._r("org:notify", "", "Nobody is notified of alerts", "operations", 3, 3,
                               "Alerts are only visible while someone has the dashboard open.", "Add a notification channel (Settings)."))
        owners = self.db.one("SELECT COUNT(*) n FROM users WHERE role='owner' AND disabled=0")["n"]
        if owners < 2:
            out.append(self._r("org:owners", "", "Only one owner account", "people", 2, 4,
                               "If that person is unavailable or loses their phone, nobody can manage NetGuard.",
                               "Invite a second trusted owner (People)."))
        if not self.app.get_setting("keys_offline_confirmed", False):
            out.append(self._r("org:keys", "", "Recovery keys not confirmed stored offline", "data", 3, 5,
                               "If this dashboard is lost, netguard.key and the backup recovery keys are lost with it, "
                               "making encrypted backups unreadable.",
                               "Copy netguard.key and every backup recovery key to offline storage, then confirm in the Risk tab."))
        last = self.app.get_setting("last_db_backup", 0) or 0
        if time.time() - last > 2 * 86400:
            out.append(self._r("org:dbbackup", "", "Dashboard database not backed up recently", "data", 2, 3,
                               "Alert history, people and settings could be lost.", "Back up now (Settings) or check the maintenance task."))
        return out

    @staticmethod
    def _interval_h(schedule):
        return 24.0 if schedule.get("mode") == "daily" else float(schedule.get("every", 24))

    # ---- manual risks ----------------------------------------------------------
    def _clean(self, body):
        title = str(body.get("title") or "").strip()[:160]
        if not title:
            raise ValueError("title is required")
        lk, im = int(body.get("likelihood") or 3), int(body.get("impact") or 3)
        if not (1 <= lk <= 5 and 1 <= im <= 5):
            raise ValueError("likelihood and impact are 1-5")
        cat = body.get("category") if body.get("category") in CATEGORIES else "other"
        tr = body.get("treatment") if body.get("treatment") in TREATMENTS else "mitigate"
        st = body.get("status") if body.get("status") in STATUSES else "open"
        due = str(body.get("due") or "")
        if due and not re.match(r"^\d{4}-\d{2}-\d{2}$", due):
            raise ValueError("due date must be YYYY-MM-DD")
        host = str(body.get("host") or "")
        return (host, title, cat, lk, im, str(body.get("owner") or "")[:60], tr, st, due, str(body.get("notes") or "")[:2000])

    def manual(self, scope=None):
        rows = self.db.q("SELECT * FROM risks ORDER BY status='closed', likelihood*impact DESC, id DESC")
        out = []
        for r in rows:
            if scope is not None and r["host"] and r["host"] not in scope:
                continue
            r["score"] = r["likelihood"] * r["impact"]
            r["level"] = level(r["score"])
            r["source"] = "manual"
            r["overdue"] = bool(r["due"] and r["status"] != "closed" and r["due"] < time.strftime("%Y-%m-%d"))
            out.append(r)
        return out

    def save(self, user, body, rid=None):
        vals = self._clean(body)
        now = time.time()
        if rid:
            if not self.db.one("SELECT id FROM risks WHERE id=?", (rid,)):
                raise LookupError("risk not found")
            self.db.x("""UPDATE risks SET host=?, title=?, category=?, likelihood=?, impact=?, owner=?, treatment=?, status=?, due=?, notes=?,
                         updated_by=?, updated_at=? WHERE id=?""", vals + (user, now, rid))
        else:
            rid = self.db.x("""INSERT INTO risks(host,title,category,likelihood,impact,owner,treatment,status,due,notes,created_by,created_at,updated_by,updated_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", vals + (user, now, user, now))
        self.db.audit(user, "risk_saved", "%s (L%d x I%d)" % (vals[1], vals[3], vals[4]), host=vals[0] or None)
        return rid

    def delete(self, user, rid):
        self.db.x("DELETE FROM risks WHERE id=?", (rid,))
        self.db.audit(user, "risk_deleted", "risk %d" % rid)

    def accept(self, user, key, reason, days):
        if not reason or len(reason.strip()) < 5:
            raise ValueError("write down why the risk is acceptable (at least a few words)")
        until = time.time() + float(days) * 86400 if days else None
        self.db.x("""INSERT INTO risk_accepts(key,reason,accepted_by,accepted_at,until) VALUES(?,?,?,?,?)
                     ON CONFLICT(key) DO UPDATE SET reason=excluded.reason, accepted_by=excluded.accepted_by,
                     accepted_at=excluded.accepted_at, until=excluded.until""", (key, reason.strip()[:500], user, time.time(), until))
        self.db.audit(user, "risk_accepted", "%s for %s days: %s" % (key, days or "unlimited", reason))

    def unaccept(self, user, key):
        self.db.x("DELETE FROM risk_accepts WHERE key=?", (key,))
        self.db.audit(user, "risk_acceptance_removed", key)

    def register(self, scope=None):
        auto = self.auto_risks(scope)
        manual = self.manual(scope)
        heat = [[0] * 5 for _ in range(5)]          # heat[likelihood-1][impact-1], open & not accepted
        for r in auto:
            if not r["accepted"]:
                heat[r["likelihood"] - 1][r["impact"] - 1] += 1
        for r in manual:
            if r["status"] != "closed" and r["treatment"] != "accept":
                heat[r["likelihood"] - 1][r["impact"] - 1] += 1
        open_scores = [r["score"] for r in auto if not r["accepted"]] + [r["score"] for r in manual if r["status"] != "closed" and r["treatment"] != "accept"]
        return {"auto": auto, "manual": manual, "heat": heat, "categories": CATEGORIES, "treatments": TREATMENTS,
                "summary": {"open": len(open_scores), "critical": sum(1 for s in open_scores if s >= 20),
                            "high": sum(1 for s in open_scores if 12 <= s < 20), "max": max(open_scores or [0])},
                "keys_offline_confirmed": bool(self.app.get_setting("keys_offline_confirmed", False))}

    # ---- DR plans ----------------------------------------------------------------
    def save_plan(self, user, host, body):
        if not self.db.one("SELECT name FROM hosts WHERE name=?", (host,)):
            raise LookupError("unknown server")
        tier, rpo, rto = int(body.get("tier") or 2), int(body.get("rpo_hours") or 24), int(body.get("rto_hours") or 8)
        if tier not in (1, 2, 3) or not (1 <= rpo <= 8760) or not (1 <= rto <= 8760):
            raise ValueError("tier 1-3, RPO/RTO 1-8760 hours")
        vals = (tier, rpo, rto) + tuple(str(body.get(k) or "")[:2000] for k in ("owner", "contacts", "dependencies", "notes"))
        self.db.x("""INSERT INTO dr_plans(host,tier,rpo_hours,rto_hours,owner,contacts,dependencies,notes,updated_by,updated_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET tier=excluded.tier, rpo_hours=excluded.rpo_hours,
                     rto_hours=excluded.rto_hours, owner=excluded.owner, contacts=excluded.contacts, dependencies=excluded.dependencies,
                     notes=excluded.notes, updated_by=excluded.updated_by, updated_at=excluded.updated_at""",
                  (host,) + vals + (user, time.time()))
        self.db.audit(user, "dr_plan_saved", "tier %d RPO %d h RTO %d h" % (tier, rpo, rto), host=host)

    def plans(self, scope=None):
        plans = {p["host"]: p for p in self.db.q("SELECT * FROM dr_plans")}
        jobs = self.app.backups.list(scope)
        now = time.time()
        out = []
        for h in self.app.hosts(scope):
            p = plans.get(h["name"])
            hj = [j for j in jobs if j["host"] == h["name"] and j["enabled"]]
            status = {"has_plan": bool(p), "jobs": len(hj)}
            if hj:
                oks = [j["last"]["backup_ok"]["finished"] for j in hj if j["last"]["backup_ok"]]
                status["last_good_backup_age_h"] = round((now - min(oks)) / 3600, 1) if len(oks) == len(hj) else None
                tests = [j["last"]["test_ok"] for j in hj if j["last"]["test_ok"]]
                status["last_test_age_d"] = round((now - min(t["finished"] for t in tests)) / 86400, 1) if len(tests) == len(hj) else None
                status["measured_restore_min"] = round(sum(t["details"].get("duration_s", 0) for t in tests) / 60, 1) if tests else None
            if p:
                age = status.get("last_good_backup_age_h")
                status["rpo_met"] = age is not None and age <= p["rpo_hours"]
                mr = status.get("measured_restore_min")
                status["rto_met"] = None if mr is None else mr / 60 <= p["rto_hours"]
            out.append({"host": h["name"], "os": h["os"], "ip": h["ip"], "online": h["online"], "plan": p, "status": status,
                        "jobs": [{"id": j["id"], "name": j["name"], "spec": j["spec"], "recovery_item": j["recovery_item"],
                                  "last_ok": j["last"]["backup_ok"], "last_test": j["last"]["test_ok"]} for j in hj],
                        "runbook": self.runbook(h, p, hj)})
        return out

    def runbook(self, host, plan, jobs):
        windows = "windows" in (host.get("os") or "").lower()
        steps = []
        contacts = (plan or {}).get("contacts") or "(no contacts in the DR plan yet)"
        steps.append(("Declare the incident", "Tell the people below that %s is down and recovery has started. Note the time: it is "
                      "measured against the RTO%s.\nContacts: %s" % (host["name"], " of %d h" % plan["rto_hours"] if plan else "", contacts)))
        if plan and plan.get("dependencies"):
            steps.append(("Check dependencies first", plan["dependencies"]))
        steps.append(("Get the recovery keys", "You need each job's recovery key: NetGuard Vault → \"Backup recovery key: …\" "
                      "or, if the dashboard is also gone, your OFFLINE copy. Jobs: %s." % (", ".join(j["name"] for j in jobs) or "none")))
        steps.append(("Provision a replacement server", "Same OS family (%s), same name (%s) and, if possible, same IP (%s). Apply OS updates."
                      % (host.get("os") or "?", host["name"], host.get("ip") or "?")))
        steps.append(("Reconnect it to NetGuard", "Install Tailscale if you use it, then the agent: "
                      + ("Install-Agent.ps1 -Server <dashboard> -Token <join token> -CommandKey <key>" if windows else
                         "sudo ./install.sh --server <dashboard> --token <join token> --command-key <key>")
                      + ". If the old server still has a key in Settings → Servers & agent keys, click Reset key first."))
        dests = sorted({(d.get("path") or "S3 (vault #%s)" % d.get("vault_id")) for j in jobs for d in j["spec"]["destinations"]})
        steps.append(("Restore the files", "Dashboard → Backups → Restore… (choose the backup and an empty folder). Without the dashboard: copy the "
                      "newest .ngbk from %s and run: python ng-decrypt.py ARCHIVE.ngbk out.%s --key <recovery key>, then extract it."
                      % (", ".join(dests) or "the backup storage", "zip" if windows else "tar.gz")))
        srcs = {k for j in jobs for k, v in j["spec"]["sources"].items() if v}
        if "config" in srcs:
            steps.append(("Restore server configuration", (
                "From config\\ in the restore: import firewall rules (netsh advfirewall import firewall.wfw), recreate scheduled tasks "
                "(schtasks /create /xml), reinstall programs from installed-programs.txt, compare services.txt and local-users.txt."
                if windows else
                "From config/etc in the restore: copy back the files you need (users, sshd, cron, systemd units, nginx/apache), reinstall "
                "packages from config/generated/packages.txt, re-apply firewall rules (iptables-restore / ufw).")))
        if "databases" in srcs:
            steps.append(("Restore the databases", "From databases/ in the restore:\n"
                          "- MySQL/MariaDB: mysql -u root -p < NAME.mysql.sql\n"
                          "- PostgreSQL: psql -U postgres -f NAME.postgres.sql\n"
                          "- SQL Server: RESTORE DATABASE [db] FROM DISK = 'NAME.db.mssql.bak' WITH REPLACE, RECOVERY\n"
                          "- SQLite: stop the app, copy NAME.sqlite over the database file\n"
                          "Then point the applications at the restored databases and change any passwords that may have leaked."))
        if "website" in srcs:
            steps.append(("Restore the websites", (
                "Stop IIS (iisreset /stop), copy website\\C\\inetpub back, restore website\\C\\Windows\\System32\\inetsrv\\config "
                "(applicationHost.config), rebind TLS certificates (see generated/ssl-bindings.txt), iisreset /start."
                if windows else
                "Copy website/var/www and the web-server config (website/etc/nginx or apache2) back, restore /etc/letsencrypt, "
                "then nginx -t && systemctl reload nginx (or apachectl configtest && systemctl reload apache2).")))
        if "folders" in srcs:
            steps.append(("Restore the data folders", "Copy each folder under folders\\ back to its original path (shown in the archive)."))
        steps.append(("Verify", "In NetGuard: the server reports, hardening audit passes, no critical alerts. Test the websites/apps as a user. "
                      "Run a new backup and a test restore."))
        steps.append(("Close and learn", "Record the actual recovery time and data loss vs the RTO/RPO, update this plan and the risk register."))
        return [{"step": i + 1, "title": t, "text": x} for i, (t, x) in enumerate(steps)]
