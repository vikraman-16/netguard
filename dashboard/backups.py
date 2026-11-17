"""
NetGuard backups (dashboard side).

Jobs are defined here per server and delivered to that server's agent as a *signed* bundle (only when they change).
The agent runs them on schedule in a separate process, applies retention, schedules test restores, and reports
results back. Every job has its own random 256-bit encryption key: the archive format (NGBK1) is AES-256-CBC +
HMAC-SHA256 and is identical on Windows and Linux. The key is kept sealed here AND as a vault item
("recovery key"), which should also be stored offline - without it the archives cannot be decrypted.
"""
import base64
import hashlib
import json
import re
import secrets
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS backup_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL, name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    spec TEXT NOT NULL, enc_key TEXT NOT NULL DEFAULT '', recovery_item INTEGER,
    created_by TEXT, created_at REAL, updated_by TEXT, updated_at REAL
);
CREATE TABLE IF NOT EXISTS backup_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER, host TEXT, kind TEXT, run_ref TEXT UNIQUE, status TEXT,
    started REAL, finished REAL, size INTEGER, archive TEXT, sha256 TEXT, files INTEGER,
    details TEXT DEFAULT '{}', log TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_runs_job ON backup_runs(job_id, kind, finished);
"""

PATH_RE = re.compile(r"^(?:[A-Za-z]:\\|\\\\|/)[^\x00-\x1f\"<>|]{0,1020}$")
SAFE_NAME = re.compile(r"[^A-Za-z0-9_.\-]+")


class BackupError(Exception):
    pass


def _bool(v):
    return bool(v) and v not in ("0", "false", "False")


class Backups:
    def __init__(self, app):
        self.app = app
        self.db = app.db
        with self.db.lock:
            self.db.conn.executescript(SCHEMA)
            self.db.conn.commit()

    # ---- job definitions ----------------------------------------------------
    def _clean_spec(self, user, body, host):
        src = body.get("sources") or {}
        folders = [str(p).strip() for p in (src.get("folders") or []) if str(p).strip()]
        for p in folders:
            if not PATH_RE.match(p):
                raise BackupError("not an absolute path: %s" % p)
        excludes = [str(e).strip() for e in (src.get("excludes") or []) if str(e).strip()][:50]
        dbs = []
        for vid in src.get("databases") or []:
            self.app.vault.secret_for(user, int(vid), "database")      # access check
            dbs.append(int(vid))
        sources = {"website": _bool(src.get("website")), "config": _bool(src.get("config")),
                   "folders": folders, "excludes": excludes, "databases": dbs}
        if not (sources["website"] or sources["config"] or folders or dbs):
            raise BackupError("choose at least one thing to back up")
        dests = []
        for d in body.get("destinations") or []:
            if d.get("type") == "local":
                p = str(d.get("path") or "").strip()
                if not PATH_RE.match(p):
                    raise BackupError("local destination must be an absolute path (e.g. D:\\Backups or /mnt/backup)")
                dests.append({"type": "local", "path": p})
            elif d.get("type") == "s3":
                self.app.vault.secret_for(user, int(d.get("vault_id")), "s3")
                dests.append({"type": "s3", "vault_id": int(d["vault_id"])})
        if not dests:
            raise BackupError("choose at least one place to store backups")
        sch = body.get("schedule") or {}
        if sch.get("mode") == "hourly":
            every = int(sch.get("every") or 6)
            if not 1 <= every <= 168:
                raise BackupError("run every 1-168 hours")
            schedule = {"mode": "hourly", "every": every}
        else:
            at = str(sch.get("at") or "02:00")
            if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", at):
                raise BackupError("time must be HH:MM")
            schedule = {"mode": "daily", "at": at}
        ret = body.get("retention") or {}
        # explicit 0 days is meaningful ("don't keep by age"), so only fall back when the field is missing
        keep_last = int(ret["keep_last"]) if ret.get("keep_last") not in (None, "") else 7
        keep_days = int(ret["keep_days"]) if ret.get("keep_days") not in (None, "") else 30
        if not (1 <= keep_last <= 1000 and 0 <= keep_days <= 3650):
            raise BackupError("retention out of range")
        rpo = int(body.get("rpo_hours") or (24 if schedule["mode"] == "daily" else schedule["every"]))
        test_days = int(body.get("test_every_days") if body.get("test_every_days") is not None else 7)
        return {"sources": sources, "destinations": dests, "schedule": schedule,
                "retention": {"keep_last": keep_last, "keep_days": keep_days},
                "rpo_hours": max(1, rpo), "test_every_days": max(0, test_days), "encrypt": True}

    def save(self, user, body, jid=None):
        host = str(body.get("host") or "")
        if not self.db.one("SELECT name FROM hosts WHERE name=?", (host,)):
            raise BackupError("unknown server")
        name = re.sub(r"\s+", " ", str(body.get("name") or "").strip())[:60]
        if not name:
            raise BackupError("name is required")
        spec = self._clean_spec(user, body, host)
        now = time.time()
        enabled = 0 if body.get("enabled") is False else 1
        if jid:
            job = self.db.one("SELECT * FROM backup_jobs WHERE id=?", (jid,))
            if not job:
                raise LookupError("job not found")
            self.db.x("UPDATE backup_jobs SET host=?, name=?, enabled=?, spec=?, updated_by=?, updated_at=? WHERE id=?",
                      (host, name, enabled, json.dumps(spec), user["username"], now, jid))
            self.db.audit(user["username"], "backup_job_updated", name, host=host)
            return {"id": jid}
        key = secrets.token_bytes(32)
        jid = self.db.x("""INSERT INTO backup_jobs(host,name,enabled,spec,created_by,created_at,updated_by,updated_at)
                           VALUES(?,?,?,?,?,?,?,?)""", (host, name, enabled, json.dumps(spec), user["username"], now, user["username"], now))
        key_b64 = base64.b64encode(key).decode()
        self.db.x("UPDATE backup_jobs SET enc_key=? WHERE id=?", (self.app.keys.seal(key_b64, "backupkey:%d" % jid), jid))
        rid = self.app.vault.save(user, {"name": "Backup recovery key: %s (%s)" % (name, host), "kind": "secret", "host": host,
                                         "fields": {"value": key_b64, "notes": "Decrypts the NGBK1 archives of backup job '%s' on %s "
                                                    "(tools/ng-decrypt.py). Store a copy OFFLINE." % (name, host)}}, system=True)
        self.db.x("UPDATE backup_jobs SET recovery_item=? WHERE id=?", (rid, jid))
        self.db.audit(user["username"], "backup_job_created", name, host=host)
        return {"id": jid, "recovery_key": key_b64, "recovery_item": rid}

    def delete(self, user, jid):
        job = self.db.one("SELECT * FROM backup_jobs WHERE id=?", (jid,))
        if not job:
            raise LookupError("job not found")
        self.db.x("DELETE FROM backup_jobs WHERE id=?", (jid,))
        self.db.audit(user["username"], "backup_job_deleted", "%s (archives and recovery key kept)" % job["name"], host=job["host"])

    def jobs_using_vault(self, vid):
        out = []
        for j in self.db.q("SELECT name, spec FROM backup_jobs"):
            s = json.loads(j["spec"])
            if vid in s["sources"]["databases"] or any(d.get("vault_id") == vid for d in s["destinations"]):
                out.append(j["name"])
        return out

    def list(self, scope=None):
        if scope is None:
            f, fa = "1=1", []
        else:
            f, fa = ("host IN (%s)" % ",".join("?" * len(scope)), list(scope)) if scope else ("0=1", [])
        jobs = []
        for j in self.db.q("SELECT * FROM backup_jobs WHERE %s ORDER BY host, name" % f, fa):
            spec = json.loads(j["spec"])
            last = self.last_runs(j["id"])
            labels = []
            for d in spec["destinations"]:
                if d["type"] == "local":
                    labels.append(d["path"])
                else:
                    it = self.db.one("SELECT name FROM vault_items WHERE id=?", (d["vault_id"],))
                    labels.append("S3: %s" % (it["name"] if it else "missing vault item #%d" % d["vault_id"]))
            jobs.append({"id": j["id"], "host": j["host"], "name": j["name"], "enabled": bool(j["enabled"]), "spec": spec, "dest_labels": labels,
                         "recovery_item": j["recovery_item"], "created_by": j["created_by"], "updated_at": j["updated_at"],
                         "last": last, "health": self.health(j, spec, last)})
        return jobs

    def runs(self, jid, scope=None, limit=50):
        job = self.db.one("SELECT host FROM backup_jobs WHERE id=?", (jid,))
        if not job or (scope is not None and job["host"] not in scope):
            raise LookupError("job not found")
        rows = self.db.q("SELECT * FROM backup_runs WHERE job_id=? ORDER BY COALESCE(finished, started) DESC LIMIT ?", (jid, limit))
        for r in rows:
            r["details"] = json.loads(r["details"] or "{}")
        return rows

    def last_runs(self, jid):
        def one(kind, status=None):
            sql = "SELECT * FROM backup_runs WHERE job_id=? AND kind=?"
            args = [jid, kind]
            if status:
                sql += " AND status=?"
                args.append(status)
            r = self.db.one(sql + " ORDER BY COALESCE(finished, started) DESC LIMIT 1", args)
            if r:
                r["details"] = json.loads(r["details"] or "{}")
            return r
        return {"backup": one("backup"), "backup_ok": one("backup", "ok"), "test": one("test"), "test_ok": one("test", "ok")}

    def health(self, job, spec, last):
        """Returns list of (rule, severity, title, detail) problems for this job (empty = healthy)."""
        if not job["enabled"]:
            return []
        now = time.time()
        out = []
        ok = last["backup_ok"]
        grace = 3600
        if last["backup"] and last["backup"]["status"] == "failed":
            out.append(("backup_failed", "high", "Backup failed: %s" % job["name"],
                        (last["backup"]["log"] or "")[-300:] or "see the run log"))
        if not ok:
            if now - job["created_at"] > spec["rpo_hours"] * 3600 + grace:
                out.append(("backup_missing", "high", "No successful backup yet: %s" % job["name"],
                            "The job exists for %.0f h but has never completed." % ((now - job["created_at"]) / 3600)))
        elif now - ok["finished"] > spec["rpo_hours"] * 3600 + grace:
            out.append(("backup_stale", "high", "Backup older than its RPO: %s" % job["name"],
                        "Last good backup %.1f h ago; RPO is %d h." % ((now - ok["finished"]) / 3600, spec["rpo_hours"])))
        td = spec.get("test_every_days") or 0
        if td and ok:
            t_ok = last["test_ok"]
            if last["test"] and last["test"]["status"] == "failed":
                out.append(("restore_test_failed", "high", "Test restore failed: %s" % job["name"],
                            (last["test"]["log"] or "")[-300:]))
            elif not t_ok and now - job["created_at"] > td * 86400 * 1.5:
                out.append(("restore_untested", "medium", "Backups never test-restored: %s" % job["name"],
                            "No successful test restore yet; scheduled every %d days." % td))
            elif t_ok and now - t_ok["finished"] > td * 86400 * 1.5:
                out.append(("restore_untested", "medium", "Test restore overdue: %s" % job["name"],
                            "Last successful test %.0f days ago; should be every %d days." % ((now - t_ok["finished"]) / 86400, td)))
        return out

    def check_health(self):
        """Raise/clear backup alerts (called from the maintenance loop)."""
        now = time.time()
        rules = ("backup_failed", "backup_missing", "backup_stale", "restore_untested", "restore_test_failed")
        for j in self.db.q("SELECT * FROM backup_jobs"):
            spec = json.loads(j["spec"])
            problems = {p[0]: p for p in self.health(j, spec, self.last_runs(j["id"]))}
            for rule in rules:
                fp = "%s:%d" % (rule, j["id"])
                if rule in problems:
                    _, sev, title, detail = problems[rule]
                    self.app._upsert_alert(j["host"], {"rule": rule, "severity": sev, "fingerprint": fp, "title": title,
                                                       "details": detail, "evidence": {"job": j["name"], "job_id": j["id"]},
                                                       "suggested": [{"action": "backup_run", "params": {"job_id": j["id"]},
                                                                      "label": "Run the backup now"}]
                                                       if rule != "restore_untested" else
                                                       [{"action": "backup_test", "params": {"job_id": j["id"]},
                                                         "label": "Run a test restore now"}]}, now)
                else:
                    self.db.x("""UPDATE alerts SET status='resolved', resolved_at=?, resolved_by='system', note='backup healthy again',
                                 updated_at=? WHERE host=? AND fingerprint=? AND status IN ('open','acknowledged')""",
                              (now, now, j["host"], fp))

    # ---- agent side ---------------------------------------------------------
    def _bundle(self, host):
        jobs = []
        for j in self.db.q("SELECT * FROM backup_jobs WHERE host=? AND enabled=1 ORDER BY id", (host,)):
            spec = json.loads(j["spec"])
            dbs = []
            for vid in spec["sources"]["databases"]:
                it = self.app.vault.open_item(vid)
                if it:
                    d = it["data"]
                    dbs.append({"name": it["name"], "engine": d.get("engine"), "host": d.get("host"), "port": d.get("port"),
                                "username": d.get("username"), "password": d.get("password"), "database": d.get("database")})
            dests = []
            for d in spec["destinations"]:
                if d["type"] == "local":
                    dests.append(d)
                else:
                    it = self.app.vault.open_item(d["vault_id"])
                    if it:
                        x = it["data"]
                        dests.append({"type": "s3", "name": it["name"], "endpoint": x["endpoint"], "region": x["region"],
                                      "bucket": x["bucket"], "prefix": x.get("prefix", ""), "access_key": x["access_key"],
                                      "secret_key": x["secret_key"]})
            jobs.append({"id": j["id"], "name": j["name"], "slug": SAFE_NAME.sub("-", j["name"]).strip("-").lower() or "job%d" % j["id"],
                         "sources": dict(spec["sources"], databases=dbs), "destinations": dests, "schedule": spec["schedule"],
                         "retention": spec["retention"], "test_every_days": spec["test_every_days"], "encrypt": True,
                         "key": self.app.keys.open(j["enc_key"], "backupkey:%d" % j["id"])})
        return jobs

    def agent_extra(self, host, report):
        """Called on every agent report: store results, hand out the job bundle if it changed."""
        for r in report.get("backup_results") or []:
            self._store_result(host, r)
        for ref in report.get("backup_running") or []:
            pass
        jobs = self._bundle(host)
        version = hashlib.sha256(json.dumps(jobs, sort_keys=True).encode()).hexdigest()[:16]
        out = {"backup_jobs_version": version}
        if report.get("backup_jobs_version") != version:
            envelope = json.dumps({"host": host, "version": version, "jobs": jobs, "issued": int(time.time())},
                                  sort_keys=True, separators=(",", ":"))
            out["backup_jobs"] = {"envelope": envelope, "sig": self.app.keys.sign_payload(envelope)}
        return out

    def _store_result(self, host, r):
        ref = str(r.get("run_ref") or "")[:64]
        if not re.match(r"^[A-Za-z0-9\-]{8,64}$", ref):
            return
        job = self.db.one("SELECT id, name FROM backup_jobs WHERE id=? AND host=?", (int(r.get("job_id") or 0), host))
        kind = r.get("kind") if r.get("kind") in ("backup", "test", "restore") else "backup"
        status = r.get("status") if r.get("status") in ("running", "ok", "failed") else "failed"
        vals = (job["id"] if job else None, host, kind, ref, status, float(r.get("started") or time.time()),
                float(r["finished"]) if r.get("finished") else None, int(r.get("size") or 0), str(r.get("archive") or "")[:200],
                str(r.get("sha256") or "")[:64], int(r.get("files") or 0), json.dumps(r.get("details") or {})[:20000],
                str(r.get("log") or "")[-20000:])
        if self.db.one("SELECT id FROM backup_runs WHERE run_ref=?", (ref,)):
            self.db.x("""UPDATE backup_runs SET job_id=?, host=?, kind=?, run_ref=?, status=?, started=?, finished=?, size=?,
                         archive=?, sha256=?, files=?, details=?, log=? WHERE run_ref=?""", vals + (ref,))
        else:
            self.db.x("""INSERT INTO backup_runs(job_id,host,kind,run_ref,status,started,finished,size,archive,sha256,files,details,log)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", vals)
        if status != "running":
            self.db.audit("agent", "backup_%s_%s" % (kind, status), "%s %s" % (job["name"] if job else "?", r.get("archive") or ""), host=host)

    def digest_lines(self):
        jobs = self.list()
        bad = [j for j in jobs if j["health"]]
        lines = ["Backups: %d job(s), %d need attention" % (len(jobs), len(bad))]
        for j in bad[:5]:
            lines.append("- %s on %s: %s" % (j["name"], j["host"], j["health"][0][2]))
        return lines
