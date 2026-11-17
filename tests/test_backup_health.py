"""Backup health -> alerts (in-process), and the Linux runner's S3 client against the signature-checking fake S3."""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

from fake_s3 import FakeS3
from helpers import REPO

sys.path.insert(0, os.path.join(REPO, "dashboard"))
sys.path.insert(0, os.path.join(REPO, "agents", "linux"))
import netguard_backup as lb  # noqa: E402
import server  # noqa: E402


class LinuxS3Client(unittest.TestCase):
    def test_put_list_get_delete(self):
        s3 = FakeS3()
        try:
            tmp = tempfile.mkdtemp()
            src = os.path.join(tmp, "a.ngbk")
            open(src, "wb").write(os.urandom(70000))
            d = lb.Dest({"type": "s3", "endpoint": s3.endpoint, "region": "us-east-1", "bucket": "backups", "prefix": "p",
                         "access_key": "AKTEST", "secret_key": "secret-test-key"}, "host1", "job")
            for n in ("host1_job_20260101-000000.ngbk", "host1_job_20260102-000000.ngbk", "host1_job_20260103-000000.ngbk"):
                d.upload(src, n)
            self.assertEqual(d.archives()[0], "host1_job_20260103-000000.ngbk", "newest first")
            d.download("host1_job_20260102-000000.ngbk", os.path.join(tmp, "b"))
            self.assertEqual(open(os.path.join(tmp, "b"), "rb").read(), open(src, "rb").read())
            removed = lb.apply_retention(d, 1, 0)
            self.assertEqual(len(removed), 2)
            self.assertEqual(d.archives(), ["host1_job_20260103-000000.ngbk"])
            self.assertEqual(s3.bad_signatures, 0)
            bad = lb.Dest(dict(d.d, secret_key="wrong"), "host1", "job")
            with self.assertRaises(RuntimeError):
                bad.archives()
            shutil.rmtree(tmp, ignore_errors=True)
        finally:
            s3.stop()


class Health(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfgp = os.path.join(self.dir, "config.json")
        json.dump({"admin_password": "", "agent_token": "t", "db_path": "h.db"}, open(cfgp, "w"))
        cfg = server.load_config(cfgp)
        self.app = server.NetGuard(cfg, cfgp)
        self.app.ingest({"host": "H1"})
        self.user = dict(self.app.db.one("SELECT * FROM users WHERE username='admin'"))
        r = self.app.backups.save(self.user, {"host": "H1", "name": "J", "sources": {"folders": ["/var/www"]},
                                              "destinations": [{"type": "local", "path": "/backup"}],
                                              "schedule": {"mode": "daily", "at": "02:00"}, "rpo_hours": 24, "test_every_days": 7})
        self.jid = r["id"]
        self.assertTrue(r["recovery_key"])

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def alerts(self):
        return {a["rule"]: a["status"] for a in self.app.db.q("SELECT rule, status FROM alerts WHERE host='H1' AND rule LIKE '%backup%' OR rule LIKE 'restore%'")}

    def age_job(self, hours):
        self.app.db.x("UPDATE backup_jobs SET created_at=? WHERE id=?", (time.time() - hours * 3600, self.jid))

    def result(self, kind, status, hours_ago):
        t = time.time() - hours_ago * 3600
        self.app.backups._store_result("H1", {"run_ref": "ref-%s-%s-%d" % (kind, status, hours_ago * 1000), "job_id": self.jid, "kind": kind,
                                              "status": status, "started": t - 60, "finished": t, "archive": "x.ngbk"})

    def test_lifecycle(self):
        self.app.backups.check_health()
        self.assertEqual(self.alerts(), {}, "new job: no alerts yet")
        self.age_job(30)
        self.app.backups.check_health()
        self.assertEqual(self.alerts().get("backup_missing"), "open")
        self.result("backup", "failed", 2)
        self.app.backups.check_health()
        self.assertEqual(self.alerts().get("backup_failed"), "open")
        self.result("backup", "ok", 1)
        self.app.backups.check_health()
        a = self.alerts()
        self.assertEqual((a.get("backup_missing"), a.get("backup_failed")), ("resolved", "resolved"))
        self.result("backup", "ok", 30)   # make the newest success old: delete the fresh one
        self.app.db.x("DELETE FROM backup_runs WHERE kind='backup' AND finished > ?", (time.time() - 7200,))
        self.app.backups.check_health()
        self.assertEqual(self.alerts().get("backup_stale"), "open")
        self.age_job(24 * 12)
        self.result("backup", "ok", 0.1)
        self.app.backups.check_health()
        a = self.alerts()
        self.assertEqual(a.get("backup_stale"), "resolved")
        self.assertEqual(a.get("restore_untested"), "open", "12-day-old job never test-restored")
        self.result("test", "ok", 0.05)
        self.app.backups.check_health()
        self.assertEqual(self.alerts().get("restore_untested"), "resolved")
        # the suggested remediation is a real, signed-able action
        al = self.app.db.one("SELECT suggested FROM alerts WHERE rule='backup_stale'")
        self.assertEqual(json.loads(al["suggested"])[0]["action"], "backup_run")

    def test_recovery_key_in_vault_and_bundle_signed(self):
        items = self.app.vault.list(self.user)
        self.assertTrue(any(i["name"].startswith("Backup recovery key: J") for i in items))
        out = self.app.backups.agent_extra("H1", {})
        env = out["backup_jobs"]["envelope"]
        import base64
        self.assertTrue(lb.__name__)  # imported
        sys.path.insert(0, os.path.join(REPO, "agents", "linux"))
        import netguard_agent as ag
        self.assertTrue(ag.p256_verify(self.app.keys.public_raw, env.encode(), base64.b64decode(out["backup_jobs"]["sig"])))
        self.assertNotIn("backup_jobs", self.app.backups.agent_extra("H1", {"backup_jobs_version": out["backup_jobs_version"]}),
                         "bundle only re-sent when it changes")


if __name__ == "__main__":
    unittest.main()
