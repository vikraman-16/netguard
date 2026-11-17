"""Risk register and DR plans: automatic risks, acceptance, manual risks, RPO/RTO checks, runbooks, permissions."""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

from helpers import REPO, Dashboard, invite, owner

sys.path.insert(0, os.path.join(REPO, "dashboard"))
import server  # noqa: E402


class RiskLogic(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        cfgp = os.path.join(self.dir, "config.json")
        json.dump({"admin_password": "", "agent_token": "t", "db_path": "r.db"}, open(cfgp, "w"))
        self.app = server.NetGuard(server.load_config(cfgp), cfgp)
        self.app.ingest({"host": "WEB1", "hardening": {"total": 10, "passed": 5, "ts": time.time()}})
        self.user = dict(self.app.db.one("SELECT * FROM users WHERE username='admin'"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def keys(self):
        return {r["key"]: r for r in self.app.risk.register()["auto"]}

    def test_auto_risks_follow_reality(self):
        k = self.keys()
        for expected in ("nobackup:WEB1", "noplan:WEB1", "harden:WEB1", "org:notify", "org:owners", "org:keys"):
            self.assertIn(expected, k)
        self.assertEqual(k["nobackup:WEB1"]["score"], 15)
        self.assertEqual(k["harden:WEB1"]["likelihood"], 4, "50% hardening = likely")
        # a critical alert -> critical security risk
        self.app.ingest({"host": "WEB1", "alerts": [{"rule": "process_masquerade", "severity": "critical", "fingerprint": "m", "title": "Fake svchost"}]})
        self.assertEqual(self.keys()["crit:WEB1"]["score"], 20)
        # backup job + plan with a tight RPO -> schedule can't meet it
        self.app.backups.save(self.user, {"host": "WEB1", "name": "J", "sources": {"folders": ["/srv"]},
                                          "destinations": [{"type": "local", "path": "/b"}], "schedule": {"mode": "daily", "at": "01:00"}})
        self.app.risk.save_plan("admin", "WEB1", {"tier": 1, "rpo_hours": 4, "rto_hours": 2, "contacts": "Ops 555-0100"})
        k = self.keys()
        self.assertNotIn("nobackup:WEB1", k)
        self.assertNotIn("noplan:WEB1", k)
        self.assertIn("rpo:WEB1", k)
        self.app.risk.save_plan("admin", "WEB1", {"tier": 1, "rpo_hours": 26, "rto_hours": 2})
        self.assertNotIn("rpo:WEB1", self.keys())
        # owner confirms offline keys
        self.app.set_setting("keys_offline_confirmed", True)
        self.assertNotIn("org:keys", self.keys())

    def test_accept_and_heatmap(self):
        before = self.app.risk.register()
        self.assertEqual(sum(map(sum, before["heat"])), before["summary"]["open"])
        self.app.risk.accept("admin", "noplan:WEB1", "dev box, rebuilt from scratch if lost", 30)
        after = self.app.risk.register()
        self.assertEqual(after["summary"]["open"], before["summary"]["open"] - 1)
        acc = [r for r in after["auto"] if r["key"] == "noplan:WEB1"][0]
        self.assertTrue(acc["accepted"]["until"] > time.time())
        with self.assertRaises(ValueError):
            self.app.risk.accept("admin", "org:notify", "ok", 30)   # reason too short
        self.app.risk.unaccept("admin", "noplan:WEB1")
        self.assertEqual(self.app.risk.register()["summary"]["open"], before["summary"]["open"])

    def test_manual_risks(self):
        rid = self.app.risk.save("admin", {"title": "Single ISP line", "likelihood": 2, "impact": 5, "category": "vendor", "due": "2020-01-01"})
        m = self.app.risk.manual()[0]
        self.assertEqual((m["score"], m["level"], m["overdue"]), (10, "medium", True))
        with self.assertRaises(ValueError):
            self.app.risk.save("admin", {"title": "x", "likelihood": 9, "impact": 1})
        self.app.risk.save("admin", {"title": "Single ISP line", "likelihood": 2, "impact": 5, "status": "closed"}, rid)
        self.assertFalse(self.app.risk.manual()[0]["overdue"])

    def test_plan_status_and_runbook(self):
        dbi = self.app.vault.save(self.user, {"name": "db", "kind": "database", "fields": {"engine": "mysql", "host": "localhost"}})
        j = self.app.backups.save(self.user, {"host": "WEB1", "name": "Site", "sources": {"website": True, "config": True, "databases": [dbi]},
                                              "destinations": [{"type": "local", "path": "/b"}], "schedule": {"mode": "hourly", "every": 6}})
        self.app.risk.save_plan("admin", "WEB1", {"tier": 1, "rpo_hours": 12, "rto_hours": 1})
        now = time.time()
        self.app.backups._store_result("WEB1", {"run_ref": "run-ok-000001", "job_id": j["id"], "kind": "backup", "status": "ok",
                                                "started": now - 7300, "finished": now - 7200})
        self.app.backups._store_result("WEB1", {"run_ref": "run-tst-000001", "job_id": j["id"], "kind": "test", "status": "ok",
                                                "started": now - 4000, "finished": now - 100, "details": {"duration_s": 5400}})
        p = self.app.risk.plans()[0]
        self.assertTrue(p["status"]["rpo_met"], p["status"])
        self.assertFalse(p["status"]["rto_met"], "90 min restore > 1 h RTO")
        self.assertIn("rto:WEB1", self.keys())
        text = json.dumps(p["runbook"])
        for needle in ("Restore the databases", "mysql -u root -p", "Restore the websites", "Restore server configuration", "ng-decrypt.py"):
            self.assertIn(needle, text)


class RiskPermissions(unittest.TestCase):
    def test_roles(self):
        d = Dashboard().start()
        try:
            own = owner(d)
            d.report("WEB1")
            adm = invite(own, "admin", ["WEB1"], "ann.r", "Admin-Strong-Secret-1")
            vw = invite(own, "viewer", "*", "vee.r", "Viewer-Strong-Secret-2")
            self.assertEqual(vw.call("/api/risks")[0], 200)
            self.assertEqual(vw.call("/api/dr")[0], 200)
            self.assertEqual(vw.call("/api/risks", {"title": "x"})[0], 403)
            self.assertEqual(adm.call("/api/risks", {"title": "UPS battery old", "likelihood": 3, "impact": 4})[0], 200)
            self.assertEqual(adm.call("/api/dr/WEB1", {"tier": 1, "rpo_hours": 24, "rto_hours": 4})[0], 200)
            self.assertEqual(adm.call("/api/risks/accept", {"key": "noplan:WEB1", "reason": "because reasons"})[0], 403)
            self.assertEqual(own.call("/api/risks/accept", {"key": "org:notify", "reason": "email relay comes next month", "days": 30})[0], 200)
            reg = own.call("/api/risks")[1]
            self.assertTrue([r for r in reg["auto"] if r["key"] == "org:notify"][0]["accepted"])
            self.assertFalse([r for r in adm.call("/api/risks")[1]["auto"] if r["key"].startswith("org:")], "org-wide risks are owner-level")
            dr = own.call("/api/dr")[1]["plans"][0]
            self.assertEqual(dr["plan"]["rto_hours"], 4)
        finally:
            d.stop()


if __name__ == "__main__":
    unittest.main()
