"""End-to-end backups with the real agents: Windows (this PC) and Linux (WSL).
Local folder + S3 (fake, signature-verifying) destinations, retention, test restore, restore, DR tool, health alerts."""
import base64
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile

from fake_s3 import FakeS3
from helpers import REPO, Dashboard, owner

HAS_WSL = sys.platform == "win32" and shutil.which("wsl.exe") is not None


def make_sample(root):
    os.makedirs(os.path.join(root, "site", "img"), exist_ok=True)
    with open(os.path.join(root, "site", "index.html"), "w") as f:
        f.write("<h1>hello netguard</h1>")
    with open(os.path.join(root, "site", "img", "logo.bin"), "wb") as f:
        f.write(os.urandom(200000))
    db = os.path.join(root, "app.sqlite")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE t(x)")
    c.executemany("INSERT INTO t VALUES(?)", [(i,) for i in range(500)])
    c.commit()
    c.close()
    return os.path.join(root, "site"), db


@unittest.skipUnless(sys.platform == "win32", "Windows agent")
class WindowsBackups(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Dashboard().start()
        cls.own = owner(cls.d)
        cls.s3 = FakeS3()
        cls.tmp = tempfile.mkdtemp(prefix="ng-bk-")
        cls.site, cls.dbfile = make_sample(os.path.join(cls.tmp, "data"))
        cls.dest = os.path.join(cls.tmp, "dest")
        cls.cfgp = os.path.join(cls.tmp, "agent.json")
        json.dump({"server_url": cls.d.base, "agent_token": "test-agent-token", "host_name": "BKWIN",
                   "state_dir": os.path.join(cls.tmp, "state"), "harden_script": "",
                   "backup_script": os.path.join(REPO, "agents", "windows", "NetGuard-Backup.ps1")}, open(cls.cfgp, "w"))
        cls.agent()

    @classmethod
    def tearDownClass(cls):
        cls.d.stop()
        cls.s3.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def agent(cls):
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                        os.path.join(REPO, "agents", "windows", "NetGuard-Agent.ps1"), "-ConfigPath", cls.cfgp],
                       capture_output=True, text=True, timeout=300)

    def wait_run(self, jid, kind, n=1, timeout=240):
        end = time.time() + timeout
        while time.time() < end:
            self.agent()
            runs = [r for r in self.own.call("/api/backups/%d/runs" % jid)[1] if r["kind"] == kind and r["status"] != "running"]
            if len(runs) >= n:
                return runs[0]
            time.sleep(2)
        self.fail("no finished %s run within %ds" % (kind, timeout))

    def test_full_cycle(self):
        st, s3item = self.own.call("/api/vault/items", {"name": "fake s3", "kind": "s3", "fields": {
            "endpoint": self.s3.endpoint, "region": "us-east-1", "bucket": "backups", "prefix": "nb", "access_key": "AKTEST",
            "secret_key": "secret-test-key"}})
        st, dbitem = self.own.call("/api/vault/items", {"name": "app db", "kind": "database", "fields": {"engine": "sqlite", "host": self.dbfile}})
        st, job = self.own.call("/api/backups/jobs", {
            "host": "BKWIN", "name": "Site and DB",
            "sources": {"folders": [self.site], "databases": [dbitem["id"]], "excludes": ["*.tmp"]},
            "destinations": [{"type": "local", "path": self.dest}, {"type": "s3", "vault_id": s3item["id"]}],
            "schedule": {"mode": "daily", "at": "00:00"}, "retention": {"keep_last": 1, "keep_days": 0},
            "rpo_hours": 24, "test_every_days": 7})
        self.assertEqual(st, 200, job)
        jid, key = job["id"], job["recovery_key"]
        # first run happens on schedule (today's 00:00 slot has passed)
        run = self.wait_run(jid, "backup")
        self.assertEqual(run["status"], "ok", run["log"])
        self.assertEqual([d["ok"] for d in run["details"]["destinations"]], [True, True], run["details"])
        self.assertEqual(self.s3.bad_signatures, 0, "every S3 request was correctly signed")
        local_dir = os.path.join(self.dest, "BKWIN", "site-and-db")
        self.assertTrue(os.path.exists(os.path.join(local_dir, run["archive"])))
        self.assertTrue(any(k.endswith(run["archive"]) for k in self.s3.objects), list(self.s3.objects))
        # DR tool, without NetGuard
        out = os.path.join(self.tmp, "dr.zip")
        r = subprocess.run([sys.executable, os.path.join(REPO, "tools", "ng-decrypt.py"), os.path.join(local_dir, run["archive"]), out,
                            "--key", key], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with zipfile.ZipFile(out) as z:
            names = z.namelist()
            self.assertTrue(any(n.endswith("site/index.html") for n in names), names[:10])
            self.assertTrue(any(n.startswith("databases/") and n.endswith(".sqlite") for n in names))
        # a second backup -> retention keeps only the newest
        time.sleep(1.2)
        self.own.call("/api/hosts/BKWIN/action", {"action": "backup_run", "params": {"job_id": jid}})
        run2 = self.wait_run(jid, "backup", n=2)
        self.assertEqual(run2["status"], "ok", run2["log"])
        self.assertEqual(sorted(f for f in os.listdir(local_dir) if f.endswith(".ngbk")), [run2["archive"]])
        self.assertEqual(len([k for k in self.s3.objects if k.endswith(".ngbk")]), 1)
        # test restore
        self.own.call("/api/hosts/BKWIN/action", {"action": "backup_test", "params": {"job_id": jid}})
        t = self.wait_run(jid, "test")
        self.assertEqual(t["status"], "ok", t["log"])
        self.assertTrue(all(c["ok"] for c in t["details"]["checks"]), t["details"])
        # restore into a new folder
        target = os.path.join(self.tmp, "restored")
        self.own.call("/api/hosts/BKWIN/action", {"action": "backup_restore", "params": {"job_id": jid, "target": target}})
        rr = self.wait_run(jid, "restore")
        self.assertEqual(rr["status"], "ok", rr["log"])
        restored = [os.path.join(dp, f) for dp, _, fs in os.walk(target) for f in fs if f == "logo.bin"][0]
        self.assertEqual(hashlib.sha256(open(restored, "rb").read()).hexdigest(),
                         hashlib.sha256(open(os.path.join(self.site, "img", "logo.bin"), "rb").read()).hexdigest())
        # job list shows healthy state
        jobs = self.own.call("/api/backups")[1]["jobs"]
        j = [x for x in jobs if x["id"] == jid][0]
        self.assertEqual(j["health"], [])
        self.assertEqual(j["last"]["test_ok"]["status"], "ok")


@unittest.skipUnless(HAS_WSL, "WSL Linux agent")
class LinuxBackups(unittest.TestCase):
    def test_linux_backup_test_restore(self):
        d = Dashboard({"listen_host": "0.0.0.0"}).start()
        try:
            own = owner(d)
            gw = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "ip", "route", "show", "default"], capture_output=True, text=True).stdout.split()[2]
            base = "/tmp/ng-bk-%d" % os.getpid()
            agent = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "wslpath", "-a", os.path.join(REPO, "agents", "linux").replace("\\", "/")],
                                   capture_output=True, text=True).stdout.strip() + "/netguard_agent.py"
            cfg = json.dumps({"server_url": "http://%s:%d" % (gw, d.port), "agent_token": "test-agent-token", "host_name": "BKLNX",
                              "state_dir": base + "/state", "harden_script": ""})
            setup = ("mkdir -p {b}/data/site {b}/dest && head -c 100000 /dev/urandom > {b}/data/site/blob.bin && echo hi > {b}/data/site/a.txt && "
                     "python3 -c \"import sqlite3;c=sqlite3.connect('{b}/data/app.sqlite');c.execute('create table t(x)');c.commit()\" && "
                     "printf '%s' '{cfg}' > {b}/a.json").format(b=base, cfg=cfg)
            subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", "-c", setup], capture_output=True, text=True, timeout=120)
            run_agent = lambda: subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", "-c", "python3 '%s' --config %s/a.json --once" % (agent, base)],
                                               capture_output=True, text=True, timeout=300)
            run_agent()
            st, dbi = own.call("/api/vault/items", {"name": "lnx db", "kind": "database", "fields": {"engine": "sqlite", "host": base + "/data/app.sqlite"}})
            st, job = own.call("/api/backups/jobs", {"host": "BKLNX", "name": "lnx", "sources": {"folders": [base + "/data/site"], "databases": [dbi["id"]]},
                                                     "destinations": [{"type": "local", "path": base + "/dest"}],
                                                     "schedule": {"mode": "daily", "at": "00:00"}, "retention": {"keep_last": 3, "keep_days": 0}})
            self.assertEqual(st, 200, job)
            jid = job["id"]

            def wait(kind):
                for _ in range(60):
                    r = run_agent()
                    runs = [x for x in own.call("/api/backups/%d/runs" % jid)[1] if x["kind"] == kind and x["status"] != "running"]
                    if runs:
                        return runs[0], r
                    time.sleep(2)
                self.fail("no %s result; agent stderr: %s" % (kind, r.stderr[-1500:]))
            b, _ = wait("backup")
            self.assertEqual(b["status"], "ok", b["log"])
            own.call("/api/hosts/BKLNX/action", {"action": "backup_test", "params": {"job_id": jid}})
            t, _ = wait("test")
            self.assertEqual(t["status"], "ok", t["log"])
            own.call("/api/hosts/BKLNX/action", {"action": "backup_restore", "params": {"job_id": jid, "target": base + "/restored"}})
            r, _ = wait("restore")
            self.assertEqual(r["status"], "ok", r["log"])
            chk = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", "-c",
                                  "cmp {b}/data/site/blob.bin $(find {b}/restored -name blob.bin) && echo SAME; rm -rf {b}".format(b=base)],
                                 capture_output=True, text=True).stdout
            self.assertIn("SAME", chk)
        finally:
            d.stop()


if __name__ == "__main__":
    unittest.main()
