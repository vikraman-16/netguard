"""Per-server agent keys, signed commands, join control, DB backups, notifications."""
import base64
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from helpers import AGENT_TOKEN, REPO, Dashboard, free_port, owner

sys.path.insert(0, os.path.join(REPO, "agents", "linux"))
import netguard_agent as agent  # noqa: E402


class Receiver:
    """Fake webhook endpoint that records what NetGuard posts."""

    def __init__(self):
        self.got = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                outer.got.append({"path": self.path, "headers": dict(self.headers), "json": json.loads(self.rfile.read(n))})
                self.send_response(204)
                self.end_headers()

            def log_message(self, *a):
                pass
        self.port = free_port()
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.port

    def wait(self, n, timeout=10):
        end = time.time() + timeout
        while len(self.got) < n and time.time() < end:
            time.sleep(0.1)
        return self.got


class AgentKeysAndSigning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Dashboard().start()
        cls.own = owner(cls.d)

    @classmethod
    def tearDownClass(cls):
        cls.d.stop()

    def test_join_then_own_key(self):
        st, r1 = self.d.report("WEB1", token=AGENT_TOKEN)
        self.assertEqual(st, 200)
        key = r1["agent_token"]
        self.assertNotEqual(key, AGENT_TOKEN)
        st, r2 = self.d.report("WEB1", token=key)          # first use activates the key
        self.assertEqual(st, 200)
        self.assertNotIn("agent_token", r2)
        st, e = self.d.report("WEB1", token=AGENT_TOKEN)
        self.assertEqual(st, 401, "join token must stop working for this server")
        self.assertIn("own agent key", e["error"])
        self.assertEqual(self.d.report("WEB1", token="wrong")[0], 401)
        s = self.own.call("/api/settings")[1]
        self.assertTrue([h for h in s["hosts"] if h["name"] == "WEB1"][0]["has_key"])

    def test_lost_reply_does_not_lock_out(self):
        st, r1 = self.d.report("LOSSY", token=AGENT_TOKEN)        # reply "lost": agent never saw r1's key
        st, r2 = self.d.report("LOSSY", token=AGENT_TOKEN)
        self.assertEqual(st, 200)
        self.assertEqual(self.d.report("LOSSY", token=r1["agent_token"])[0], 401, "superseded key")
        self.assertEqual(self.d.report("LOSSY", token=r2["agent_token"])[0], 200)

    def test_signed_commands_verify_with_the_agent_code(self):
        st, r = self.d.report("SIGN1", [{"rule": "new_listener", "severity": "high", "fingerprint": "l:1", "title": "t"}])
        key = r["agent_token"]
        self.d.report("SIGN1", token=key)
        aid = [a for a in self.own.call("/api/alerts")[1] if a["host"] == "SIGN1"][0]["id"]
        st, q = self.own.call("/api/alerts/%d/action" % aid, {"action": "accept_listener", "params": {"port": 8080, "protocol": "tcp"}})
        self.assertEqual(st, 200, q)
        st, r = self.d.report("SIGN1", token=key)
        cmd = r["commands"][0]
        pub = base64.b64decode(r["command_public_key"])
        self.assertTrue(agent.p256_verify(pub, cmd["envelope"].encode(), base64.b64decode(cmd["sig"])))
        env = json.loads(cmd["envelope"])
        self.assertEqual((env["host"], env["action"], env["params"]), ("SIGN1", "accept_listener", {"port": 8080, "protocol": "tcp"}))
        # the agent's own checks
        a = agent.Agent.__new__(agent.Agent)
        a.host, a.cfg, a.state = "SIGN1", {"state_dir": "/tmp"}, agent.State(os.devnull + "-none")
        self.assertEqual(a.verify_command(cmd, r["command_public_key"])[0], "accept_listener")
        with self.assertRaises(PermissionError):
            a.verify_command(cmd, r["command_public_key"])          # replay
        a.host = "OTHER"
        with self.assertRaises(PermissionError):
            a.verify_command(dict(cmd, id=cmd["id"]), r["command_public_key"])
        forged = dict(cmd, envelope=cmd["envelope"].replace("accept_listener", "kill_process"))
        a.host, a.state = "SIGN1", agent.State(os.devnull + "-none2")
        with self.assertRaises(PermissionError):
            a.verify_command(forged, r["command_public_key"])
        with self.assertRaises(PermissionError):
            a.verify_command({"id": cmd["id"], "action": "kill_process", "params": {}}, r["command_public_key"])

    def test_zz_join_control_reset_and_rotation(self):
        self.own.call("/api/settings", {"allow_enrollment": False})
        st, e = self.d.report("NEWBOX", token=AGENT_TOKEN)
        self.assertEqual(st, 401)
        self.own.call("/api/settings", {"allow_enrollment": True})
        st, r = self.d.report("RESETME", token=AGENT_TOKEN)
        self.d.report("RESETME", token=r["agent_token"])
        self.assertEqual(self.d.report("RESETME", token=AGENT_TOKEN)[0], 401)
        self.assertEqual(self.own.call("/api/hosts/RESETME/reset-key", {})[0], 200)
        self.assertEqual(self.d.report("RESETME", token=AGENT_TOKEN)[0], 200, "after reset it can re-join")
        new = self.own.call("/api/settings/rotate-join-token", {})[1]["token"]
        self.assertEqual(self.d.report("BRANDNEW", token=AGENT_TOKEN)[0], 401, "old join token rotated out")
        self.assertEqual(self.d.report("BRANDNEW2", token=new)[0], 200)
        self.assertEqual(json.load(open(self.d.cfg_path))["agent_token"], new, "persisted")
        self.d.report("WEB1x", token=new)

    def test_db_backup(self):
        st, r = self.own.call("/api/settings/backup-db", {})
        self.assertEqual(st, 200)
        self.assertTrue(os.path.getsize(r["path"]) > 0)
        self.assertTrue(self.own.call("/api/settings")[1]["db_backups"])

    def test_keys_exist_and_are_private(self):
        self.assertTrue(os.path.exists(os.path.join(self.d.dir, "netguard.key")))
        self.assertTrue(os.path.exists(os.path.join(self.d.dir, "command-signing.pub")))


class Notifications(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Dashboard().start()
        cls.own = owner(cls.d)
        cls.rx = Receiver()

    @classmethod
    def tearDownClass(cls):
        cls.d.stop()
        cls.rx.srv.shutdown()

    def add(self, ctype, cfg, sev="high", digest=True, name=None):
        st, r = self.own.call("/api/notify/channels", {"name": name or ctype, "type": ctype, "config": cfg,
                                                       "min_severity": sev, "digest": digest})
        self.assertEqual(st, 200, r)
        return r["id"]

    def test_channels_alerts_digest(self):
        base = len(self.rx.got)
        self.add("discord", {"webhook_url": self.rx.url + "/discord"}, "high", name="d")
        self.add("teams", {"webhook_url": self.rx.url + "/teams"}, "critical", name="t")
        self.add("webhook", {"url": self.rx.url + "/hook", "header": "Authorization: Bearer abc123secret"}, "medium", name="w")
        # secrets are never shown back
        lst = json.dumps(self.own.call("/api/notify/channels")[1])
        self.assertNotIn("abc123secret", lst)
        self.assertNotIn("/discord", lst)
        self.d.report("N1", [{"rule": "x", "severity": "critical", "fingerprint": "c1", "title": "Crit thing", "details": "boom"},
                             {"rule": "x", "severity": "medium", "fingerprint": "m1", "title": "Med thing"}])
        got = self.rx.wait(base + 4)[base:]
        by = {}
        for g in got:
            by.setdefault(g["path"], []).append(g)
        self.assertEqual(len(by.get("/discord", [])), 1, "critical only (min high)")
        self.assertIn("CRITICAL on N1: Crit thing", by["/discord"][0]["json"]["content"])
        self.assertIn("/#alert=", by["/discord"][0]["json"]["content"])
        self.assertEqual(len(by.get("/teams", [])), 1)
        self.assertEqual(by["/teams"][0]["json"]["attachments"][0]["contentType"], "application/vnd.microsoft.card.adaptive")
        self.assertEqual(len(by.get("/hook", [])), 2, "medium + critical")
        self.assertEqual(by["/hook"][0]["headers"].get("Authorization"), "Bearer abc123secret")
        # repeat of the same alert does not notify again
        n = len(self.rx.got)
        self.d.report("N1", [{"rule": "x", "severity": "critical", "fingerprint": "c1", "title": "Crit thing"}])
        time.sleep(1)
        self.assertEqual(len(self.rx.got), n)
        # daily summary
        self.own.call("/api/settings/digest-now", {})
        dg = [g for g in self.rx.wait(n + 3)[n:] if g["path"] == "/discord"]
        self.assertTrue(dg and "Daily summary" in dg[0]["json"]["content"] and "Open alerts" in dg[0]["json"]["content"])

    def test_test_button_and_errors(self):
        cid = self.add("discord", {"webhook_url": self.rx.url + "/t2"}, name="t2")
        st, r = self.own.call("/api/notify/channels/%d/test" % cid, {})
        self.assertTrue(r["ok"], r)
        bad = self.add("discord", {"webhook_url": "http://127.0.0.1:1/nothing"}, name="bad")
        st, r = self.own.call("/api/notify/channels/%d/test" % bad, {})
        self.assertFalse(r["ok"])
        ch = [c for c in self.own.call("/api/notify/channels")[1]["channels"] if c["id"] == bad][0]
        self.assertTrue(ch["last_status"].startswith("error"))
        st, e = self.own.call("/api/notify/channels", {"name": "x", "type": "discord", "config": {"webhook_url": "http://evil.example/x"}})
        self.assertEqual(st, 400, "non-https rejected")

    def test_rate_limit(self):
        cid = self.add("webhook", {"url": self.rx.url + "/flood"}, "low", digest=False, name="flood")
        self.d.report("FLOOD", [{"rule": "x", "severity": "high", "fingerprint": "f%d" % i, "title": "t%d" % i} for i in range(30)])
        time.sleep(3)
        flood = [g for g in self.rx.got if g["path"] == "/flood"]
        self.assertEqual(len(flood), 21, "20 alerts + one 'too many' notice")
        self.assertIn("Too many alerts", flood[-1]["json"]["subject"])

    def test_non_owner_cannot_configure(self):
        from helpers import invite
        bob = invite(self.own, "admin", "*", "bob.n", "Some-Strong-Secret-7")
        self.assertEqual(bob.call("/api/notify/channels")[0], 403)
        self.assertEqual(bob.call("/api/settings/join-token", {})[0], 403)


if __name__ == "__main__":
    unittest.main()
