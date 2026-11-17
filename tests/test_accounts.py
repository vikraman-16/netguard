"""Accounts, roles, per-server access, 2-factor, invites, lockouts, recovery."""
import json
import unittest

from helpers import BOOT_PW, Client, Dashboard, code, enroll, invite, owner


class AccountsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Dashboard().start()
        for h in ("WEB1", "DB1"):
            cls.d.report(h, [{"rule": "hardening_drift", "severity": "high", "fingerprint": "harden:x", "title": "Hardening on " + h}])
        cls.own = owner(cls.d)

    @classmethod
    def tearDownClass(cls):
        cls.d.stop()

    def test_anonymous_is_refused(self):
        anon = Client(self.d)
        self.assertEqual(anon.call("/api/alerts")[0], 401)
        import urllib.request
        with urllib.request.urlopen(self.d.base + "/", timeout=5) as r:
            self.assertTrue(r.url.endswith("/login"))

    def test_bootstrap_password_is_single_use_and_erased(self):
        cfg = json.load(open(self.d.cfg_path))
        self.assertEqual(cfg["admin_password"], "")
        self.assertEqual(Client(self.d).call("/api/auth/login", {"username": "admin", "password": BOOT_PW})[0], 400)

    def test_session_cookie_flags(self):
        cookie = list(self.own.jar)[0]
        self.assertTrue(cookie.has_nonstandard_attr("HttpOnly"))
        self.assertEqual(cookie.get_nonstandard_attr("SameSite"), "Strict")

    def test_weak_password_and_bad_code(self):
        c = Client(self.d)
        st, inv = self.own.call("/api/users/invite", {"role": "viewer"})
        tok = inv["link_path"].split("=", 1)[1]
        st, e = c.call("/api/invite/accept", {"token": tok, "username": "weak", "password": "short"})
        self.assertEqual(st, 400)
        st, r = c.call("/api/invite/accept", {"token": tok, "username": "weakfix", "password": "Fine-Password-123"})
        st, en = c.call("/api/auth/enroll/start", {"ticket": r["ticket"]})
        self.assertEqual(c.call("/api/auth/enroll/finish", {"ticket": r["ticket"], "code": "000000"})[0], 400)
        self.assertEqual(Client(self.d).call("/api/invite/info", {"token": tok})[0], 400, "invite must be single-use")

    def test_admin_scoped_to_one_server(self):
        bob = invite(self.own, "admin", ["WEB1"], "bob.scope")
        st, alerts = bob.call("/api/alerts")
        self.assertEqual({a["host"] for a in alerts}, {"WEB1"})
        self.assertEqual([h["name"] for h in bob.call("/api/hosts")[1]], ["WEB1"])
        db1 = [a for a in self.own.call("/api/alerts")[1] if a["host"] == "DB1"][0]
        web1 = alerts[0]
        self.assertEqual(bob.call("/api/alerts/%d" % db1["id"])[0], 404)
        self.assertEqual(bob.call("/api/alerts/%d/status" % db1["id"], {"status": "resolved"})[0], 404)
        self.assertEqual(bob.call("/api/alerts/%d/status" % web1["id"], {"status": "acknowledged"})[0], 200)
        self.assertEqual(bob.call("/api/alerts/%d/action" % web1["id"], {"action": "suppress", "scope": "rule_all"})[0], 403)
        self.assertEqual(bob.call("/api/users")[0], 403)
        audit = self.own.call("/api/audit")[1]
        self.assertTrue(any(x["user"] == "bob.scope" and x["action"] == "status_acknowledged" for x in audit))

    def test_viewer_is_read_only(self):
        vic = invite(self.own, "viewer", "*", "vic.ro", "Viewer-Strong-Password-9")
        al = vic.call("/api/alerts")[1]
        self.assertEqual({a["host"] for a in al}, {"WEB1", "DB1"})
        self.assertEqual(vic.call("/api/alerts/%d/status" % al[0]["id"], {"status": "resolved"})[0], 403)

    def test_csrf_header_required(self):
        self.assertEqual(self.own.call("/api/me/password", {"current": "x", "new": "y"}, csrf=False)[0], 403)

    def test_lockout_and_generic_errors(self):
        invite(self.own, "viewer", "*", "lock.me", "Locked-Password-123")
        for i in range(5):
            Client(self.d).call("/api/auth/login", {"username": "lock.me", "password": "wrong-%d" % i})
        st, e = Client(self.d).call("/api/auth/login", {"username": "lock.me", "password": "Locked-Password-123"})
        self.assertEqual(st, 400)
        self.assertIn("locked", e["error"])
        st, e = Client(self.d).call("/api/auth/login", {"username": "nobody", "password": "x"})
        self.assertEqual(e["error"], "Wrong username or password.")

    def test_code_replay_rejected(self):
        c = invite(self.own, "viewer", "*", "replay", "Another-Secret-Pw-123")
        st, r = Client(self.d).call("/api/auth/login", {"username": "replay", "password": "Another-Secret-Pw-123"})
        self.assertEqual(Client(self.d).call("/api/auth/totp", {"ticket": r["ticket"], "code": code(c.secret)})[0], 400)

    def test_owner_controls_and_reset(self):
        carl = invite(self.own, "admin", "*", "carl", "Admin-Strong-Secret-1")
        uid = [u for u in self.own.call("/api/users")[1]["users"] if u["username"] == "carl"][0]["id"]
        self.own.call("/api/users/%d/update" % uid, {"role": "admin", "hosts": "*", "disabled": True})
        self.assertEqual(carl.call("/api/me")[0], 401, "disable must sign out")
        owner_id = [u for u in self.own.call("/api/users")[1]["users"] if u["username"] == "admin"][0]["id"]
        self.assertEqual(self.own.call("/api/users/%d/update" % owner_id, {"role": "admin"})[0], 400, "last owner")
        self.own.call("/api/users/%d/update" % uid, {"role": "admin", "hosts": "*", "disabled": False})
        st, rs = self.own.call("/api/users/%d/reset" % uid, {})
        c2 = Client(self.d)
        st, r = c2.call("/api/invite/accept", {"token": rs["link_path"].split("=", 1)[1], "password": "Brand-New-Secret-2026"})
        self.assertEqual(r["step"], "enroll")
        enroll(c2, r)
        sess = [s for s in self.own.call("/api/sessions")[1] if s["username"] == "carl"][0]
        self.own.call("/api/sessions/%d/revoke" % sess["id"], {})
        self.assertEqual(c2.call("/api/me")[0], 401)

    def test_zz_console_reset(self):
        d = Dashboard().start()
        try:
            o = owner(d)
            out = d.cli("--reset-user", "admin").stdout
            pw = out.split("One-time password: ")[1].split()[0]
            self.assertEqual(o.call("/api/me")[0], 401)
            st, r = Client(d).call("/api/auth/login", {"username": "admin", "password": pw})
            self.assertEqual(r["step"], "password")
        finally:
            d.stop()


if __name__ == "__main__":
    unittest.main()
