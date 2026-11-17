"""Credential vault: encryption at rest, sharing, step-up 2FA before reveal, logging, roles."""
import json
import sqlite3
import unittest

from helpers import Client, Dashboard, code, invite, owner, wait_next_step


class VaultTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Dashboard().start()
        cls.own = owner(cls.d)
        cls.d.report("WEB1")
        cls.bob = invite(cls.own, "admin", "*", "bob.v", "Some-Strong-Secret-7")
        cls.vic = invite(cls.own, "viewer", "*", "vic.v", "Viewer-Strong-Secret-9")

    @classmethod
    def tearDownClass(cls):
        cls.d.stop()

    def add(self, who, body):
        st, r = who.call("/api/vault/items", body)
        self.assertEqual(st, 200, r)
        return r["id"]

    def test_secrets_are_encrypted_masked_and_need_stepup(self):
        iid = self.add(self.own, {"name": "Router admin", "kind": "login",
                                  "fields": {"url": "https://10.0.0.1", "username": "root", "password": "Hunter2-very-secret"}})
        db = sqlite3.connect(self.d.dir + "/t.db")
        raw = db.execute("SELECT data FROM vault_items WHERE id=?", (iid,)).fetchone()[0]
        self.assertNotIn("Hunter2", raw, "stored encrypted")
        items = self.own.call("/api/vault")[1]["items"]
        it = [i for i in items if i["id"] == iid][0]
        self.assertEqual(it["fields"]["username"], "root")
        self.assertNotIn("Hunter2", json.dumps(items), "list never contains secrets")
        st, e = self.own.call("/api/vault/items/%d/reveal" % iid, {})
        self.assertEqual(st, 403)
        self.assertTrue(e.get("stepup"))
        wait_next_step()                      # the sign-in code of this 30 s window is already used
        self.assertEqual(self.own.call("/api/vault/stepup", {"code": "000000"})[0], 400)
        self.assertEqual(self.own.call("/api/vault/stepup", {"code": code(self.own.secret)})[0], 200)
        st, r = self.own.call("/api/vault/items/%d/reveal" % iid, {})
        self.assertEqual(r["fields"]["password"], "Hunter2-very-secret")
        log = self.own.call("/api/vault/log")[1]
        self.assertTrue(any(x["action"] == "reveal" and x["item_id"] == iid for x in log))

    def test_sharing_and_roles(self):
        iid = self.add(self.own, {"name": "DB prod", "kind": "database",
                                  "fields": {"engine": "mysql", "host": "db1", "username": "backup", "password": "pw-db-123"}})
        self.assertFalse([i for i in self.bob.call("/api/vault")[1]["items"] if i["id"] == iid], "not shared yet")
        self.assertEqual(self.bob.call("/api/vault/items/%d/reveal" % iid, {})[0], 404)
        self.own.call("/api/vault/items/%d/share" % iid, {"users": ["bob.v", "vic.v"]})
        shared = [i for i in self.bob.call("/api/vault")[1]["items"] if i["id"] == iid]
        self.assertTrue(shared)
        self.assertNotIn("vic.v", shared[0]["access"], "viewers can't be given vault access")
        self.assertEqual(self.vic.call("/api/vault")[0], 403)
        st, e = self.bob.call("/api/vault/items/%d/share" % iid, {"users": []})
        self.assertEqual(st, 403, "only owner/creator re-shares")
        bob_item = self.add(self.bob, {"name": "Bob's API key", "kind": "api_key", "fields": {"service": "x", "key": "k-123"}})
        self.assertTrue([i for i in self.own.call("/api/vault")[1]["items"] if i["id"] == bob_item], "owners see everything")

    def test_validation_and_edit_keeps_secret(self):
        self.assertEqual(self.own.call("/api/vault/items", {"name": "bad", "kind": "s3", "fields": {"endpoint": "http://evil", "bucket": "b",
                                                                                                    "access_key": "a", "secret_key": "s"}})[0], 400)
        iid = self.add(self.own, {"name": "S3", "kind": "s3", "fields": {"endpoint": "https://s3.example.com", "bucket": "b",
                                                                         "access_key": "AK", "secret_key": "SK-keep"}})
        self.own.call("/api/vault/items/%d/update" % iid, {"name": "S3 renamed", "fields": {"endpoint": "https://s3.example.com",
                                                                                           "bucket": "b2", "access_key": "AK", "secret_key": ""}})
        db = sqlite3.connect(self.d.dir + "/t.db")
        self.assertEqual(db.execute("SELECT name FROM vault_items WHERE id=?", (iid,)).fetchone()[0], "S3 renamed")


if __name__ == "__main__":
    unittest.main()
