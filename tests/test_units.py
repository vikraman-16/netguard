"""Fast unit tests for pure functions (no server)."""
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "dashboard"))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "agents", "linux"))

import auth  # noqa: E402
import server  # noqa: E402
import netguard_agent as agent  # noqa: E402


class ActionValidation(unittest.TestCase):
    def test_known_and_unknown(self):
        self.assertEqual(server.validate_action("block_ip", {"ip": "203.0.113.5", "hours": "24"}), {"ip": "203.0.113.5", "hours": 24})
        for bad in [("rm_rf", {}), ("block_ip", {"ip": "127.0.0.1"}), ("block_ip", {"ip": "10.0.0.0/8"}),
                    ("block_port", {"port": 70000, "protocol": "tcp"}), ("kill_process", {"pid": 1, "name": "a;b"}),
                    ("allow_process", {"name": "x", "path": "relative\\x.exe"}), ("harden_fix", {"check_id": "../x"})]:
            with self.assertRaises((ValueError, TypeError)):
                server.validate_action(*bad)

    def test_scope_sql(self):
        self.assertEqual(server.scope_sql(None), ("1=1", []))
        self.assertEqual(server.scope_sql([]), ("0=1", []))
        self.assertEqual(server.scope_sql(["a", "b"], "name"), ("name IN (?,?)", ["a", "b"]))


class AuthPrimitives(unittest.TestCase):
    def test_password_hash(self):
        h = auth.hash_password("Correct-Horse-1")
        self.assertTrue(auth.verify_password("Correct-Horse-1", h))
        self.assertFalse(auth.verify_password("correct-horse-1", h))
        self.assertNotEqual(h, auth.hash_password("Correct-Horse-1"), "salted")

    def test_totp_rfc6238_vector(self):
        # RFC 6238 test secret "12345678901234567890", T=59 -> 94287082 (8 digits) -> 287082 (6 digits)
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(auth.totp_at(secret, 59 // 30), "287082")

    def test_totp_window_and_replay(self):
        s = auth.new_totp_secret()
        now = int(time.time() // 30)
        step = auth.totp_match(s, auth.totp_at(s, now), 0)
        self.assertEqual(step, now)
        self.assertIsNone(auth.totp_match(s, auth.totp_at(s, now), step), "same code twice")
        self.assertIsNone(auth.totp_match(s, auth.totp_at(s, now - 5), 0), "too old")


class LinuxAgentHelpers(unittest.TestCase):
    def test_split_addr(self):
        self.assertEqual(agent.split_addr("0.0.0.0:22"), ("0.0.0.0", 22))
        self.assertEqual(agent.split_addr("[::1]:631"), ("::1", 631))
        self.assertEqual(agent.split_addr("127.0.0.53%lo:53"), ("127.0.0.53", 53))
        self.assertEqual(agent.split_addr("[::ffff:10.0.0.2]:443"), ("10.0.0.2", 443))

    def test_lookalikes(self):
        self.assertEqual(agent.damerau("scvhost", "svchost"), 1)
        self.assertEqual(agent.ProcessTrust.lookalike("sshdd"), "sshd")
        self.assertIsNone(agent.ProcessTrust.lookalike("nginx"))
        self.assertIsNone(agent.ProcessTrust.lookalike("python3"))


if __name__ == "__main__":
    unittest.main()
