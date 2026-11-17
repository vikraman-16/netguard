"""Command signing: dashboard (cryptography) signs, agents verify (pure-Python on Linux, CNG on Windows)."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "dashboard"))
sys.path.insert(0, os.path.join(REPO, "agents", "linux"))
import netguard_agent as agent  # noqa: E402
from secure import KeyStore  # noqa: E402


class Signing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.ks = KeyStore(cls.dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_pure_python_verifier_matches_cryptography(self):
        pub = self.ks.public_raw
        for i in range(150):
            env, sig = self.ks.sign_command(i, "web1", "block_ip", {"ip": "203.0.113.%d" % (i % 250 + 1)})
            raw = base64.b64decode(sig)
            self.assertTrue(agent.p256_verify(pub, env.encode(), raw), env)
            self.assertFalse(agent.p256_verify(pub, env.replace("web1", "web2").encode(), raw), "tampered message")
            bad = bytearray(raw); bad[i % 64] ^= 1
            self.assertFalse(agent.p256_verify(pub, env.encode(), bytes(bad)), "tampered signature")
        other = KeyStore(tempfile.mkdtemp())
        env, sig = other.sign_command(1, "web1", "kill_process", {"pid": 5, "name": "x"})
        self.assertFalse(agent.p256_verify(pub, env.encode(), base64.b64decode(sig)), "signed by a different dashboard")
        self.assertFalse(agent.p256_verify(b"\x01" * 64, env.encode(), base64.b64decode(sig)), "point not on curve")

    def test_envelope_contents(self):
        env, _ = self.ks.sign_command(7, "web1", "harden_fix", {"check_id": "x"})
        e = json.loads(env)
        self.assertEqual((e["id"], e["host"], e["action"]), (7, "web1", "harden_fix"))
        self.assertGreater(e["expires"], time.time() + 600)

    def test_sealing(self):
        t = self.ks.seal({"password": "s3cret"}, "vault:1")
        self.assertNotIn("s3cret", t)
        self.assertEqual(self.ks.open(t, "vault:1", as_json=True), {"password": "s3cret"})
        with self.assertRaises(Exception):
            self.ks.open(t, "vault:2")          # bound to its purpose
        self.assertNotEqual(t, self.ks.seal({"password": "s3cret"}, "vault:1"), "random nonce")

    @unittest.skipUnless(sys.platform == "win32", "Windows CNG check")
    def test_windows_cng_verifies(self):
        env, sig = self.ks.sign_command(3, "HOST", "kill_process", {"pid": 9, "name": "x"})
        ps = os.path.join(self.dir, "v.ps1")
        with open(ps, "w") as f:
            f.write(r'''param($pub, $sig, $msgFile)
$msg = [IO.File]::ReadAllText($msgFile)
$raw = [Convert]::FromBase64String($pub); $blob = New-Object byte[] 72
[BitConverter]::GetBytes([uint32]0x31534345).CopyTo($blob, 0); [BitConverter]::GetBytes([uint32]32).CopyTo($blob, 4)
[Array]::Copy($raw, 0, $blob, 8, 64)
$k = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
$e = New-Object Security.Cryptography.ECDsaCng($k); $e.HashAlgorithm = [Security.Cryptography.CngAlgorithm]::Sha256
$e.VerifyData([Text.Encoding]::UTF8.GetBytes($msg), [Convert]::FromBase64String($sig))
$e.VerifyData([Text.Encoding]::UTF8.GetBytes($msg + ' '), [Convert]::FromBase64String($sig))''')
        mf = os.path.join(self.dir, "m.txt")
        with open(mf, "w", encoding="utf-8", newline="") as f:
            f.write(env)
        out = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps,
                              self.ks.public_b64, sig, mf], capture_output=True, text=True).stdout.split()
        self.assertEqual(out, ["True", "False"])


if __name__ == "__main__":
    unittest.main()
