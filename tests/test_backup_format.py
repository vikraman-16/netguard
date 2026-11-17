"""NGBK1 archive format is identical on Windows (.NET) and Linux (openssl), and the DR tool reads both.
Also: both S3 signers reproduce the AWS documentation example."""
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "agents", "linux"))
import netguard_backup as lb  # noqa: E402

WIN_RUNNER = os.path.join(REPO, "agents", "windows", "NetGuard-Backup.ps1")
TOOL = os.path.join(REPO, "tools", "ng-decrypt.py")
HAS_WSL = sys.platform == "win32" and shutil.which("wsl.exe") is not None
AWS_SIG = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"


def ps(cmd):
    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                        ". '%s' -LibOnly; %s" % (WIN_RUNNER, cmd)], capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr)
    return r.stdout.strip()


def wsl_path(p):
    """wslpath only converts existing paths, so convert the folder and append the file name."""
    d, name = (p, "") if os.path.isdir(p) else os.path.split(p)
    base = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "wslpath", "-a", d.replace("\\", "/")], capture_output=True, text=True).stdout.strip()
    return base + ("/" + name if name else "")


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


class Format(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ngfmt-")
        self.key = os.urandom(32)
        self.k64 = base64.b64encode(self.key).decode()
        self.plain = os.path.join(self.dir, "plain.bin")
        with open(self.plain, "wb") as f:
            f.write(os.urandom(3 * 1024 * 1024 + 123))       # > 1 MB buffers, not block aligned

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def tool(self, archive, out, key=None):
        return subprocess.run([sys.executable, TOOL, archive, out, "--key", key or self.k64], capture_output=True, text=True)

    def test_aws_example_python(self):
        h = lb.sigv4_headers("GET", "https://examplebucket.s3.amazonaws.com/test.txt", "us-east-1", "AKIAIOSFODNN7EXAMPLE",
                             "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", lb.S3.EMPTY, "20130524T000000Z", {"Range": "bytes=0-9"})
        self.assertTrue(h["Authorization"].endswith(AWS_SIG))

    @unittest.skipUnless(sys.platform == "win32", "Windows")
    def test_aws_example_windows(self):
        out = ps("(Get-SigV4Headers 'GET' 'https://examplebucket.s3.amazonaws.com/test.txt' 'us-east-1' 'AKIAIOSFODNN7EXAMPLE' "
                 "'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' $EmptyHash '20130524T000000Z' @{ Range = 'bytes=0-9' }).Authorization")
        self.assertTrue(out.endswith(AWS_SIG), out)

    @unittest.skipUnless(sys.platform == "win32", "Windows")
    def test_windows_encrypt_then_tool_decrypts_and_detects_tampering(self):
        enc, out = os.path.join(self.dir, "w.ngbk"), os.path.join(self.dir, "w.out")
        ps("Protect-File '%s' '%s' ([Convert]::FromBase64String('%s'))" % (self.plain, enc, self.k64))
        r = self.tool(enc, out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sha(out), sha(self.plain))
        self.assertNotEqual(self.tool(enc, out + "2", base64.b64encode(os.urandom(32)).decode()).returncode, 0, "wrong key")
        data = bytearray(open(enc, "rb").read())
        data[len(data) // 2] ^= 1
        open(enc, "wb").write(bytes(data))
        r = self.tool(enc, out + "3")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("INTEGRITY CHECK FAILED", r.stdout + r.stderr)
        self.assertFalse(os.path.exists(out + "3"), "nothing written for a tampered archive")

    @unittest.skipUnless(sys.platform == "win32", "Windows")
    def test_windows_roundtrip_and_tamper(self):
        enc, out = os.path.join(self.dir, "w.ngbk"), os.path.join(self.dir, "w.out")
        ps("$k=[Convert]::FromBase64String('%s'); Protect-File '%s' '%s' $k; Unprotect-File '%s' '%s' $k" % (self.k64, self.plain, enc, enc, out))
        self.assertEqual(sha(out), sha(self.plain))
        with self.assertRaises(RuntimeError):
            ps("Unprotect-File '%s' '%s' ([Convert]::FromBase64String('%s'))" % (enc, out + "x", base64.b64encode(os.urandom(32)).decode()))

    @unittest.skipUnless(HAS_WSL, "WSL")
    def test_cross_os(self):
        # Windows -> Linux
        wenc = os.path.join(self.dir, "w.ngbk")
        ps("Protect-File '%s' '%s' ([Convert]::FromBase64String('%s'))" % (self.plain, wenc, self.k64))
        code = ("import base64,sys; sys.path.insert(0,'%s'); import netguard_backup as b; "
                "b.decrypt_file('%s','%s',base64.b64decode('%s')); b.encrypt_file('%s','%s',base64.b64decode('%s'))") % (
            wsl_path(os.path.join(REPO, "agents", "linux")), wsl_path(wenc), wsl_path(os.path.join(self.dir, "l.out")), self.k64,
            wsl_path(self.plain), wsl_path(os.path.join(self.dir, "l.ngbk")), self.k64)
        r = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "python3", "-c", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sha(os.path.join(self.dir, "l.out")), sha(self.plain), "Linux decrypts Windows archive")
        # Linux -> Windows + DR tool
        ps("Unprotect-File '%s' '%s' ([Convert]::FromBase64String('%s'))" % (os.path.join(self.dir, "l.ngbk"), os.path.join(self.dir, "w2.out"), self.k64))
        self.assertEqual(sha(os.path.join(self.dir, "w2.out")), sha(self.plain), "Windows decrypts Linux archive")
        r = self.tool(os.path.join(self.dir, "l.ngbk"), os.path.join(self.dir, "t.out"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sha(os.path.join(self.dir, "t.out")), sha(self.plain), "DR tool decrypts Linux archive")


if __name__ == "__main__":
    unittest.main()
