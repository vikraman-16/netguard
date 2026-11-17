#!/usr/bin/env python3
"""
Decrypt a NetGuard backup archive (.ngbk) WITHOUT NetGuard - for disaster recovery.

    python ng-decrypt.py ARCHIVE.ngbk OUTPUT [--key RECOVERY_KEY]       (or set NG_RECOVERY_KEY)

The recovery key is the base64 key shown when the backup job was created (vault item
"Backup recovery key: ..."). Output is a .zip (Windows servers) or .tar.gz (Linux servers).
Works with the Python 'cryptography' package if installed, otherwise with the 'openssl' command.
The archive's integrity tag is verified BEFORE anything is decrypted.
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import os
import shutil
import subprocess
import sys

MAGIC = b"NGBK1"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("archive")
    ap.add_argument("output")
    ap.add_argument("--key", help="recovery key (base64); prompted if omitted")
    a = ap.parse_args()
    key_b64 = a.key or os.environ.get("NG_RECOVERY_KEY") or getpass.getpass("Recovery key: ")
    key = base64.b64decode(key_b64.strip())
    if len(key) != 32:
        sys.exit("That is not a NetGuard recovery key (expected 32 bytes, base64).")
    enc_pass = hmac.new(key, b"enc", hashlib.sha256).hexdigest().encode()
    mac_key = hmac.new(key, b"mac", hashlib.sha256).digest()

    size = os.path.getsize(a.archive)
    with open(a.archive, "rb") as f:
        if f.read(5) != MAGIC or f.read(8) != b"Salted__":
            sys.exit("Not a NetGuard (NGBK1) archive.")
        salt = f.read(8)
        f.seek(0)
        h = hmac.new(mac_key, digestmod=hashlib.sha256)
        left = size - 32
        while left:
            chunk = f.read(min(1 << 20, left))
            h.update(chunk)
            left -= len(chunk)
        if not hmac.compare_digest(h.digest(), f.read(32)):
            sys.exit("INTEGRITY CHECK FAILED: wrong recovery key, or the archive is damaged/tampered with. Nothing was written.")
    print("Integrity verified.")

    dk = hashlib.pbkdf2_hmac("sha256", enc_pass, salt, 1, 48)
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(dk[:32]), modes.CBC(dk[32:48])).decryptor()
        unpad = padding.PKCS7(128).unpadder()
        with open(a.archive, "rb") as f, open(a.output, "wb") as out:
            f.seek(21)
            left = size - 21 - 32
            while left:
                chunk = f.read(min(1 << 20, left))
                left -= len(chunk)
                out.write(unpad.update(dec.update(chunk)))
            out.write(unpad.update(dec.finalize()) + unpad.finalize())
    except ImportError:
        if not shutil.which("openssl"):
            sys.exit("Need either the Python 'cryptography' package (pip install cryptography) or the 'openssl' command.")
        blob = a.output + ".blob"
        with open(a.archive, "rb") as f, open(blob, "wb") as out:
            f.seek(5)
            left = size - 5 - 32
            while left:
                chunk = f.read(min(1 << 20, left))
                out.write(chunk)
                left -= len(chunk)
        r = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "1", "-md", "sha256", "-pass", "env:NGKEY",
                            "-in", blob, "-out", a.output], env=dict(os.environ, NGKEY=enc_pass.decode()))
        os.remove(blob)
        if r.returncode:
            sys.exit("openssl failed to decrypt.")
    kind = "zip (Windows backup)" if open(a.output, "rb").read(2) == b"PK" else "tar.gz (Linux backup)"
    print("Decrypted to %s - %s. Extract it with any archive tool." % (a.output, kind))


if __name__ == "__main__":
    main()
