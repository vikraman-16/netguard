"""
NetGuard key material and cryptography (uses the 'cryptography' package).

Files in the dashboard data folder (keep that folder admin/SYSTEM-only, back it up offline):
  netguard.key           32-byte master key: AES-256-GCM encryption of stored secrets (vault, channels, cloud keys)
  command-signing.pem    ECDSA P-256 private key: signs every command sent to agents

Without netguard.key the encrypted secrets in the database cannot be recovered.
"""
import base64
import json
import os
import secrets
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

COMMAND_TTL = 15 * 60   # agents refuse commands older than this


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


class KeyStore:
    def __init__(self, data_dir):
        self.dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        kp = os.path.join(data_dir, "netguard.key")
        if not os.path.exists(kp):
            _write_private(kp, base64.b64encode(secrets.token_bytes(32)))
        with open(kp, "rb") as f:
            self.master = base64.b64decode(f.read().strip())
        if len(self.master) != 32:
            raise ValueError("netguard.key is corrupt (expected 32 bytes)")
        sp = os.path.join(data_dir, "command-signing.pem")
        if not os.path.exists(sp):
            k = ec.generate_private_key(ec.SECP256R1())
            _write_private(sp, k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        with open(sp, "rb") as f:
            self.signing = serialization.load_pem_private_key(f.read(), password=None)
        nums = self.signing.public_key().public_numbers()
        # raw X||Y (64 bytes): easy to load in Windows CNG (EccPublicBlob) and in the pure-Python verifier
        self.public_raw = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
        self.public_b64 = base64.b64encode(self.public_raw).decode()

    # ---- encryption at rest ------------------------------------------------
    def seal(self, value, purpose=""):
        """Encrypt str/bytes/JSON-able value. 'purpose' is bound as associated data (e.g. 'vault:12')."""
        if not isinstance(value, (str, bytes)):
            value = json.dumps(value)
        if isinstance(value, str):
            value = value.encode("utf-8")
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self.master).encrypt(nonce, value, purpose.encode())
        return "v1:" + base64.b64encode(nonce + ct).decode()

    def open(self, token, purpose="", as_json=False):
        if not token:
            return None
        if not token.startswith("v1:"):
            raise ValueError("unknown sealed format")
        raw = base64.b64decode(token[3:])
        pt = AESGCM(self.master).decrypt(raw[:12], raw[12:], purpose.encode())
        return json.loads(pt) if as_json else pt.decode("utf-8")

    # ---- command signing ---------------------------------------------------
    def sign_command(self, cid, host, action, params):
        now = int(time.time())
        envelope = json.dumps({"id": cid, "host": host, "action": action, "params": params, "issued": now,
                               "expires": now + COMMAND_TTL, "nonce": secrets.token_hex(8)},
                              sort_keys=True, separators=(",", ":"))
        der = self.signing.sign(envelope.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")       # IEEE P1363 (what Windows CNG expects)
        return envelope, base64.b64encode(sig).decode()
