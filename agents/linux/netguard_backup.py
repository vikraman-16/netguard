#!/usr/bin/env python3
"""
NetGuard backup runner (Linux). Started by the agent in its own process:

    netguard_backup.py --job JOBFILE --mode backup|test|restore [--archive NAME] [--target DIR] --result RESULTFILE

Archive format NGBK1 (identical on Windows and Linux; decrypt anywhere with tools/ng-decrypt.py):
    b"NGBK1" | openssl-salted blob ("Salted__" + 8-byte salt + AES-256-CBC ciphertext) | HMAC-SHA256 tag (32 bytes)
    enc passphrase = hex(HMAC-SHA256(job_key, "enc")), AES key/IV = PBKDF2-HMAC-SHA256(passphrase, salt, 1 iteration, 48 bytes)
    tag = HMAC-SHA256(HMAC-SHA256(job_key, "mac"), everything before the tag)
Standard library + the `openssl` command only.
"""
import argparse
import base64
import datetime
import fnmatch
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

MAGIC = b"NGBK1"
TOOL_VERSION = "1.0"
LOG = []


def log(msg):
    line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
    LOG.append(line)
    sys.stderr.write(line + "\n")


# ---------------------------------------------------------------------------
# Encryption (NGBK1)
# ---------------------------------------------------------------------------
def _subkeys(key):
    return (hmac.new(key, b"enc", hashlib.sha256).hexdigest(), hmac.new(key, b"mac", hashlib.sha256).digest())


def _openssl(args, passphrase):
    env = dict(os.environ, NGKEY=passphrase)
    r = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "1", "-md", "sha256", "-pass", "env:NGKEY"] + args,
                       env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode:
        raise RuntimeError("openssl failed: %s" % r.stderr.decode(errors="replace").strip())


def encrypt_file(src, dst, key):
    if not shutil.which("openssl"):
        raise RuntimeError("the 'openssl' command is required for encrypted backups (install the openssl package)")
    enc, mac = _subkeys(key)
    blob = dst + ".blob"
    _openssl(["-salt", "-in", src, "-out", blob], enc)
    h = hmac.new(mac, MAGIC, hashlib.sha256)
    with open(dst, "wb") as out, open(blob, "rb") as f:
        out.write(MAGIC)
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            out.write(chunk)
        out.write(h.digest())
    os.remove(blob)


def decrypt_file(src, dst, key):
    enc, mac = _subkeys(key)
    size = os.path.getsize(src)
    if size < len(MAGIC) + 16 + 32:
        raise ValueError("file too small to be an NGBK1 archive")
    h = hmac.new(mac, digestmod=hashlib.sha256)
    blob = dst + ".blob"
    with open(src, "rb") as f, open(blob, "wb") as out:
        if f.read(len(MAGIC)) != MAGIC:
            raise ValueError("not an NGBK1 archive")
        h.update(MAGIC)
        remaining = size - len(MAGIC) - 32
        while remaining:
            chunk = f.read(min(1 << 20, remaining))
            h.update(chunk)
            out.write(chunk)
            remaining -= len(chunk)
        tag = f.read(32)
    if not hmac.compare_digest(h.digest(), tag):
        os.remove(blob)
        raise ValueError("integrity check FAILED: wrong key, or the archive was damaged/tampered with")
    try:
        _openssl(["-d", "-in", blob, "-out", dst], enc)
    finally:
        os.remove(blob)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# S3 (AWS Signature Version 4, path-style or virtual-hosted for amazonaws.com)
# ---------------------------------------------------------------------------
def _sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sigv4_headers(method, url, region, access_key, secret_key, payload_hash, amz_date=None, extra_headers=None):
    """Returns the headers (incl. Authorization) for an S3 request. amz_date like 20130524T000000Z."""
    u = urllib.parse.urlsplit(url)
    amz_date = amz_date or datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    date = amz_date[:8]
    headers = {"host": u.netloc, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    for k, v in (extra_headers or {}).items():
        headers[k.lower()] = str(v).strip()
    q = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
    cq = "&".join("%s=%s" % (urllib.parse.quote(k, safe="-_.~"), urllib.parse.quote(v, safe="-_.~")) for k, v in sorted(q))
    signed = ";".join(sorted(headers))
    canon = "\n".join([method, u.path or "/", cq, "".join("%s:%s\n" % (k, headers[k]) for k in sorted(headers)), signed, payload_hash])
    scope = "%s/%s/s3/aws4_request" % (date, region)
    sts = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = _sign(_sign(_sign(_sign(("AWS4" + secret_key).encode(), date), region), "s3"), "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = "AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s" % (access_key, scope, signed, sig)
    return headers


class S3:
    EMPTY = hashlib.sha256(b"").hexdigest()

    def __init__(self, d):
        self.d = d
        ep = urllib.parse.urlsplit(d["endpoint"].rstrip("/"))
        self.scheme, self.host = ep.scheme, ep.netloc
        self.virtual = self.host.endswith("amazonaws.com")
        self.prefix = d.get("prefix", "").strip("/")

    def url(self, key="", query=""):
        k = urllib.parse.quote(key, safe="/-_.~")
        if self.virtual:
            base = "%s://%s.%s/%s" % (self.scheme, self.d["bucket"], self.host, k)
        else:
            base = "%s://%s/%s/%s" % (self.scheme, self.host, self.d["bucket"], k)
        return base + ("?" + query if query else "")

    def key(self, *parts):
        return "/".join(p.strip("/") for p in ([self.prefix] if self.prefix else []) + list(parts) if p)

    def _req(self, method, url, payload_hash=None, data=None, length=None, stream_to=None):
        h = sigv4_headers(method, url, self.d.get("region") or "us-east-1", self.d["access_key"], self.d["secret_key"],
                          payload_hash or self.EMPTY)
        h.pop("host")
        if length is not None:
            h["Content-Length"] = str(length)
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                if stream_to:
                    with open(stream_to, "wb") as f:
                        shutil.copyfileobj(r, f, 1 << 20)
                    return b""
                return r.read()
        except urllib.error.HTTPError as e:
            body = e.read()[:400].decode("utf-8", "replace")
            raise RuntimeError("S3 %s %s -> HTTP %d %s" % (method, url.split("?")[0], e.code, re.sub(r"\s+", " ", body)))

    def put(self, key, path):
        size = os.path.getsize(path)
        if size > 5 * 1024 ** 3:
            raise RuntimeError("archive is larger than 5 GB (single-upload limit); split the job into smaller jobs")
        with open(path, "rb") as f:
            self._req("PUT", self.url(key), sha256_file(path), f, size)

    def get(self, key, dest):
        self._req("GET", self.url(key), stream_to=dest)

    def delete(self, key):
        self._req("DELETE", self.url(key))

    def list(self, prefix):
        out, token = [], None
        while True:
            q = "list-type=2&prefix=" + urllib.parse.quote(prefix, safe="-_.~")
            if token:
                q += "&continuation-token=" + urllib.parse.quote(token, safe="-_.~")
            root = ET.fromstring(self._req("GET", self.url("", q)))
            ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
            for c in root.findall(ns + "Contents"):
                out.append({"key": c.find(ns + "Key").text, "size": int(c.find(ns + "Size").text)})
            tr = root.find(ns + "IsTruncated")
            if tr is not None and tr.text == "true":
                token = root.find(ns + "NextContinuationToken").text
            else:
                return out


# ---------------------------------------------------------------------------
# Destinations (local folder / S3) share one interface
# ---------------------------------------------------------------------------
class Dest:
    def __init__(self, d, host, slug):
        self.d, self.host, self.slug = d, host, slug
        self.label = d.get("path") if d["type"] == "local" else "s3://%s/%s" % (d["bucket"], d.get("prefix", ""))
        if d["type"] == "local":
            self.dir = os.path.join(d["path"], host, slug)
        else:
            self.s3 = S3(d)
            self.prefix = self.s3.key(host, slug) + "/"

    def upload(self, path, name):
        if self.d["type"] == "local":
            os.makedirs(self.dir, exist_ok=True)
            tmp = os.path.join(self.dir, name + ".part")
            shutil.copyfile(path, tmp)
            os.replace(tmp, os.path.join(self.dir, name))
        else:
            self.s3.put(self.prefix + name, path)

    def download(self, name, dest):
        if self.d["type"] == "local":
            shutil.copyfile(os.path.join(self.dir, name), dest)
        else:
            self.s3.get(self.prefix + name, dest)

    def archives(self):
        """Newest first: [name]"""
        if self.d["type"] == "local":
            names = os.listdir(self.dir) if os.path.isdir(self.dir) else []
        else:
            names = [o["key"][len(self.prefix):] for o in self.s3.list(self.prefix)]
        return sorted([n for n in names if n.endswith(".ngbk")], reverse=True)

    def remove(self, name):
        for n in (name, name[:-5] + ".json"):
            try:
                if self.d["type"] == "local":
                    os.remove(os.path.join(self.dir, n))
                else:
                    self.s3.delete(self.prefix + n)
            except (OSError, RuntimeError) as e:
                log("could not delete %s: %s" % (n, e))


def archive_time(name):
    m = re.search(r"_(\d{8}-\d{6})\.ngbk$", name)
    return time.mktime(time.strptime(m.group(1), "%Y%m%d-%H%M%S")) if m else 0


def apply_retention(dest, keep_last, keep_days):
    names = dest.archives()
    now = time.time()
    removed = []
    for i, n in enumerate(names):
        young = keep_days and now - archive_time(n) < keep_days * 86400
        if i < max(1, keep_last) or young:
            continue
        dest.remove(n)
        removed.append(n)
    return removed


# ---------------------------------------------------------------------------
# Collecting sources
# ---------------------------------------------------------------------------
WEB_PATHS = ["/var/www", "/srv/www", "/usr/share/nginx/html", "/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/caddy",
             "/etc/letsencrypt", "/etc/php"]


def text_snapshot(cmd):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        return r.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return "(%s: %s)\n" % (cmd[0], e)


def dump_database(db, outdir):
    eng = db.get("engine")
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", db.get("name") or eng)
    dbs = [d.strip() for d in (db.get("database") or "").split(",") if d.strip()]
    env = dict(os.environ)
    if eng == "mysql":
        tool = shutil.which("mysqldump") or shutil.which("mariadb-dump")
        if not tool:
            raise RuntimeError("mysqldump not found")
        env["MYSQL_PWD"] = db.get("password") or ""
        cmd = [tool, "--single-transaction", "--quick", "--routines", "--events", "--triggers",
               "-h", db.get("host") or "localhost", "-P", str(db.get("port") or 3306), "-u", db.get("username") or "root"]
        cmd += ["--databases"] + dbs if dbs else ["--all-databases"]
        out = os.path.join(outdir, "%s.mysql.sql" % name)
    elif eng == "postgres":
        env["PGPASSWORD"] = db.get("password") or ""
        conn = ["-h", db.get("host") or "localhost", "-p", str(db.get("port") or 5432), "-U", db.get("username") or "postgres"]
        if dbs:
            outs = []
            for d in dbs:
                out = os.path.join(outdir, "%s.%s.postgres.sql" % (name, d))
                _run_dump([shutil.which("pg_dump") or "pg_dump"] + conn + ["--clean", "--if-exists", d], out, env)
                outs.append(out)
            return outs
        cmd = [shutil.which("pg_dumpall") or "pg_dumpall"] + conn + ["--clean", "--if-exists"]
        out = os.path.join(outdir, "%s.postgres.sql" % name)
    elif eng == "sqlite":
        path = db.get("host") or db.get("database")
        if not path or not os.path.isfile(path):
            raise RuntimeError("SQLite file not found: %s (put the file path in the Host field)" % path)
        out = os.path.join(outdir, "%s.sqlite" % name)
        src = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
        dst = sqlite3.connect(out)
        src.backup(dst)                       # consistent online copy
        dst.close()
        src.close()
        return [out]
    else:
        raise RuntimeError("database engine '%s' is not supported on Linux" % eng)
    _run_dump(cmd, out, env)
    return [out]


def _run_dump(cmd, out, env):
    with open(out, "wb") as f:
        r = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, env=env, timeout=6 * 3600)
    if r.returncode:
        raise RuntimeError("%s failed: %s" % (os.path.basename(cmd[0]), r.stderr.decode("utf-8", "replace")[-500:]))
    if os.path.getsize(out) == 0:
        raise RuntimeError("%s produced an empty dump" % os.path.basename(cmd[0]))


def build_archive(job, staging, tar_path):
    src = job["sources"]
    excludes = src.get("excludes") or []
    contents, skipped = [], []
    gen = os.path.join(staging, "generated")
    os.makedirs(gen, exist_ok=True)
    items = []          # (path on disk, name in archive, label)

    if src.get("website"):
        found = [p for p in WEB_PATHS if os.path.exists(p)]
        if not found:
            log("website preset: no web folders found (%s)" % ", ".join(WEB_PATHS))
        items += [(p, "website" + p, "website") for p in found]
    if src.get("config"):
        items.append(("/etc", "config/etc", "config"))
        for spool in ("/var/spool/cron", "/var/spool/cron/crontabs"):
            if os.path.isdir(spool):
                items.append((spool, "config" + spool, "config"))
        snaps = {"packages.txt": ["dpkg", "-l"] if shutil.which("dpkg") else ["rpm", "-qa"],
                 "enabled-services.txt": ["systemctl", "list-unit-files", "--state=enabled", "--no-pager"],
                 "network.txt": ["ip", "addr"], "routes.txt": ["ip", "route"],
                 "firewall-iptables.txt": ["iptables-save"], "firewall-nft.txt": ["nft", "list", "ruleset"],
                 "firewall-ufw.txt": ["ufw", "status", "verbose"], "users.txt": ["getent", "passwd"],
                 "groups.txt": ["getent", "group"], "disks.txt": ["lsblk", "-f"], "mounts.txt": ["findmnt"]}
        if shutil.which("docker"):
            snaps["docker.txt"] = ["docker", "ps", "-a"]
        for fn, cmd in snaps.items():
            if shutil.which(cmd[0]):
                with open(os.path.join(gen, fn), "w") as f:
                    f.write(text_snapshot(cmd))
        items.append((gen, "config/generated", "config"))
    for p in src.get("folders") or []:
        if os.path.exists(p):
            items.append((p, "folders" + p, "folder"))
        else:
            raise RuntimeError("folder not found: %s" % p)
    dbdir = os.path.join(staging, "databases")
    os.makedirs(dbdir, exist_ok=True)
    for db in src.get("databases") or []:
        log("dumping database %s (%s)" % (db.get("name"), db.get("engine")))
        dump_database(db, dbdir)
    if os.listdir(dbdir):
        items.append((dbdir, "databases", "database"))

    stats = {}
    with tarfile.open(tar_path, "w:gz", compresslevel=6) as tar:
        for path, arcname, label in items:
            def flt(ti, _p=path, _a=arcname):
                full = os.path.join(_p, ti.name[len(_a):].lstrip("/")) if ti.name.startswith(_a) else ti.name
                if any(fnmatch.fnmatch(full, e) or fnmatch.fnmatch(os.path.basename(full), e) for e in excludes):
                    return None
                if ti.isfile():
                    s = stats.setdefault(label, [0, 0])
                    s[0] += 1
                    s[1] += ti.size
                return ti
            try:
                tar.add(path, arcname=arcname.lstrip("/"), filter=flt)
            except (PermissionError, OSError) as e:
                skipped.append("%s: %s" % (path, e))
                log("skipped unreadable %s: %s" % (path, e))
    contents = [{"type": k, "files": v[0], "bytes": v[1]} for k, v in stats.items()]
    return contents, skipped


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
def do_backup(job, host, state_dir):
    t0 = time.time()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = "%s_%s_%s.ngbk" % (re.sub(r"[^A-Za-z0-9.-]", "-", host), job["slug"], stamp)
    work = tempfile.mkdtemp(prefix="ngbk-", dir=os.path.join(state_dir, "staging"))
    try:
        tar_path = os.path.join(work, "archive.tar.gz")
        contents, skipped = build_archive(job, work, tar_path)
        enc_path = os.path.join(work, name)
        encrypt_file(tar_path, enc_path, base64.b64decode(job["key"]))
        os.remove(tar_path)
        digest, size = sha256_file(enc_path), os.path.getsize(enc_path)
        manifest = {"format": "netguard-backup/1", "host": host, "job_id": job["id"], "job": job["name"], "archive": name,
                    "created": datetime.datetime.utcnow().isoformat() + "Z", "sha256": digest, "size": size, "encrypted": True,
                    "archive_type": "tar.gz", "contents": contents, "skipped": skipped, "tool": "netguard-linux/" + TOOL_VERSION}
        man_path = os.path.join(work, name[:-5] + ".json")
        with open(man_path, "w") as f:
            json.dump(manifest, f, indent=2)
        dest_status, ok_any = [], False
        for d in job["destinations"]:
            dest = Dest(d, host, job["slug"])
            try:
                dest.upload(enc_path, name)
                dest.upload(man_path, name[:-5] + ".json")
                removed = apply_retention(dest, job["retention"]["keep_last"], job["retention"]["keep_days"])
                dest_status.append({"dest": dest.label, "ok": True, "removed_old": removed})
                ok_any = True
                log("stored on %s (removed %d old)" % (dest.label, len(removed)))
            except Exception as e:
                dest_status.append({"dest": dest.label, "ok": False, "error": str(e)})
                log("FAILED to store on %s: %s" % (dest.label, e))
        all_ok = all(x["ok"] for x in dest_status)
        return {"status": "ok" if all_ok else "failed", "archive": name, "sha256": digest, "size": size,
                "files": sum(c["files"] for c in contents),
                "details": {"destinations": dest_status, "contents": contents, "skipped": skipped,
                            "duration_s": round(time.time() - t0, 1), "partial": ok_any and not all_ok}}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _fetch(job, host, work, archive=None):
    """Download + verify + decrypt the requested (or latest) archive from the first destination that has it."""
    errors = []
    for d in job["destinations"]:
        dest = Dest(d, host, job["slug"])
        try:
            names = dest.archives()
            name = archive or (names[0] if names else None)
            if not name or name not in names:
                errors.append("%s: %s" % (dest.label, "no archives" if not names else "%s not found" % name))
                continue
            enc = os.path.join(work, name)
            dest.download(name, enc)
            man = {}
            try:
                dest.download(name[:-5] + ".json", os.path.join(work, "m.json"))
                man = json.load(open(os.path.join(work, "m.json")))
            except Exception:
                pass
            return dest, name, enc, man
        except Exception as e:
            errors.append("%s: %s" % (dest.label, e))
    raise RuntimeError("could not fetch a backup: " + "; ".join(errors))


def _safe_members(tar, target):
    base = os.path.realpath(target)
    for m in tar.getmembers():
        p = os.path.realpath(os.path.join(target, m.name))
        if not (p == base or p.startswith(base + os.sep)) or m.issym() and os.path.isabs(m.linkname) or m.isdev():
            continue
        yield m


def do_test_or_restore(job, host, state_dir, mode, archive=None, target=None):
    t0 = time.time()
    work = tempfile.mkdtemp(prefix="ngrs-", dir=os.path.join(state_dir, "staging"))
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})
        log("%s %s %s" % ("PASS" if ok else "FAIL", name, detail))
        return ok
    try:
        dest, name, enc, man = _fetch(job, host, work, archive)
        age_h = (time.time() - archive_time(name)) / 3600
        check("downloaded from %s" % dest.label, True, name)
        digest = sha256_file(enc)
        check("checksum matches manifest", not man or man.get("sha256") == digest, digest[:16])
        tar_path = os.path.join(work, "a.tar.gz")
        try:
            decrypt_file(enc, tar_path, base64.b64decode(job["key"]))
            check("decrypts with the job key (integrity verified)", True)
        except Exception as e:
            check("decrypts with the job key (integrity verified)", False, str(e))
            raise
        os.remove(enc)
        with tarfile.open(tar_path, "r:gz") as tar:
            members = tar.getmembers()
            files = [m for m in members if m.isfile()]
            check("archive readable", True, "%d files" % len(files))
            if man.get("contents"):
                expected = sum(c["files"] for c in man["contents"])
                check("file count matches manifest", len(files) >= expected * 0.99, "%d of %d" % (len(files), expected))
            for m in files:
                if m.name.startswith("databases/"):
                    head = tar.extractfile(m).read(200)
                    good = m.size > 0 and (b"MySQL dump" in head or b"MariaDB dump" in head or b"PostgreSQL" in head
                                           or head.startswith(b"SQLite format 3") or b"--" in head[:5])
                    check("database dump looks valid: %s" % os.path.basename(m.name), good, "%d bytes" % m.size)
            restored_to = None
            if mode == "restore":
                target = target or os.path.join(state_dir, "restores", "%s-%s" % (job["slug"], time.strftime("%Y%m%d-%H%M%S")))
                if os.path.exists(target) and os.listdir(target):
                    raise RuntimeError("restore target %s is not empty; choose a new folder" % target)
                os.makedirs(target, exist_ok=True)
                tar.extractall(target, members=list(_safe_members(tar, target)))
                restored_to = target
                check("extracted", True, target)
            else:
                sample = os.path.join(work, "sample")
                tar.extractall(sample, members=list(_safe_members(tar, sample))[:200])
                check("sample of files extracts", True)
        ok = all(c["ok"] for c in checks)
        return {"status": "ok" if ok else "failed", "archive": name, "sha256": digest, "files": len(files),
                "details": {"checks": checks, "archive_age_h": round(age_h, 1), "restored_to": restored_to,
                            "duration_s": round(time.time() - t0, 1)}}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--job", required=True)
    ap.add_argument("--mode", choices=["backup", "test", "restore"], default="backup")
    ap.add_argument("--archive")
    ap.add_argument("--target")
    ap.add_argument("--result", required=True)
    ap.add_argument("--run-ref", default=str(uuid.uuid4()))
    ap.add_argument("--host", default=socket.gethostname())
    ap.add_argument("--state-dir", default="/var/lib/netguard")
    a = ap.parse_args()
    os.umask(0o077)
    os.makedirs(os.path.join(a.state_dir, "staging"), exist_ok=True)
    with open(a.job) as f:
        job = json.load(f)
    res = {"run_ref": a.run_ref, "job_id": job["id"], "kind": a.mode, "started": time.time()}
    try:
        if a.mode == "backup":
            res.update(do_backup(job, a.host, a.state_dir))
        else:
            res.update(do_test_or_restore(job, a.host, a.state_dir, a.mode, a.archive, a.target))
    except Exception as e:
        log("ERROR: %s" % e)
        res.update({"status": "failed", "details": dict(res.get("details") or {}, error=str(e))})
    res["finished"] = time.time()
    res["log"] = "\n".join(LOG)[-20000:]
    tmp = a.result + ".tmp"
    with open(tmp, "w") as f:
        json.dump(res, f)
    os.replace(tmp, a.result)


if __name__ == "__main__":
    main()
