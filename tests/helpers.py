"""Shared test helpers: start a throwaway dashboard, talk to it as a browser/agent, sign in with 2-factor."""
import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASH = os.path.join(REPO, "dashboard")
sys.path.insert(0, DASH)

from auth import totp_at  # noqa: E402

AGENT_TOKEN = "test-agent-token"
BOOT_PW = "Initial-Setup-Pw1"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Dashboard:
    """A dashboard server in a temp dir. Use as a context manager."""

    def __init__(self, extra_cfg=None):
        self.dir = tempfile.mkdtemp(prefix="netguard-test-")
        self.port = free_port()
        self.base = "http://127.0.0.1:%d" % self.port
        self.cfg_path = os.path.join(self.dir, "config.json")
        cfg = {"listen_host": "127.0.0.1", "listen_port": self.port, "admin_user": "admin", "admin_password": BOOT_PW,
               "agent_token": AGENT_TOKEN, "db_path": "t.db", "offline_after_seconds": 300}
        cfg.update(extra_cfg or {})
        with open(self.cfg_path, "w") as f:
            json.dump(cfg, f)
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen([sys.executable, os.path.join(DASH, "server.py"), "--config", self.cfg_path],
                                     stdout=subprocess.DEVNULL, stderr=open(os.path.join(self.dir, "server.log"), "w"))
        for _ in range(80):
            try:
                urllib.request.urlopen(self.base + "/healthz", timeout=1)
                return self
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("dashboard did not start: " + open(os.path.join(self.dir, "server.log")).read())

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self.start()

    def __exit__(self, *a):
        self.stop()

    def cli(self, *args):
        return subprocess.run([sys.executable, os.path.join(DASH, "server.py"), "--config", self.cfg_path] + list(args),
                              capture_output=True, text=True)

    def agent(self, path, body, token=None):
        req = urllib.request.Request(self.base + path, method="POST", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", "X-Agent-Token": token or AGENT_TOKEN})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def report(self, host, alerts=(), token=None, **extra):
        body = {"host": host, "os": "test", "alerts": list(alerts)}
        body.update(extra)
        return self.agent("/api/agent/report", body, token)


class Client:
    """A browser: keeps cookies, sends the CSRF header."""

    def __init__(self, dash):
        self.d = dash
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, path, body=None, csrf=True):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.d.base + path, data=data, method="POST" if body is not None else "GET")
        req.add_header("Content-Type", "application/json")
        if csrf:
            req.add_header("X-NetGuard", "1")
        try:
            with self.op.open(req, timeout=15) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raw = e.read() or b"{}"
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {"raw": raw.decode("utf-8", "replace")}


def code(secret, offset=0):
    return totp_at(secret.replace(" ", ""), int(time.time() // 30) + offset)


def wait_next_step():
    """2-factor codes can't be reused: wait for the next 30 s window when a test signs in twice."""
    time.sleep(30 - (time.time() % 30) + 0.5)


def enroll(client, step):
    """Finish 2-factor enrolment for a sign-in step dict. Returns the TOTP secret."""
    st, en = client.call("/api/auth/enroll/start", {"ticket": step["ticket"]})
    assert st == 200, en
    st, fin = client.call("/api/auth/enroll/finish", {"ticket": step["ticket"], "code": code(en["secret"])})
    assert st == 200, fin
    return en["secret"]


def owner(dash, password="Owner-Strong-Password-42"):
    """Signed-in owner client (first sign-in: setup password -> own password -> 2FA)."""
    c = Client(dash)
    st, r = c.call("/api/auth/login", {"username": "admin", "password": BOOT_PW})
    assert st == 200 and r["step"] == "password", r
    st, r = c.call("/api/auth/password", {"ticket": r["ticket"], "new_password": password})
    assert st == 200, r
    c.secret = enroll(c, r)
    return c


def invite(owner_client, role="admin", hosts="*", username="bob", password="Bob-Strong-Password-7"):
    st, inv = owner_client.call("/api/users/invite", {"role": role, "hosts": hosts})
    assert st == 200, inv
    tok = inv["link_path"].split("=", 1)[1]
    c = Client(owner_client.d)
    st, r = c.call("/api/invite/accept", {"token": tok, "username": username, "password": password})
    assert st == 200, r
    c.secret = enroll(c, r)
    return c
