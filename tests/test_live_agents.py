"""Live test: the real Windows agent (this PC) and Linux agent (WSL) join a throwaway dashboard,
switch to their own key, and execute a signed command. Skipped where the platform is missing."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from helpers import REPO, Dashboard, owner

HAS_WSL = sys.platform == "win32" and shutil.which("wsl.exe") is not None


def wsl_gateway_ip():
    out = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "ip", "route", "show", "default"], capture_output=True, text=True).stdout
    return out.split()[2] if out.split() else None


class LiveAgents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Dashboard({"listen_host": "0.0.0.0"}).start()
        cls.own = owner(cls.d)
        cls.tmp = tempfile.mkdtemp(prefix="ng-live-")

    @classmethod
    def tearDownClass(cls):
        cls.d.stop()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def host(self, name):
        return [h for h in self.own.call("/api/settings")[1]["hosts"] if h["name"] == name]

    def command_status(self, host):
        return [c for c in self.own.call("/api/commands")[1] if c["host"] == host]

    @unittest.skipUnless(sys.platform == "win32", "Windows agent")
    def test_windows_agent(self):
        cfgp = os.path.join(self.tmp, "win.json")
        json.dump({"server_url": self.d.base, "agent_token": "test-agent-token", "host_name": "LIVEWIN",
                   "state_dir": os.path.join(self.tmp, "winstate"), "harden_script": ""}, open(cfgp, "w"))
        run = lambda: subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                                      os.path.join(REPO, "agents", "windows", "NetGuard-Agent.ps1"), "-ConfigPath", cfgp],
                                     capture_output=True, text=True, timeout=240)
        run()
        self.assertTrue(self.host("LIVEWIN"), "joined")
        run()
        self.assertTrue(self.host("LIVEWIN")[0]["has_key"], "switched to its own key")
        state = json.load(open(os.path.join(self.tmp, "winstate", "agent-state.json"), encoding="utf-8-sig"))
        self.assertTrue(state.get("command_key"), "dashboard key pinned")
        self.own.call("/api/hosts/LIVEWIN/action", {"action": "run_hardening_audit", "params": {}})
        run()
        c = self.command_status("LIVEWIN")[0]
        self.assertEqual(c["status"], "done", c)

    @unittest.skipUnless(HAS_WSL, "WSL Linux agent")
    def test_linux_agent_in_wsl(self):
        gw = wsl_gateway_ip()
        sd = "/tmp/ng-live-%d" % os.getpid()
        cfg = {"server_url": "http://%s:%d" % (gw, self.d.port), "agent_token": "test-agent-token", "host_name": "LIVELNX",
               "state_dir": sd, "harden_script": ""}
        agentp = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "wslpath", "-a", os.path.join(REPO, "agents", "linux", "netguard_agent.py")],
                                capture_output=True, text=True).stdout.strip()
        script = ("mkdir -p {sd} && printf '%s' '{cfg}' > {sd}/a.json && for i in 1 2; do python3 '{ag}' --config {sd}/a.json --once; done; "
                  "echo DONE").format(sd=sd, cfg=json.dumps(cfg), ag=agentp)
        r = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", "-c", script], capture_output=True, text=True, timeout=240)
        self.assertIn("DONE", r.stdout, r.stderr)
        self.assertTrue(self.host("LIVELNX") and self.host("LIVELNX")[0]["has_key"], r.stderr[-800:])
        self.own.call("/api/hosts/LIVELNX/action", {"action": "accept_listener", "params": {"port": 4321, "protocol": "tcp"}})
        r = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "bash", "-c",
                            "python3 '%s' --config %s/a.json --once; rm -rf %s" % (agentp, sd, sd)], capture_output=True, text=True, timeout=240)
        c = self.command_status("LIVELNX")[0]
        self.assertEqual(c["status"], "done", (c, r.stderr[-800:]))


if __name__ == "__main__":
    unittest.main()
