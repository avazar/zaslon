import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

def wait(label, predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.08)
    raise RuntimeError(label)

def read_file(path):
    return path.read_text() if path.exists() else ""

def trigger(profile, target):
    journal = profile / "process-recovery.json"
    gate = profile / "unavailable"
    def phase():
        return json.loads(read_file(journal) or "{}").get("entries", {}).get(target, {}).get("phase")
    gate.touch()
    wait("failed probe did not suspend Codex", lambda: phase() == "frozen")
    print("paused", flush=True)
    if input() != "resume":
        raise RuntimeError("unexpected command")
    gate.unlink()
    wait("allowed probe did not release Codex", lambda: phase() is None)
    print("resumed", flush=True)

def run(zaslon, codex):
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as tmp:
        profile = Path(tmp)
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if (profile / "unavailable").exists():
                    self.send_error(503)
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"203.0.113.10")
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        config = dict(apps=["codex"], allow={"ips": ["203.0.113.10"]},
                      check_interval="3s", ip_services=[f"http://127.0.0.1:{server.server_port}"],
                      min_agree=1, check_ipv6=False, dns_check="off", language="en",
                      notifications=False, domain_checks_enabled={"codex": False})
        (profile / "config.yaml").write_text(json.dumps(config))
        env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "ZASLON_DIR": tmp, "LANG": "C.UTF-8"}
        with (profile / "headless.txt").open("w") as log:
            guard = subprocess.Popen([zaslon, "headless"], env=env, stdout=log, stderr=log)
            try:
                wait("initial allowed IP missing", lambda: "203.0.113.10" in read_file(profile / "state.json"))
                check = Path(__file__).with_name("check.py")
                subprocess.run([sys.executable, "-u", str(check), __file__, codex],
                               env={**os.environ, "TERMINAL_PROFILE": tmp}, check=True, timeout=80)
            finally:
                guard.terminate()
                guard.wait(timeout=10)
                print("Release guard log:", read_file(profile / "zaslon.log")[-4500:], flush=True)
                print("Headless output:", read_file(profile / "headless.txt")[-1600:], flush=True)
                server.shutdown()

if __name__ == "__main__":
    if "TERMINAL_PROFILE" in os.environ:
        trigger(Path(os.environ["TERMINAL_PROFILE"]), sys.argv[2])
    else:
        run(*sys.argv[1:])
