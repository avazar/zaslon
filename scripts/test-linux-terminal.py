"""Ubuntu acceptance test. Run only in a disposable runner with no other CLIs.

Arguments: zaslon-binary, cgroup|bash, codex-binary, claude-binary.
Uses two real offline onboarding screens plus a custom CLI with a child and a
grandchild. Each scenario controls its own local IP responder and guard profile.
"""
import fcntl
import json
import os
import pty
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def wait(label, predicate, timeout=35):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.06)
    raise AssertionError(label)


class Terminal:
    def __init__(self, program, args, directory, init):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(directory)
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
            os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-i"], {
                "HOME": str(directory), "PATH": f"{program.parent}:/usr/bin:/bin",
                "LANG": "C.UTF-8", "TERM": "xterm-256color", "PS1": "tty-test> ",
                "DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            })
        self.screen = bytearray()
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        wait("Bash prompt", lambda: b"tty-test> " in self.screen)
        if init:
            self.send(("source " + shlex.quote(str(init)) + "\n").encode())
        invocation = [program.name if init else str(program), *map(str, args)]
        self.send((shlex.join(invocation) + "\n").encode())
        self.group = wait("foreground job", lambda: (g if (g := os.tcgetpgrp(self.fd)) > 0 and g != self.pid else 0))

    def read(self):
        try:
            while True:
                data = os.read(self.fd, 32768)
                if not data:
                    return
                self.screen.extend(data)
                if b"\x1b[6n" in data:
                    self.send(b"\x1b[1;1R")
        except OSError:
            pass

    def send(self, data):
        os.write(self.fd, data)

    def key(self, key, marker):
        assert os.tcgetpgrp(self.fd) == self.group
        offset = len(self.screen)
        self.send(key)
        try:
            wait(f"menu did not react to {key!r}", lambda: marker in self.screen[offset:], 5)
        except AssertionError:
            print("screen before/after key:", repr(bytes(self.screen[offset-800:])[-1500:]), flush=True)
            raise

    def close(self):
        os.close(self.fd)
        for proc in Path("/proc").glob("[0-9]*"):
            pid = int(proc.name)
            try:
                if os.getsid(pid) == self.pid:
                    os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        os.waitpid(self.pid, 0)


def read_json(path):
    return json.loads(path.read_text()) if path.exists() else {}


def main(root, guard_binary, mode, codex, claude):
    assert mode in ("cgroup", "bash")
    unavailable = threading.Event()
    failures = []

    class IP(BaseHTTPRequestHandler):
        def do_GET(self):
            if unavailable.is_set():
                failures.append(time.monotonic())
                self.send_error(503)
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"203.0.113.10")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), IP)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    custom = root / "term-fixture"
    shutil.copy2(sys.executable, custom)
    fixture = root / "fixture.py"
    fixture.write_text("""import os, sys, time
from pathlib import Path
level = 0
while level < 2 and os.fork() == 0:
    level += 1
Path(f'pid-{level}').write_text(str(os.getpid()))
if level == 0:
    print('fixture ready', flush=True)
    for line in sys.stdin:
        print('accepted ' + line.strip(), flush=True)
else:
    while True:
        Path(f'tick-{level}').write_text(str(time.monotonic_ns()))
        time.sleep(.05)
""")
    profile = root / "guard"
    profile.mkdir()
    cfg = dict(apps=["codex", "claude"], custom_apps=[{"name": "fixture", "match": [str(custom)]}],
               allow={"ips": ["203.0.113.10"]}, check_interval="3s", min_agree=1,
               ip_services=[f"http://127.0.0.1:{server.server_port}"], check_ipv6=False,
               dns_check="off", language="en", notifications=False)
    (profile / "config.yaml").write_text(json.dumps(cfg))
    init = None
    if mode == "bash":
        init = root / "integration.bash"
        init.write_bytes(subprocess.check_output([guard_binary, "bash-init", "codex", "claude", custom.name]))
    env = {"HOME": str(root), "PATH": "/usr/bin:/bin", "ZASLON_DIR": str(profile), "LANG": "C.UTF-8"}
    guard = subprocess.Popen([guard_binary, "headless"], env=env, stdout=subprocess.DEVNULL)
    terminals = []
    def entries():
        return read_json(profile / "process-recovery.json").get("entries", {})
    try:
        wait("guard must confirm initial IP", lambda: "203.0.113.10" in str(read_json(profile / "state.json")))
        for program, args in [(codex, []), (claude, []), (custom, ["-u", fixture])]:
            directory = root / (program.name + "-home")
            directory.mkdir()
            terminals.append(Terminal(program, args, directory, init))
        ct, at, ft = terminals
        wait("Codex did not draw", lambda: b"Sign in with ChatGPT" in ct.screen)
        wait("Claude Code did not draw", lambda: b"theme" in at.screen.lower() or b"dark mode" in at.screen.lower())
        work = root / (custom.name + "-home")
        wait("fixture descendants", lambda: len(list(work.glob("pid-*"))) == 3)
        fixture_pids = {p.read_text() for p in work.glob("pid-*")}
        def keyboard():
            ct.key(b"\x1b[B", b"> 2. ")
            ct.key(b"\x1b[A", b"> 1. ")
            # Claude redraws the theme preview when the selected theme changes.
            at.key(b"\x1b[B", b"\x1b[")
            at.key(b"\x1b[A", b"\x1b[")
            ft.key(b"ping\n", b"accepted ping")
        keyboard()
        for cycle in range(2):
            start = len(failures)
            unavailable.set()
            def census():
                processes = {}
                for stat in Path("/proc").glob("[0-9]*/stat"):
                    try:
                        fields = stat.read_text().rsplit(") ", 1)[1].split()
                        processes[stat.parent.name] = (fields[1], int(fields[2]), fields[0])
                    except FileNotFoundError:
                        continue
                jobs = {t.group for t in terminals}
                expected = {pid for pid, (_, pg, state) in processes.items()
                            if pg in jobs and state != "Z" and not (mode == "bash" and int(pid) in jobs)}
                while True:
                    children = {pid for pid, (ppid, _, state) in processes.items() if ppid in expected and state != "Z"}
                    if children <= expected:
                        return expected
                    expected |= children
            def held():
                journal = entries()
                expected = census()
                return (fixture_pids <= expected <= journal.keys() and
                        {"codex", "claude", "fixture"} <= {e["process"]["AppID"] for e in journal.values()} and
                        all(e["phase"] == "frozen" for e in journal.values()))
            wait("all apps and descendants must be held", held)
            ticks = [p.read_bytes() for p in sorted(work.glob("tick-*"))]
            assert len(ticks) == 2
            def verify():
                held_entries = entries()
                assert fixture_pids <= census() <= held_entries.keys()
                for pid, record in held_entries.items():
                    assert record["phase"] == "frozen"
                    if mode == "cgroup":
                        group = Path(record["freezer"]["path"])
                        assert (group / "cgroup.procs").read_text().split() == [pid]
                        assert "frozen 1" in (group / "cgroup.events").read_text().splitlines()
                    else:
                        assert not record.get("freezer")
                        assert Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1][0] == "T"
                assert ticks == [p.read_bytes() for p in sorted(work.glob("tick-*"))]
                assert all(os.tcgetpgrp(t.fd) == t.group for t in terminals)
                return len(failures) >= start + 3
            wait("three consecutive failed probes", verify)
            count = len(entries())
            unavailable.clear()
            wait("all holds released", lambda: not entries())
            keyboard()
            wait("heartbeats resumed", lambda: all(p.read_bytes() != old for p, old in zip(sorted(work.glob("tick-*")), ticks)))
            print(f"{mode} cycle {cycle+1}: {count} stopped processes, 3 failed probes, both menus and fixture input recovered", flush=True)
    finally:
        unavailable.clear()
        guard.terminate()
        guard.wait(timeout=15)
        for t in terminals:
            t.close()
        server.shutdown()
        log = profile / "zaslon.log"
        if log.exists():
            print(log.read_text()[-3200:], flush=True)
        for t in terminals:
            if sys.exc_info()[0]:
                print("terminal tail:", repr(bytes(t.screen[-800:])), flush=True)


if __name__ == "__main__":
    if os.getenv("GITHUB_ACTIONS") != "true":
        raise SystemExit("This test targets real CLI process names. Use an isolated GitHub runner.")
    with tempfile.TemporaryDirectory(dir=os.environ["RUNNER_TEMP"]) as tmp:
        main(Path(tmp), Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).absolute(), Path(sys.argv[4]).absolute())
