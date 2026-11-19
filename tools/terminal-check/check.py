import fcntl
import os
import pty
import re
import select
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path


controller, program = sys.argv[1:]
name = Path(program).name
profile = tempfile.TemporaryDirectory()
shell, master = pty.fork()
if shell == 0:
    os.chdir(profile.name)
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 110, 0, 0))
    os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-i"],
              {"HOME": profile.name, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
               "TERM": "xterm-256color", "PS1": "PTY-test> "})

transcript = bytearray()

def pump():
    if select.select([master], [], [], 0.05)[0]:
        data = os.read(master, 32768)
        transcript.extend(data)
        if b"\x1b[6n" in data:
            os.write(master, b"\x1b[1;1R")

def until(label, predicate, timeout=6):
    limit = time.monotonic() + timeout
    while time.monotonic() < limit:
        value = predicate()
        if value:
            return value
        pump()
    raise RuntimeError(label + ": " + repr(bytes(transcript[-1800:])))

def collect(duration):
    end = time.monotonic() + duration
    while time.monotonic() < end:
        pump()

def state(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]

try:
    until("shell prompt", lambda: b"PTY-test> " in transcript)
    os.write(master, (shlex.quote(program) + "\n").encode())
    target = until("foreground child", lambda: (g if (g := os.tcgetpgrp(master)) > 0 and g != shell else None))
    until("child executable", lambda: Path(f"/proc/{target}/comm").read_text().strip() == name)
    if name == "codex":
        until("Codex drew its screen", lambda: b"Codex" in transcript or b"OpenAI" in transcript, 15)
        collect(1)
        print("Codex startup screen:", repr(bytes(transcript[-1000:])))
        print("Mouse tracking enables:", re.findall(rb"\x1b\[\?(100[0236])h", transcript))
    with subprocess.Popen([controller, str(shell), str(target), name],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as control:
        assert control.stdout.readline().strip() == "paused"
        until("foreground returned to Bash", lambda: os.tcgetpgrp(master) == shell)
        print("Paused: Bash owns the foreground, job state =", state(target))
        control.stdin.write("resume\n")
        control.stdin.flush()
        assert control.stdout.readline().strip() == "resumed"
        assert control.wait(timeout=5) == 0
    collect(1.2)
    print("After Zaslon Resume: foreground =", os.tcgetpgrp(master),
          "bash =", shell, "job =", target, "job state =", state(target))
    if os.tcgetpgrp(master) == shell:
        offset = len(transcript)
        os.write(master, b"jobs -l\n")
        collect(0.5)
        print("Bash jobs:", repr(bytes(transcript[offset:])))
        if name == "cat":
            assert b"Stopped (tty input)" in transcript[offset:]
        os.write(master, b"fg %1\n")
    until("job in foreground", lambda: os.tcgetpgrp(master) == target and state(target) not in ("T", "t"))
    if name == "cat":
        offset = len(transcript)
        os.write(master, b"input-works\n")
        until("cat read and echoed", lambda: transcript[offset:].count(b"input-works") >= 2)
        print("After fg: cat accepted input again")
    else:
        collect(0.3)
        offset = len(transcript)
        os.write(master, b"\x1b[B")
        collect(0.7)
        print("After fg: foreground =", os.tcgetpgrp(master) == target,
              "output bytes following Down =", len(transcript) - offset,
              "draw commands =", b"\x1b[" in transcript[offset:])
finally:
    # All of these processes were created in this private test session.
    for entry in Path("/proc").glob("[0-9]*"):
        pid = int(entry.name)
        try:
            if os.getsid(pid) == shell:
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    os.close(master)
    os.waitpid(shell, 0)
