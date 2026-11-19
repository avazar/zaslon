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
integration = os.getenv("CHECK_FOREGROUND_BASH")
name = Path(program).name
profile = tempfile.TemporaryDirectory(dir=os.environ.get("RUNNER_TEMP"))
shell, master = pty.fork()
if shell == 0:
    os.chdir(profile.name)
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 110, 0, 0))
    os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-i"],
              {"HOME": profile.name, "PATH": str(Path(program).parent) + ":/usr/bin:/bin", "LANG": "C.UTF-8",
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
    if integration:
        os.write(master, ("source " + shlex.quote(integration) + "\ncodex\n").encode())
    else:
        os.write(master, (shlex.quote(program) + "\n").encode())
    job = until("foreground child", lambda: (g if (g := os.tcgetpgrp(master)) > 0 and g != shell else None))
    def find_target():
        for path in Path("/proc").glob("[0-9]*/comm"):
            pid = int(path.parent.name)
            try:
                if os.getpgid(pid) == job and path.read_text().strip() == name:
                    return pid
            except (ProcessLookupError, FileNotFoundError):
                pass
    target = until("foreground executable", find_target)
    if name == "codex":
        until("Codex sign-in screen", lambda: b"Choose how you want to use Codex" in transcript, 20)
        collect(1)
        print("Codex startup screen:", repr(bytes(transcript[-1000:])))
        print("Mouse tracking enables:", re.findall(rb"\x1b\[\?(100[0236])h", transcript))
        # Establish an interactive baseline on the offline welcome menu.
        offset = len(transcript)
        os.write(master, b"\x1b[B")
        collect(0.65)
        print("Before pause: Down output =", repr(bytes(transcript[offset:])[:360]))
        offset = len(transcript)
        os.write(master, b"\x1b[A")
        collect(0.65)
        print("Before pause: Up output =", repr(bytes(transcript[offset:])[:360]))
    command = ([sys.executable, controller] if controller.endswith(".py") else [controller])
    with subprocess.Popen(command + [str(shell), str(target), name],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as control:
        assert control.stdout.readline().strip() == "paused"
        if integration:
            assert os.tcgetpgrp(master) == job and state(target) == "T"
            offset = len(transcript)
            os.write(master, b"\x1b[<35;42;11M")
            collect(0.4)
            assert b"35;42;11M" not in transcript[offset:]
            print("During pause: Codex is stopped, job retains terminal, no mouse echo")
        else:
            until("foreground returned to Bash", lambda: os.tcgetpgrp(master) == shell)
            print("Paused: Bash owns the foreground, job state =", state(target))
        if name == "codex":
            modes = re.findall(rb"\x1b\[\?1003([hl])", transcript)
            if modes and modes[-1] == b"h":
                offset = len(transcript)
                os.write(master, b"\x1b[<35;42;11M")
                collect(0.25)
                print("Mouse motion while paused: echo =", repr(bytes(transcript[offset:])))
                os.write(master, b"\x15")
        control.stdin.write("resume\n")
        control.stdin.flush()
        assert control.stdout.readline().strip() == "resumed"
        assert control.wait(timeout=15) == 0
    collect(1.2)
    print("After Zaslon Resume: foreground =", os.tcgetpgrp(master),
          "bash =", shell, "job =", target, "job state =", state(target))
    if integration:
        assert os.tcgetpgrp(master) == job, "shell reclaimed terminal"
    elif os.tcgetpgrp(master) == shell:
        if name == "codex":
            offset = len(transcript)
            os.write(master, b"\x1b[<35;42;11M")
            collect(0.15)
            print("Simulated mouse input before fg:", repr(bytes(transcript[offset:])))
            os.write(master, b"\x15")
        offset = len(transcript)
        os.write(master, b"jobs -l\n")
        collect(0.5)
        print("Bash jobs:", repr(bytes(transcript[offset:])))
        if name == "cat":
            assert b"Stopped (tty input)" in transcript[offset:]
        os.write(master, b"fg %1\n")
    until("job in foreground", lambda: os.tcgetpgrp(master) == job and state(target) not in ("T", "t"))
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
        if integration:
            assert b"> 2. " in transcript[offset:], "Down did not select the second menu item"
            print("Automatic recovery: Down selected the second Codex menu item without fg")
        print("After resume: foreground =", os.tcgetpgrp(master) == job,
              "output bytes following Down =", len(transcript) - offset,
              "draw commands =", b"\x1b[" in transcript[offset:],
              "output =", repr(bytes(transcript[offset:])[:360]))
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
