"""Probe the kernel terminal semantics on an isolated, delegated CI runner unit."""
import os
import sys
import time
from pathlib import Path

shell, target = map(int, sys.argv[1:3])
mount = Path("/sys/fs/cgroup")
def group(pid):
    raw = Path(f"/proc/{pid}/cgroup").read_text()
    return next(line[3:] for line in raw.splitlines() if line.startswith("0::"))

unit = group("self")
assert "zaslon-tty-test" in unit
assert os.getuid() != 0 and os.getsid(target) == shell
assert group(shell) == group(target) == unit
parent = mount / unit.lstrip("/")
leaf = parent / "codex-fixture"
leaf.mkdir()
print("Direct Codex and Bash initially share group", unit, file=sys.stderr)
print("Delegated CI unit, regular UID =", os.getuid(), file=sys.stderr)
# This is a private test only. Select only members of this one-use systemd
# unit running executables from the test package, never the user's session.
binary = Path(f"/proc/{target}/exe").resolve(strict=True)
package = Path(os.environ["CODEX_TEST_PACKAGE"]).resolve(strict=True)
assert binary.is_relative_to(package)
members = []
for line in (parent / "cgroup.procs").read_text().splitlines():
    pid = int(line)
    try:
        if Path(f"/proc/{pid}/exe").resolve(strict=True).is_relative_to(package):
            (leaf / "cgroup.procs").write_text(line)
            members.append(pid)
    except FileNotFoundError:
        continue
assert target in members and shell not in members
def event():
    return dict(line.split() for line in (leaf / "cgroup.events").read_text().splitlines())["frozen"]
def toggle(value):
    (leaf / "cgroup.freeze").write_text(value)
    deadline = time.monotonic() + 5
    while event() != value:
        if time.monotonic() > deadline:
            raise RuntimeError("freezer transition timed out")
        time.sleep(0.02)
try:
    toggle("1")
    for _ in range(25):
        assert event() == "1" and group(target) == unit + "/codex-fixture" and group(shell) == unit
        time.sleep(0.16)
    print(f"Kernel confirmed frozen=1: {len(members)} Codex package processes; Bash stayed outside", file=sys.stderr)
    print("paused", flush=True)
    assert input() == "resume"
finally:
    toggle("0")
print("resumed", flush=True)
