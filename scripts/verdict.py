#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import json
import re
import subprocess
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"

HEALTH_PATTERNS = (
    (re.compile(r"Kernel panic"), "kernel panic"),
    (re.compile(r"\bOops\b"), "Oops"),
    (re.compile(r"^(\[[^\]]*\]\s*)?BUG:"), "BUG"),
    (re.compile(r"WARNING: CPU:"), "WARN()"),
    (re.compile(r"WARNING: possible circular locking dependency"), "lock inversion"),
    (re.compile(r"\bkernel BUG at\b"), "kernel BUG"),
    (re.compile(r"BUG: KASAN:"), "KASAN"),
    (re.compile(r"INFO: .* (self-)?detected stall"), "RCU stall"),
    (re.compile(r"INFO: task .* blocked for more than"), "hung task"),
    (re.compile(r"unable to handle (kernel )?pag(e|ing) request"), "invalid memory access"),
)


def health_failures(path):
    failures = []
    for number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        for pattern, label in HEALTH_PATTERNS:
            if pattern.search(line):
                failures.append(f"console.log:{number} {label}: {line.strip()[:160]}")
                break
    return failures


def read_lines(path):
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip().strip("\x00")
        if stripped:
            lines.append(stripped)
    return lines


def tap_failures(path):
    parsed = subprocess.run(
        ["prove", "--exec", "cat", path],
        capture_output=True,
        text=True,
        check=False,
    )
    if parsed.returncode == 0:
        return []
    report = [line.strip() for line in parsed.stdout.splitlines() if line.strip()]
    return [f"TAP parser: {line}" for line in report[-20:]]


def decide(output):
    console = output / "console.log"
    if not console.is_file():
        return FAIL, ["missing console evidence"]
    try:
        host = json.loads((output / "host.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return FAIL, ["missing or invalid host metadata"]
    vm_exit_code = host.get("vm_exit_code")
    if type(vm_exit_code) is not int:
        return FAIL, ["invalid VM exit code in host metadata"]
    if vm_exit_code != 0:
        return FAIL, [f"VM exited with code {vm_exit_code}"]

    health = health_failures(console)
    if health:
        return FAIL, health

    lines = read_lines(output / "result.log")
    if not lines:
        return FAIL, ["the guest produced no output"]
    if not any(line.startswith("boot") for line in lines):
        return FAIL, ["missing boot marker"]
    if "noipe" in lines:
        return FAIL, ["IPE is unavailable in securityfs"]

    tap = tap_failures(output / "result.log")
    if tap:
        return FAIL, tap

    done = [line for line in lines if line.startswith("done rc=")]
    if not done:
        return FAIL, ["the guest stopped before its done marker"]
    if done[-1] != "done rc=0":
        return FAIL, [f"the guest runner did not exit cleanly: {done[-1]}"]

    return PASS, ["all TAP cases passed"]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evaluate IPE VM test evidence.")
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    verdict, reasons = decide(args.output)
    print(verdict)
    for reason in reasons:
        print(f"  {reason}")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "verdict.json").write_text(
        json.dumps({"verdict": verdict, "reasons": reasons}, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if verdict == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
