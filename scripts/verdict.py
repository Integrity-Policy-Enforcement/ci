#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import json
import re
import subprocess
from pathlib import Path

import evidence

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


def health_failures(path: Path) -> list[str]:
    failures = []
    for number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        for pattern, label in HEALTH_PATTERNS:
            if pattern.search(line):
                failures.append(f"{path.name}:{number} {label}: {line.strip()[:160]}")
                break
    return failures


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    lines = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip().strip("\x00")
        if stripped:
            lines.append(stripped)
    return lines


def tap_failures(path: Path) -> list[str]:
    parsed = subprocess.run(
        ["prove", "--exec", "cat", path],
        capture_output=True,
        text=True,
        check=False,
    )
    if parsed.returncode == 0:
        return []
    report = [
        line.strip()
        for stream in (parsed.stdout, parsed.stderr)
        for line in stream.splitlines()
        if line.strip()
    ]
    if not report:
        return [
            f"TAP parser exited with code {parsed.returncode} without diagnostics"
        ]
    return [f"TAP parser: {line}" for line in report[-20:]]


def decide(output: Path) -> tuple[str, list[str]]:
    console = evidence.console(output)
    if not console.is_file():
        return FAIL, ["missing console evidence"]
    try:
        vm_facts = json.loads(evidence.vm_facts(output).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return FAIL, ["missing or invalid host metadata"]
    vm_exit_code = vm_facts.get(evidence.VM_EXIT_CODE)
    if type(vm_exit_code) is not int:
        return FAIL, ["invalid VM exit code in host metadata"]
    if vm_exit_code != 0:
        return FAIL, [f"VM exited with code {vm_exit_code}"]

    health = health_failures(console)
    if health:
        return FAIL, health

    lines = read_lines(evidence.result(output))
    if not lines:
        return FAIL, ["the guest produced no output"]
    if not any(line.startswith("boot") for line in lines):
        return FAIL, ["missing boot marker"]
    if "noipe" in lines:
        return FAIL, ["IPE is unavailable in securityfs"]

    tap = tap_failures(evidence.result(output))
    if tap:
        return FAIL, tap

    done = [line for line in lines if line.startswith("done rc=")]
    if not done:
        return FAIL, ["the guest stopped before its done marker"]
    if done[-1] != "done rc=0":
        return FAIL, [f"the guest runner did not exit cleanly: {done[-1]}"]

    return PASS, ["all TAP cases passed"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate IPE VM test evidence.")
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    verdict, reasons = decide(args.output)
    print(verdict)
    for reason in reasons:
        print(f"  {reason}")
    args.output.mkdir(parents=True, exist_ok=True)
    evidence.verdict(args.output).write_text(
        json.dumps({"verdict": verdict, "reasons": reasons}, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0 if verdict == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
