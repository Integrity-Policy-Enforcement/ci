# SPDX-License-Identifier: GPL-2.0-only
"""The files a VM run leaves for verdict.py, under its chosen output directory."""

from pathlib import Path

VM_EXIT_CODE = "vm_exit_code"


def _path(root: Path, name: str) -> Path:
    return root.resolve() / name


def result(root: Path) -> Path:
    """The TAP stream written by the guest."""
    return _path(root, "result.log")


def console(root: Path) -> Path:
    """The complete VM console."""
    return _path(root, "console.log")


def payload(root: Path) -> Path:
    """The ext4 payload disk attached to the VM."""
    return _path(root, "payload.raw")


def verdict(root: Path) -> Path:
    """The final PASS or FAIL and its reasons."""
    return _path(root, "verdict.json")


def vm_facts(root: Path) -> Path:
    """How QEMU ran and the exit code it returned."""
    return _path(root, "host.json")
