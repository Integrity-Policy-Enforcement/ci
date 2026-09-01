#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import evidence
import layout


def restore_owner(path: Path) -> None:
    uid = os.environ.get("SUDO_UID")
    if not uid:
        return
    gid = os.environ.get("SUDO_GID", uid)
    subprocess.run(["chown", "-fhR", f"{uid}:{gid}", path], check=False)


def make_payload(output: Path) -> None:
    if not tuple(layout.build.POLICIES_DIR.rglob("*.p7s")):
        raise SystemExit("signed policies are missing; run prepare-policies.py")
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary) / "payload"
        ignored = shutil.ignore_patterns("__pycache__", "*.pyc")
        shutil.copytree(layout.source.SUITE_DIR, staging, ignore=ignored)
        # Guest modules import layout.py and hashes.py from /run/ipe-tests, so
        # copy both files beside run-tests.py.
        shutil.copy(layout.source.LAYOUT, staging / layout.source.LAYOUT.name)
        shutil.copy(layout.source.HASHES, staging / layout.source.HASHES.name)
        shutil.copytree(layout.build.POLICIES_DIR, staging / layout.guest.POLICIES_DIR.name)
        shutil.copytree(
            layout.build.DMVERITY_ASSETS_DIR,
            staging / layout.guest.DMVERITY_ASSETS_DIR.name,
        )
        kernel_modules = staging / layout.guest.KERNEL_MODULES_DIR.name
        kernel_modules.mkdir()
        shutil.copy(layout.build.KMODULE_TEST_BINARY, kernel_modules)
        shutil.copytree(
            layout.build.FSVERITY_ASSETS_DIR,
            staging / layout.guest.FSVERITY_ASSETS_DIR.name,
        )
        with output.open("wb") as stream:
            stream.truncate(48 * 1024 * 1024)
        subprocess.run(
            [
                "mkfs.ext4", "-q", "-F", "-O", "verity",
                "-L", "ipe-payload", "-d", staging, output,
            ],
            check=True,
        )


def line_count(path: Path) -> int:
    with path.open("rb") as stream:
        return sum(chunk.count(b"\n") for chunk in iter(lambda: stream.read(1 << 20), b""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the IPE tests in a virtual machine.")
    parser.add_argument("output", type=Path)
    parser.add_argument("--mkosi", default="mkosi")
    args = parser.parse_args(argv)

    output = args.output.resolve()
    image = layout.build.GUEST_IMAGE
    if not image.is_file():
        parser.error(f"guest image does not exist: {image}")

    output.mkdir(parents=True, exist_ok=True)
    atexit.register(restore_owner, output)
    result = evidence.result(output)
    console = evidence.console(output)
    payload = evidence.payload(output)
    verdict = evidence.verdict(output)
    vm_facts = evidence.vm_facts(output)
    for path in (result, console, payload, verdict, vm_facts):
        path.unlink(missing_ok=True)
    result.touch()
    make_payload(payload)

    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    acceleration = "kvm" if kvm else "tcg"
    timeout = os.environ.get("IPE_TEST_TIMEOUT", "180" if kvm else "3600")
    command = [
        "timeout",
        timeout,
        args.mkosi,
        "--directory",
        layout.source.IMAGE_DIR,
        f"--kvm={'yes' if kvm else 'no'}",
        f"--machine=ipe-tests-{os.getpid()}",
        "vm",
        "--",
        "-device",
        "virtserialport,chardev=results,name=ipe-tests-result",
        "-chardev",
        f"file,id=results,path={result}",
        "-drive",
        f"file={payload},format=raw,if=virtio",
    ]
    try:
        with console.open("w", encoding="utf-8") as stream:
            returncode = subprocess.run(
                [str(part) for part in command],
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=False,
            ).returncode
    except OSError as error:
        returncode = 127
        console.write_text(f"{error}\n", encoding="utf-8")

    print(
        f"    VM exit code {returncode}; acceleration={acceleration}; "
        f"timeout={timeout}s; lines={line_count(result)}"
    )
    vm_facts.write_text(
        json.dumps(
            {
                evidence.VM_EXIT_CODE: returncode,
                "acceleration": acceleration,
                "timeout_seconds": timeout,
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    return subprocess.run(
        [sys.executable, layout.source.SCRIPTS_DIR / "verdict.py", output], check=False
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
