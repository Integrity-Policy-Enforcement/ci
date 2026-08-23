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

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
IMAGE_DIR = ROOT / "image"
SUITE = ROOT / "suite"
POLICIES = ROOT / "build" / "policies"


def restore_owner(path):
    uid = os.environ.get("SUDO_UID")
    if not uid:
        return
    gid = os.environ.get("SUDO_GID", uid)
    subprocess.run(["chown", "-fhR", f"{uid}:{gid}", path], check=False)


def make_payload(output):
    if not tuple(POLICIES.rglob("*.p7s")):
        raise SystemExit("signed policies are missing; run prepare-policies.py")
    with tempfile.TemporaryDirectory() as temporary:
        staging = Path(temporary) / "payload"
        ignored = shutil.ignore_patterns("__pycache__", "*.pyc")
        shutil.copytree(SUITE, staging, ignore=ignored)
        shutil.copytree(POLICIES, staging / "policies")
        with output.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024)
        subprocess.run(
            ["mkfs.ext4", "-q", "-F", "-L", "ipe-payload", "-d", staging, output],
            check=True,
        )


def line_count(path):
    with path.open("rb") as stream:
        return sum(chunk.count(b"\n") for chunk in iter(lambda: stream.read(1 << 20), b""))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the IPE tests in a virtual machine.")
    parser.add_argument("output", type=Path)
    parser.add_argument("--mkosi", default="mkosi")
    args = parser.parse_args(argv)

    output = args.output.resolve()
    image = IMAGE_DIR / "output" / "ipe-tests.raw"
    if not image.is_file():
        parser.error(f"guest image does not exist: {image}")

    output.mkdir(parents=True, exist_ok=True)
    atexit.register(restore_owner, output)
    result = output / "result.log"
    console = output / "console.log"
    payload = output / "payload.raw"
    verdict = output / "verdict.json"
    host = output / "host.json"
    for path in (result, console, payload, verdict, host):
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
        IMAGE_DIR,
        f"--kvm={'yes' if kvm else 'no'}",
        f"--machine=ipe-tests-{os.getpid()}",
        "vm",
        "--",
        "-device",
        "virtserialport,chardev=results,name=ipe-tests-result",
        "-chardev",
        f"file,id=results,path={result}",
        "-drive",
        f"file={payload},format=raw,if=virtio,readonly=on",
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
    temporary_host = host.with_suffix(".tmp")
    temporary_host.write_text(
        json.dumps(
            {
                "vm_exit_code": returncode,
                "acceleration": acceleration,
                "timeout_seconds": timeout,
            },
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    temporary_host.replace(host)
    return subprocess.run(
        [sys.executable, ROOT / "scripts" / "verdict.py", output], check=False
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
