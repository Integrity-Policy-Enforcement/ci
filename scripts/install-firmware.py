#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import hashlib
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ARM64_FIRMWARE_URL = (
    "https://snapshot.debian.org/archive/debian/20260806T202652Z"
    "/pool/main/e/edk2/qemu-efi-aarch64_2026.05-2_all.deb"
)
ARM64_FIRMWARE_SHA256 = "ec0a922bc758fcf4b57b00b81870475d97e07ef166d4160d4651931958bbbdc3"


def download(url: str, destination: Path) -> None:
    with urllib.request.urlopen(url) as response:
        destination.write_bytes(response.read())


def main() -> int:
    with tempfile.TemporaryDirectory() as workspace:
        package = Path(workspace) / "firmware.deb"
        download(ARM64_FIRMWARE_URL, package)

        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        if digest != ARM64_FIRMWARE_SHA256:
            print(f"firmware digest {digest} does not match the pinned value", file=sys.stderr)
            return 1

        subprocess.run(["dpkg", "--install", package], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
