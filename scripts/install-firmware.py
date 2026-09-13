#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import hashlib
import http.client
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ARM64_FIRMWARE_URL = (
    "https://snapshot.debian.org/archive/debian/20260806T202652Z"
    "/pool/main/e/edk2/qemu-efi-aarch64_2026.05-2_all.deb"
)
ARM64_FIRMWARE_SHA256 = "ec0a922bc758fcf4b57b00b81870475d97e07ef166d4160d4651931958bbbdc3"

# snapshot.debian.org regularly truncates or refuses responses, so retry instead
# of failing the whole test run on a transient network error.
DOWNLOAD_ATTEMPTS = 5
DOWNLOAD_RETRY_DELAY = 15


def download(url: str, destination: Path) -> None:
    with urllib.request.urlopen(url) as response:
        destination.write_bytes(response.read())


def fetch(url: str, destination: Path, sha256: str) -> bool:
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        try:
            download(url, destination)
        except (OSError, http.client.HTTPException) as error:
            reason = f"download failed: {error}"
        else:
            digest = hashlib.sha256(destination.read_bytes()).hexdigest()
            if digest == sha256:
                return True
            reason = f"digest {digest} does not match the pinned value"

        print(f"attempt {attempt}/{DOWNLOAD_ATTEMPTS}: {reason}", file=sys.stderr)
        if attempt < DOWNLOAD_ATTEMPTS:
            time.sleep(DOWNLOAD_RETRY_DELAY)

    return False


def main() -> int:
    with tempfile.TemporaryDirectory() as workspace:
        package = Path(workspace) / "firmware.deb"
        if not fetch(ARM64_FIRMWARE_URL, package, ARM64_FIRMWARE_SHA256):
            print(f"could not download verified firmware from {ARM64_FIRMWARE_URL}", file=sys.stderr)
            return 1

        subprocess.run(["dpkg", "--install", package], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
