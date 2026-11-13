#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import hashlib
import http.client
import os
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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(url: str, destination: Path, sha256: str) -> bool:
    for attempt in range(DOWNLOAD_ATTEMPTS):
        if attempt:
            time.sleep(DOWNLOAD_RETRY_DELAY)

        try:
            download(url, destination)
        except (OSError, http.client.HTTPException) as error:
            reason = f"download failed: {error}"
        else:
            actual = digest(destination)
            if actual == sha256:
                return True
            reason = f"digest {actual} does not match the pinned value"

        print(reason, file=sys.stderr)

    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install the pinned arm64 UEFI firmware package.")
    parser.add_argument(
        "cache",
        nargs="?",
        type=Path,
        help="directory that keeps the verified package for later runs",
    )
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as workspace:
        directory = args.cache or Path(workspace)
        directory.mkdir(parents=True, exist_ok=True)
        package = directory / "firmware.deb"
        cached = package.is_file() and digest(package) == ARM64_FIRMWARE_SHA256
        if not cached and not fetch(ARM64_FIRMWARE_URL, package, ARM64_FIRMWARE_SHA256):
            print(f"could not download verified firmware from {ARM64_FIRMWARE_URL}", file=sys.stderr)
            return 1

        sudo = [] if os.geteuid() == 0 else ["sudo"]
        subprocess.run(sudo + ["dpkg", "--install", package], check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
