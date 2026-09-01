#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only

import os
import subprocess
import sys

import layout

def emit(line: str) -> None:
    """Write one marker to the result channel."""
    data = (line.replace("\n", " ").replace("\r", " ") + "\n").encode()
    descriptor = os.open(layout.guest.RESULT_CHANNEL, os.O_WRONLY)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if not written:
                raise OSError("result channel write returned zero")
            offset += written
    finally:
        os.close(descriptor)


def log(message: str) -> None:
    """Write a message to the VM console."""
    print(f"[ipe-tests] {message}", flush=True)


def service_main() -> int:
    """Check that IPE is present, then run the suite."""
    if not layout.guest.RESULT_CHANNEL.exists():
        sys.stderr.write(f"result channel does not exist: {layout.guest.RESULT_CHANNEL}\n")
        return 1
    if not layout.guest.SECURITYFS_DIR.is_dir():
        emit("Bail out! IPE unavailable in securityfs")
        log(f"{layout.guest.SECURITYFS_DIR} does not exist")
        return 0

    try:
        runner_rc = subprocess.run(
            [sys.executable, layout.guest.RUNNER, layout.guest.RESULT_CHANNEL],
            check=False,
        ).returncode
    except OSError as failure:
        emit(f"Bail out! runner failed to start: {failure}")
    else:
        if runner_rc:
            emit(f"Bail out! runner exited {runner_rc}")
    log("test run complete")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Reject command-line arguments and run the service entry point."""
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: start-tests.py", file=sys.stderr)
        return 2
    return service_main()


if __name__ == "__main__":
    raise SystemExit(main())
