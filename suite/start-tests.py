#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only

import os
import subprocess
import sys

import layout

COMMAND_NOT_EXECUTABLE = 126
COMMAND_NOT_FOUND = 127


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
    """Check that IPE is present, run the suite and report its exit code."""
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
    except PermissionError:
        runner_rc = COMMAND_NOT_EXECUTABLE
    except OSError:
        runner_rc = COMMAND_NOT_FOUND
    emit(f"done rc={runner_rc}")
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
