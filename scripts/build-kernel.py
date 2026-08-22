#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
IPE_TEST_CONFIG = ROOT / "config" / "ipe-tests.config"
BOOT_POLICY = ROOT / "config" / "boot-policy.pol"
CERTIFICATE = ROOT / "build" / "keys" / "signing-cert.pem"
MODULE_KEY = ROOT / "build" / "keys" / "module-signing.pem"
OUTPUT = ROOT / "build" / "kernel"
STAGING = ROOT / "build" / "kernel-install"
IMAGE = OUTPUT / "arch" / "x86" / "boot" / "bzImage"


def run_result(command, **kwargs):
    return subprocess.run([str(part) for part in command], check=False, **kwargs)


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build the IPE test kernel.")
    parser.add_argument("kernel_tree", type=Path)
    args = parser.parse_args(argv)

    source = args.kernel_tree.resolve()
    if not (source / "Makefile").is_file():
        return fail(f"not a Linux kernel tree: {source}")
    if not BOOT_POLICY.is_file():
        return fail(f"boot policy is missing: {BOOT_POLICY}")
    if not CERTIFICATE.is_file() or not MODULE_KEY.is_file():
        return fail("signing keys are missing; run prepare-policies.py")

    shutil.rmtree(OUTPUT, ignore_errors=True)
    shutil.rmtree(STAGING, ignore_errors=True)
    OUTPUT.mkdir(parents=True)
    jobs = os.cpu_count() or 1
    make = ["make", "-C", source, f"O={OUTPUT}", "ARCH=x86", f"-j{jobs}"]

    print("    Configure x86_64 kernel", flush=True)
    if run_result([*make, "x86_64_defconfig"], stdout=subprocess.DEVNULL).returncode:
        return 1

    key_fragment = OUTPUT / ".signing-key.config"
    key_fragment.write_text(
        f'CONFIG_SYSTEM_TRUSTED_KEYS="{CERTIFICATE}"\n'
        f'CONFIG_MODULE_SIG_KEY="{MODULE_KEY}"\n'
        f'CONFIG_IPE_BOOT_POLICY="{BOOT_POLICY}"\n',
        encoding="utf-8",
    )
    merge_log = OUTPUT / "merge.log"
    environment = os.environ.copy()
    environment["ARCH"] = "x86"
    with merge_log.open("w", encoding="utf-8") as log:
        result = run_result(
            [
                source / "scripts" / "kconfig" / "merge_config.sh",
                "-O",
                OUTPUT,
                OUTPUT / ".config",
                IPE_TEST_CONFIG,
                key_fragment,
            ],
            cwd=OUTPUT,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    merge_text = merge_log.read_text(encoding="utf-8")
    merge_warnings = [line for line in merge_text.splitlines() if line.startswith("WARNING:")]
    if result.returncode or merge_warnings:
        print(merge_text, file=sys.stderr)
        return result.returncode or 1

    print("    Compile kernel", flush=True)
    build_log = OUTPUT / "build.log"
    with build_log.open("w", encoding="utf-8") as log:
        result = run_result(make, stdout=log, stderr=subprocess.STDOUT, text=True)
    if result.returncode:
        print(build_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
        return result.returncode
    if not IMAGE.is_file():
        return fail(f"kernel image was not produced: {IMAGE}")

    release = run_result(
        [*make, "-s", "kernelrelease"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if release.returncode:
        print(release.stderr, file=sys.stderr)
        return release.returncode
    release = release.stdout.strip()

    print("    Install kernel", flush=True)
    install_log = OUTPUT / "install.log"
    with install_log.open("w", encoding="utf-8") as log:
        result = run_result(
            [
                *make,
                f"INSTALL_MOD_PATH={STAGING / 'usr'}",
                "INSTALL_MOD_STRIP=1",
                "modules_install",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if result.returncode:
        print(install_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
        return result.returncode

    modules = STAGING / "usr" / "lib" / "modules" / release
    if not modules.is_dir():
        return fail(f"kernel modules were not installed: {modules}")
    shutil.copy2(IMAGE, modules / "vmlinuz")

    print(f"    Built {IMAGE} ({IMAGE.stat().st_size / 1024 / 1024:.1f} MiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
