#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

import layout
import signing

KERNEL_MERGE_CONFIG = Path("scripts") / "kconfig" / "merge_config.sh"


def run_result(command: list, **kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run([str(part) for part in command], check=False, **kwargs)


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the IPE test kernel.")
    parser.add_argument("kernel_tree", type=Path)
    args = parser.parse_args(argv)

    source = args.kernel_tree.resolve()
    machine = platform.machine()
    if machine == "x86_64":
        architecture = "x86_64"
        kernel_arch = "x86"
        defconfig = "x86_64_defconfig"
        image = layout.build.KERNEL / "arch" / "x86" / "boot" / "bzImage"
    elif machine == "aarch64":
        architecture = "arm64"
        kernel_arch = "arm64"
        defconfig = "defconfig"
        image = layout.build.KERNEL / "arch" / "arm64" / "boot" / "Image"
    else:
        return fail(f"unsupported build host architecture: {machine}")
    if not (source / "Makefile").is_file():
        return fail(f"not a Linux kernel tree: {source}")
    if not layout.source.BOOT_POLICY.is_file():
        return fail(f"boot policy is missing: {layout.source.BOOT_POLICY}")
    if not signing.BUILTIN.certificate.is_file() or not signing.MODULE_SIGNING.is_file():
        return fail("signing keys are missing; run prepare-keys.py")

    shutil.rmtree(layout.build.KERNEL, ignore_errors=True)
    shutil.rmtree(layout.build.KERNEL_STAGING, ignore_errors=True)
    layout.build.KERNEL.mkdir(parents=True)
    jobs = os.cpu_count() or 1
    make = [
        "make", "-C", source, f"O={layout.build.KERNEL}",
        f"ARCH={kernel_arch}", f"-j{jobs}",
    ]

    print(f"    Configure {architecture} kernel", flush=True)
    if run_result([*make, defconfig], stdout=subprocess.DEVNULL).returncode:
        return 1

    key_fragment = layout.build.KERNEL / ".signing-key.config"
    key_fragment.write_text(
        f'CONFIG_SYSTEM_TRUSTED_KEYS="{signing.BUILTIN.certificate}"\n'
        f'CONFIG_MODULE_SIG_KEY="{signing.MODULE_SIGNING}"\n'
        f'CONFIG_IPE_BOOT_POLICY="{layout.source.BOOT_POLICY}"\n'
        f'CONFIG_SYSTEM_REVOCATION_KEYS="{signing.REVOKED.certificate}"\n',
        encoding="utf-8",
    )
    merge_log = layout.build.KERNEL / "merge.log"
    environment = os.environ.copy()
    environment["ARCH"] = kernel_arch
    with merge_log.open("w", encoding="utf-8") as log:
        result = run_result(
            [
                source / KERNEL_MERGE_CONFIG,
                "-O",
                layout.build.KERNEL,
                layout.build.KERNEL_CONFIG,
                layout.source.KERNEL_CONFIG,
                key_fragment,
            ],
            cwd=layout.build.KERNEL,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
    if result.returncode:
        print(merge_log.read_text(encoding="utf-8"), file=sys.stderr)
        return result.returncode

    print("    Compile kernel", flush=True)
    build_log = layout.build.KERNEL / "build.log"
    with build_log.open("w", encoding="utf-8") as log:
        result = run_result(make, stdout=log, stderr=subprocess.STDOUT, text=True)
    if result.returncode:
        print(build_log.read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
        return result.returncode
    if not image.is_file():
        return fail(f"kernel image was not produced: {image}")

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
    install_log = layout.build.KERNEL / "install.log"
    with install_log.open("w", encoding="utf-8") as log:
        result = run_result(
            [
                *make,
                f"INSTALL_MOD_PATH={layout.build.KERNEL_STAGING / 'usr'}",
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

    modules = layout.build.KERNEL_STAGING / "usr" / "lib" / "modules" / release
    if not modules.is_dir():
        return fail(f"kernel modules were not installed: {modules}")
    shutil.copy2(image, modules / "vmlinuz")

    print(f"    Built {image} ({image.stat().st_size / 1024 / 1024:.1f} MiB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
