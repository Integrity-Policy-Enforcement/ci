# SPDX-License-Identifier: GPL-2.0-only

import shutil
from pathlib import Path

import layout
from command import capture, run

DEVICE_MAPPER = Path("/dev/mapper")


def points():
    live = capture("findmnt", "--noheadings", "--raw", "--output", "TARGET").split()
    return {point for point in live if point.startswith(f"{layout.MEDIA}/")}


def umount(point):
    run("umount", point)


def devices():
    """Only the devices the tests open: the root filesystem has one too."""
    listing = capture("dmsetup", "ls")
    present = {line.split()[0] for line in listing.splitlines() if line[:1].isalnum()}
    return present & {layout.DMVERITY_SIGNED_DEVICE, layout.DMVERITY_UNSIGNED_DEVICE}


def close(name):
    run("veritysetup", "close", name)


def mount(device, point, *options):
    point.mkdir(parents=True, exist_ok=True)
    run("mount", *options, device, point)


def dmverity(name, point, signed):
    assets = layout.DMVERITY_ASSETS
    root_hash = (assets / layout.ROOT_HASH).read_text().strip()
    signature = ["--root-hash-signature", assets / layout.SIGNATURE] if signed else []
    run(
        "veritysetup", "open",
        assets / layout.SQUASHFS,
        name,
        assets / layout.HASH_TREE,
        root_hash,
        *signature,
    )
    mount(DEVICE_MAPPER / name, point, "-o", "ro")


def tmpfs(point, module):
    """A filesystem with no block device, carrying a copy of the module."""
    mount("tmpfs", point, "-t", "tmpfs")
    shutil.copy(module, point)
