# SPDX-License-Identifier: GPL-2.0-only

import shutil
from pathlib import Path

import layout
from command import capture, run

DEVICE_MAPPER = Path("/dev/mapper")


def points():
    live = capture("findmnt", "--noheadings", "--raw", "--output", "TARGET").split()
    return {point for point in live if point.startswith(f"{layout.guest.MEDIA}/")}


def umount(point):
    run("umount", point)


def devices():
    """Only the devices the tests open: the root filesystem has one too."""
    listing = capture("dmsetup", "ls")
    present = {line.split()[0] for line in listing.splitlines() if line[:1].isalnum()}
    ours = {
        layout.guest.dmverity_device(algorithm, signed)
        for algorithm in layout.HASH_ALGORITHMS
        for signed in (True, False)
    }
    return present & ours


def close(name):
    run("veritysetup", "close", name)


def mount(device, point, *options):
    point.mkdir(parents=True, exist_ok=True)
    run("mount", *options, device, point)


def dmverity(algorithm, signed):
    assets = layout.guest.DMVERITY_ASSETS
    name = layout.guest.dmverity_device(algorithm, signed)
    root_hash = (assets / layout.guest.root_hash(algorithm)).read_text().strip()
    signature = (
        ["--root-hash-signature", assets / layout.guest.root_hash_signature(algorithm)]
        if signed
        else []
    )
    run(
        "veritysetup", "open",
        assets / layout.guest.SQUASHFS,
        name,
        assets / layout.guest.hash_tree(algorithm),
        root_hash,
        *signature,
    )
    mount(DEVICE_MAPPER / name, layout.guest.dmverity_mount(algorithm, signed), "-o", "ro")


def tmpfs(point, module):
    """A filesystem with no block device, carrying a copy of the module."""
    mount("tmpfs", point, "-t", "tmpfs")
    shutil.copy(module, point)
