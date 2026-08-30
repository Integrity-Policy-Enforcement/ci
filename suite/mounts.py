# SPDX-License-Identifier: GPL-2.0-only

import shutil
from contextlib import AbstractContextManager
from pathlib import Path

import hashes
import layout
from command import capture, run
from scope import collection

DEVICE_MAPPER = Path("/dev/mapper")


def points() -> set[str]:
    """Mount points under the test media directory; bounded by prefix."""
    live = capture("findmnt", "--noheadings", "--raw", "--output", "TARGET").split()
    return {point for point in live if point.startswith(f"{layout.guest.MEDIA}/")}


def umount(point: str) -> None:
    """Unmount a single mount point."""
    run("umount", point)


def device_name(algorithm: str, signed: bool) -> str:
    """The device-mapper name for one hash and signature state."""
    state = "signed" if signed else "unsigned"
    return f"ipe-dmverity-{algorithm}-{state}"


def devices() -> set[str]:
    """Only the devices the tests open: the root filesystem has one too."""
    listing = capture("dmsetup", "ls")
    present = {line.split()[0] for line in listing.splitlines() if line[:1].isalnum()}
    ours = {
        device_name(algorithm, signed)
        for algorithm in hashes.ALGORITHMS
        for signed in (True, False)
    }
    return present & ours


def close(name: str) -> None:
    """Close a dm-verity device by name."""
    run("veritysetup", "close", name)


def mount(device: Path | str, point: Path, *options: str) -> None:
    """Mount a device at a point, creating the directory if needed."""
    point.mkdir(parents=True, exist_ok=True)
    run("mount", *options, device, point)


def dmverity(algorithm: str, signed: bool) -> None:
    """Open a dm-verity device over the squashfs image and mount it read-only."""
    name = device_name(algorithm, signed)
    root_hash = layout.guest.root_hash(algorithm).read_text().strip()
    signature = (
        ["--root-hash-signature", layout.guest.root_hash_signature(algorithm)]
        if signed
        else []
    )
    run(
        "veritysetup", "open",
        layout.guest.SQUASHFS,
        name,
        layout.guest.hash_tree(algorithm),
        root_hash,
        *signature,
    )
    mount(DEVICE_MAPPER / name, layout.guest.dmverity_mount(algorithm, signed), "-o", "ro")


def tmpfs(point: Path, module: Path) -> None:
    """A filesystem with no block device, carrying a copy of the module."""
    mount("tmpfs", point, "-t", "tmpfs")
    shutil.copy(module, point)


def opened_scope() -> AbstractContextManager[None]:
    """Track dm-verity devices opened inside one context."""
    return collection(members=devices, discard=close)


def mounted_scope() -> AbstractContextManager[None]:
    """Track filesystems mounted inside one context."""
    return collection(members=points, discard=umount)
