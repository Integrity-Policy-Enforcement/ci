# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Generator
from contextlib import AbstractContextManager, contextmanager
from functools import partial
from pathlib import Path

import layout
from command import capture, run
from scope import collection

DEVICE_MAPPER = Path("/dev/mapper")


def points(directory: Path) -> set[Path]:
    """Return mount points at or below a directory.

    For ``directory = Path("/run/ipe-media")``, findmnt may return::

        /
        /run/ipe-media/plain
        /run/ipe-media/dmverity-sha256-signed

    ``is_relative_to()`` filters out mount points outside ``directory``, so
    only the last two paths are returned.
    """
    live = {
        Path(point)
        for point in capture(
            "findmnt", "--noheadings", "--raw", "--output", "TARGET"
        ).split()
    }
    return {point for point in live if point.is_relative_to(directory)}


def umount(point: Path) -> None:
    """Unmount a single mount point."""
    run("umount", point)


def device_name(*, prefix: str, algorithm: str, signed: bool) -> str:
    """Name one device from its caller-owned prefix and state."""
    state = "signed" if signed else "unsigned"
    return f"{prefix}{algorithm}-{state}"


def dmverity_devices(prefix: str) -> set[str]:
    """Return dm-verity mappings with the caller-owned prefix.

    For ``prefix = "ipe-dmverity-"``, dmsetup may return::

        root                                (253:0)
        ipe-dmverity-sha256-signed          (253:1)
        ipe-dmverity-sha256-unsigned        (253:2)

    ``split()[0]`` selects each mapping name. ``startswith(prefix)`` filters
    out ``root`` and keeps the two test mappings.
    """
    listing = capture("dmsetup", "ls")
    present = {line.split()[0] for line in listing.splitlines() if line[:1].isalnum()}
    return {name for name in present if name.startswith(prefix)}


def close_dmverity(name: str) -> None:
    """Close a dm-verity mapping by name."""
    run("veritysetup", "close", name)


def mount(device: Path | str, point: Path, *options: str) -> None:
    """Mount a device at a point, creating the directory if needed."""
    point.mkdir(parents=True, exist_ok=True)
    run("mount", *options, device, point)


def dmverity(*, prefix: str, algorithm: str, signed: bool) -> None:
    """Open a dm-verity device over the squashfs image and mount it read-only."""
    name = device_name(prefix=prefix, algorithm=algorithm, signed=signed)
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
    mount(DEVICE_MAPPER / name, layout.guest.dmverity_mount_dir(algorithm, signed), "-o", "ro")


def tmpfs(point: Path) -> None:
    """Mount tmpfs at a directory."""
    mount("tmpfs", point, "-t", "tmpfs")


def dmverity_scope(*, prefix: str) -> AbstractContextManager[None]:
    """Track dm-verity mappings created under a prefix."""
    return collection(
        members=partial(dmverity_devices, prefix),
        discard=close_dmverity,
    )


@contextmanager
def mounted_scope(*, directory: Path) -> Generator[None, None, None]:
    """Unmount new mount points below a directory, deepest first."""
    captured = points(directory)
    try:
        yield
    finally:
        failures = []
        created = points(directory) - captured
        for point in sorted(created, key=lambda path: len(path.parts), reverse=True):
            try:
                umount(point)
            except BaseException as failure:
                failures.append(failure)
        if failures:
            raise BaseExceptionGroup("mount restoration failed", failures)
