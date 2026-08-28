# SPDX-License-Identifier: GPL-2.0-only

import shutil
from pathlib import Path

import layout
from command import run


def copies():
    """The module copies a batch made, which outlive it on the payload."""
    if not layout.guest.FSVERITY_MODULES.is_dir():
        return set()
    return {str(path) for path in layout.guest.FSVERITY_MODULES.iterdir()}


def discard(copy):
    Path(copy).unlink()


def copy_module(target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(layout.guest.PAYLOAD / layout.TEST_MODULE_FILE, target)


def verity_module(target, algorithm, signature=None):
    copy_module(target)
    signed = [f"--signature={signature}"] if signature else []
    run("fsverity", "enable", target, f"--hash-alg={algorithm}", *signed)
