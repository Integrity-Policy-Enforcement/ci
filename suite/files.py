# SPDX-License-Identifier: GPL-2.0-only

import shutil
from pathlib import Path

import layout
from command import run


def copies():
    """The module copies a batch made, which outlive it on the payload."""
    if not layout.FSVERITY_MODULES.is_dir():
        return set()
    return {str(path) for path in layout.FSVERITY_MODULES.iterdir()}


def discard(copy):
    Path(copy).unlink()


def copy_module(target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(layout.PAYLOAD / layout.TEST_MODULE_FILE, target)


def verity_module(target, signature=None):
    copy_module(target)
    signed = [f"--signature={signature}"] if signature else []
    run("fsverity", "enable", target, *signed)
