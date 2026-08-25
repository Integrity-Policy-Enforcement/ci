# SPDX-License-Identifier: GPL-2.0-only

import shutil
import subprocess

import layout
from command import run


def copy_module(target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(layout.PAYLOAD / layout.TEST_MODULE_FILE, target)


def verity_module(target, signature=None):
    copy_module(target)
    signed = [f"--signature={signature}"] if signature else []
    run("fsverity", "enable", target, *signed)
