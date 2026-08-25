# SPDX-License-Identifier: GPL-2.0-only

import subprocess

import layout
from command import capture, run


def loaded():
    """Only the test module: the kernel loads its own without asking."""
    present = {line.split()[0] for line in capture("lsmod").splitlines()[1:]}
    return present & {layout.TEST_MODULE}


def insert(path):
    return subprocess.run(["insmod", str(path)], capture_output=True, text=True)


def remove(name):
    run("rmmod", name)
