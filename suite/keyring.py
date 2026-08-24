# SPDX-License-Identifier: GPL-2.0-only

import subprocess

ASYMMETRIC_KEY_TYPE = "asymmetric"


def keyctl(*arguments, payload=None):
    return subprocess.run(
        ["keyctl", *arguments],
        input=payload,
        capture_output=True,
        check=True,
    ).stdout


def linked_keys(keyring):
    return set(keyctl("rlist", keyring).split())


def add_certificate(keyring, certificate):
    keyctl("padd", ASYMMETRIC_KEY_TYPE, "", keyring, payload=certificate.read_bytes())


def unlink(key, keyring):
    keyctl("unlink", key, keyring)
