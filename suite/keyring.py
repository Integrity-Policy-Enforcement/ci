# SPDX-License-Identifier: GPL-2.0-only

import subprocess
from functools import partial
from pathlib import Path

from scope import Collection

ASYMMETRIC_KEY_TYPE = "asymmetric"


def keyctl(*arguments: str, payload: bytes | None = None) -> bytes:
    return subprocess.run(
        ["keyctl", *arguments],
        input=payload,
        capture_output=True,
        check=True,
    ).stdout


def linked_keys(keyring: str) -> set[str]:
    return set(keyctl("rlist", keyring).split())


def add_certificate(keyring: str, certificate: Path) -> None:
    keyctl("padd", ASYMMETRIC_KEY_TYPE, "", keyring, payload=certificate.read_bytes())


def unlink(key: str, keyring: str) -> None:
    keyctl("unlink", key, keyring)


def linked(keyring: str) -> Collection:
    return Collection(
        members=partial(linked_keys, keyring),
        discard=partial(unlink, keyring=keyring),
    )
