# SPDX-License-Identifier: GPL-2.0-only

import subprocess
from contextlib import AbstractContextManager
from functools import partial
from pathlib import Path

from scope import collection

ASYMMETRIC_KEY_TYPE = "asymmetric"


def keyctl(*arguments: str, payload: bytes | None = None) -> bytes:
    """Run keyctl with the given arguments and optional stdin payload."""
    return subprocess.run(
        ["keyctl", *arguments],
        input=payload,
        capture_output=True,
        check=True,
    ).stdout


def linked_keys(keyring: str) -> set[str]:
    """The key serial numbers currently linked into this keyring."""
    return set(keyctl("rlist", keyring).split())


def add_certificate(keyring: str, certificate: Path) -> None:
    """Add a DER certificate as an asymmetric key in the named keyring."""
    keyctl("padd", ASYMMETRIC_KEY_TYPE, "", keyring, payload=certificate.read_bytes())


def unlink(key: str, keyring: str) -> None:
    """Unlink a key from a keyring by its serial number."""
    keyctl("unlink", key, keyring)


def linked_scope(keyring: str) -> AbstractContextManager[None]:
    """Track keys linked into this keyring inside one context."""
    return collection(
        members=partial(linked_keys, keyring),
        discard=partial(unlink, keyring=keyring),
    )
