# SPDX-License-Identifier: GPL-2.0-only

import subprocess
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from pathlib import Path

ASYMMETRIC_KEY_TYPE = "asymmetric"


def keyctl(*arguments: str, payload: bytes | None = None) -> str:
    """Run keyctl with the given arguments and optional stdin payload."""
    return subprocess.run(
        ["keyctl", *arguments],
        input=payload,
        capture_output=True,
        check=True,
    ).stdout.decode()


def linked_keys(keyring: str) -> set[str]:
    """The key serial numbers currently linked into this keyring."""
    return set(keyctl("rlist", keyring).split())


def add_certificate(keyring: str, certificate: Path) -> str:
    """Add one DER certificate and return its key serial."""
    serial = keyctl(
        "padd",
        ASYMMETRIC_KEY_TYPE,
        "",
        keyring,
        payload=certificate.read_bytes(),
    ).strip()
    if not serial:
        raise RuntimeError("keyctl padd returned no key serial")
    return serial


def unlink(key: str, keyring: str) -> None:
    """Unlink a key from a keyring by its serial number."""
    keyctl("unlink", key, keyring)


@contextmanager
def certificates_scope(
    *,
    keyring: str,
    certificates: Sequence[Path],
) -> Generator[None, None, None]:
    """Link certificates and later unlink exactly the keys added here."""
    existing = linked_keys(keyring)
    created = []
    try:
        for certificate in certificates:
            serial = add_certificate(keyring, certificate)
            if serial not in existing and serial not in created:
                created.append(serial)
        yield
    finally:
        failures = []
        for serial in reversed(created):
            try:
                unlink(serial, keyring)
            except BaseException as failure:
                failures.append(failure)
        if failures:
            raise BaseExceptionGroup("certificate cleanup failed", failures)
