# SPDX-License-Identifier: GPL-2.0-only

import os

import ipe
from model import Observation


def write_node(entry: str, policy: ipe.Policy | None, data: bytes) -> Observation:
    """Write data to a securityfs node and report the errno."""
    descriptor = os.open(ipe.node_path(entry, policy), os.O_WRONLY)
    try:
        os.write(descriptor, data)
        return Observation(0)
    except OSError as failure:
        return Observation(failure.errno)
    finally:
        os.close(descriptor)


def write_node_and_read(
    entry: str, policy: ipe.Policy | None, data: bytes, observed: list[str]
) -> Observation:
    """Write to a node and read it back in one trigger."""
    observation = write_node(entry, policy, data)
    observed.append(ipe.node_path(entry, policy).read_text().strip())
    return Observation(observation.errno, observed=tuple(observed))


def toggle_node(entry: str, policy: ipe.Policy | None, observed: list[str]) -> Observation:
    """Flip a boolean node and read back the new value."""
    if len(observed) != 1:
        raise RuntimeError(f"expected one read, got {len(observed)}")
    (current,) = observed
    if current not in ("0", "1"):
        raise RuntimeError(f"cannot toggle {current!r}")
    observation = write_node(entry, policy, b"0" if current == "1" else b"1")
    observed.append(ipe.node_path(entry, policy).read_text().strip())
    return Observation(observation.errno, observed=tuple(observed))


def read_node(entry: str, policy: ipe.Policy | None, observed: list[str]) -> Observation:
    """Read a text node and report whether it existed."""
    try:
        observed.append(ipe.node_path(entry, policy).read_text().strip())
        return Observation(0, observed=tuple(observed))
    except OSError as failure:
        return Observation(failure.errno)


def read_binary_node(entry: str, policy: ipe.Policy | None, observed: list[str]) -> Observation:
    """Read a binary node as hex and report whether it existed."""
    try:
        observed.append(ipe.node_path(entry, policy).read_bytes().hex())
        return Observation(0, observed=tuple(observed))
    except OSError as failure:
        return Observation(failure.errno)


def write_opened_file_and_read(
    entry: str,
    policy: ipe.Policy | None,
    data: bytes,
    descriptor: list[int],
    observed: list[str],
) -> Observation:
    """Write through a previously opened fd, then read the node back."""
    observation = write_opened_file(data, descriptor)
    observed.append(ipe.node_path(entry, policy).read_text().strip())
    return Observation(observation.errno, observed=tuple(observed))


def write_opened_file(data: bytes, descriptor: list[int]) -> Observation:
    """Write to an already-opened fd, testing what happens after a late capability change."""
    try:
        os.write(descriptor[0], data)
        return Observation(0)
    except OSError as failure:
        return Observation(failure.errno)
