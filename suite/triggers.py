# SPDX-License-Identifier: GPL-2.0-only

import os

import ipe
from model import CaseState, Observation


def error_observation(error: OSError) -> Observation:
    """Turn an OS failure with an errno into an observation."""
    if error.errno is None:
        raise error
    return Observation(errno=error.errno)


def write_node(
    entry: str,
    policy: ipe.Policy | None,
    data: bytes,
    _state: CaseState,
) -> Observation:
    """Write data to a securityfs node and report the errno."""
    descriptor = os.open(ipe.node_path(entry, policy), os.O_WRONLY)
    try:
        os.write(descriptor, data)
        return Observation(errno=0)
    except OSError as failure:
        return error_observation(failure)
    finally:
        os.close(descriptor)


def write_node_and_read(
    entry: str,
    policy: ipe.Policy | None,
    data: bytes,
    state: CaseState,
) -> Observation:
    """Write to a node and append its resulting value."""
    observation = write_node(entry, policy, data, state)
    state.observed.append(ipe.node_path(entry, policy).read_text().strip())
    return observation


def toggle_node(
    entry: str,
    policy: ipe.Policy | None,
    state: CaseState,
) -> Observation:
    """Flip a boolean node and append its new value."""
    if len(state.observed) != 1:
        raise RuntimeError(f"expected one read, got {len(state.observed)}")
    (current,) = state.observed
    if current not in ("0", "1"):
        raise RuntimeError(f"cannot toggle {current!r}")
    observation = write_node(
        entry,
        policy,
        b"0" if current == "1" else b"1",
        state,
    )
    state.observed.append(ipe.node_path(entry, policy).read_text().strip())
    return observation


def read_node(
    entry: str,
    policy: ipe.Policy | None,
    state: CaseState,
) -> Observation:
    """Read a text node into this case's observations."""
    try:
        state.observed.append(ipe.node_path(entry, policy).read_text().strip())
        return Observation(errno=0)
    except OSError as failure:
        return error_observation(failure)


def read_binary_node(
    entry: str,
    policy: ipe.Policy | None,
    state: CaseState,
) -> Observation:
    """Read a binary node as hex into this case's observations."""
    try:
        state.observed.append(ipe.node_path(entry, policy).read_bytes().hex())
        return Observation(errno=0)
    except OSError as failure:
        return error_observation(failure)


def write_opened_file_and_read(
    entry: str,
    policy: ipe.Policy | None,
    data: bytes,
    state: CaseState,
) -> Observation:
    """Write through this case's open fd, then append the node value."""
    observation = write_opened_file(data, state)
    state.observed.append(ipe.node_path(entry, policy).read_text().strip())
    return observation


def write_opened_file(data: bytes, state: CaseState) -> Observation:
    """Write through the descriptor captured in this case's state."""
    if state.opened_file is None:
        raise RuntimeError("case state holds no open file")
    try:
        os.write(state.opened_file, data)
        return Observation(errno=0)
    except OSError as failure:
        return error_observation(failure)
