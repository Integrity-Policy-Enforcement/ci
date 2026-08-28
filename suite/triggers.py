# SPDX-License-Identifier: GPL-2.0-only

import os

import ipe
from model import Observation


def write_node(entry: str, policy: ipe.Policy | None, data: bytes) -> Observation:
    descriptor = os.open(ipe.node_path(entry, policy), os.O_WRONLY)
    try:
        os.write(descriptor, data)
        return Observation(0)
    except OSError as failure:
        return Observation(failure.errno)
    finally:
        os.close(descriptor)


def write_node_and_read(
    entry: str, policy: ipe.Policy | None, data: bytes, values: list[str]
) -> Observation:
    observation = write_node(entry, policy, data)
    values.append(ipe.node_path(entry, policy).read_text().strip())
    return Observation(observation.errno, values)


def toggle_node(entry: str, policy: ipe.Policy | None, values: list[str]) -> Observation:
    if len(values) != 1:
        raise RuntimeError(f"expected one read, got {len(values)}")
    (current,) = values
    if current not in ("0", "1"):
        raise RuntimeError(f"cannot toggle {current!r}")
    observation = write_node(entry, policy, b"0" if current == "1" else b"1")
    values.append(ipe.node_path(entry, policy).read_text().strip())
    return Observation(observation.errno, values)


def read_node(entry: str, policy: ipe.Policy | None, values: list[str]) -> Observation:
    try:
        values.append(ipe.node_path(entry, policy).read_text().strip())
        return Observation(0, values)
    except OSError as failure:
        return Observation(failure.errno)


def read_binary_node(entry: str, policy: ipe.Policy | None, values: list[str]) -> Observation:
    try:
        values.append(ipe.node_path(entry, policy).read_bytes().hex())
        return Observation(0, values)
    except OSError as failure:
        return Observation(failure.errno)


def write_opened_file_and_read(
    entry: str,
    policy: ipe.Policy | None,
    data: bytes,
    descriptor: list[int],
    values: list[str],
) -> Observation:
    observation = write_opened_file(data, descriptor)
    values.append(ipe.node_path(entry, policy).read_text().strip())
    return Observation(observation.errno, values)


def write_opened_file(data: bytes, descriptor: list[int]) -> Observation:
    try:
        os.write(descriptor[0], data)
        return Observation(0)
    except OSError as failure:
        return Observation(failure.errno)
