# SPDX-License-Identifier: GPL-2.0-only

import os

import ipe
from model import Observation


def write_node(node, policy, data):
    descriptor = os.open(ipe.node_path(node, policy), os.O_WRONLY)
    try:
        os.write(descriptor, data)
        return Observation(0)
    except OSError as failure:
        return Observation(failure.errno)
    finally:
        os.close(descriptor)


def read_node(node, policy, values):
    try:
        values.append(ipe.node_path(node, policy).read_text().strip())
        return Observation(0, values)
    except OSError as failure:
        return Observation(failure.errno)


def write_opened_file(data, descriptor):
    try:
        os.write(descriptor[0], data)
        return Observation(0)
    except OSError as failure:
        return Observation(failure.errno)
