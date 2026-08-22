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
