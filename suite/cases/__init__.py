# SPDX-License-Identifier: GPL-2.0-only

from . import policy
from . import securityfs


def build():
    cases = []
    for module in (securityfs, policy):
        cases.extend(module.build())
    ids = [case.id for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case id")
    return tuple(cases)
