# SPDX-License-Identifier: GPL-2.0-only

from . import policy
from . import policy_signature
from . import policy_text
from . import securityfs


def build():
    batches = []
    for module in (securityfs, policy, policy_signature, policy_text):
        batches.extend(module.build())
    ids = [case.id for batch in batches for case in batch.cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case id")
    return tuple(batches)
