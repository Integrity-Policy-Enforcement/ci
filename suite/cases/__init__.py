# SPDX-License-Identifier: GPL-2.0-only

from . import boot
from . import dmverity
from . import fsverity
from . import policy
from . import policy_signature
from . import policy_text
from . import securityfs


def build():
    batches = []
    for module in (securityfs, policy, policy_signature, policy_text, dmverity, fsverity, boot):
        batches.extend(module.build())
    for batch in batches:
        for case in batch.cases:
            if not case.trigger and not case.check:
                raise ValueError(f"case {case.id} asserts nothing")
    ids = [case.id for batch in batches for case in batch.cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case id")
    return tuple(batches)
