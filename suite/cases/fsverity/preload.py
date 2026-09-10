# SPDX-License-Identifier: GPL-2.0-only
"""LD_PRELOAD library cases using fs-verity properties."""

import hashes
import layout
from assets import (
    PRELOAD_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    preload_fsverity_digest_policy,
)
from model import Case

from .. import execute_preload


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; fsverity_signature=TRUE permits the library; signed root permits the runtime.
        # Input: library on the unsigned payload with a verified built-in fs-verity digest signature.
        # Match: library ALLOW -> constructor prints preload; the client exits zero.
        *(
            execute_preload.preload_case(
                id=f'execute_mmap_ld_preload_fsverity_signature_true_{algorithm}_signed_ok',
                policy=PRELOAD_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                library=layout.guest.fsverity_preload_library(algorithm=algorithm),
                expected_returncode=0,
                expected_preloaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; fsverity_signature=TRUE permits the library; signed root permits the runtime.
        # Input: identical library bytes without either permitted property.
        # Match: library default DENY -> no constructor output; loader refuses its segment mapping.
        execute_preload.preload_case(
            id='execute_mmap_ld_preload_fsverity_signature_true_plain_denied',
            policy=PRELOAD_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            library=layout.guest.FSVERITY_PLAIN_PRELOAD_LIBRARY,
            expected_returncode=0,
            expected_preloaded=False,
        ),
        # Policy: EXECUTE default DENY; matching fsverity_digest permits the library; signed root permits the runtime.
        # Input: library on the unsigned payload with signed fs-verity and a matching digest.
        # Match: library ALLOW -> constructor prints preload; the client exits zero.
        *(
            execute_preload.preload_case(
                id=f'execute_mmap_ld_preload_fsverity_digest_{algorithm}_signed_ok',
                policy=preload_fsverity_digest_policy(algorithm=algorithm),
                library=layout.guest.fsverity_preload_library(algorithm=algorithm),
                expected_returncode=0,
                expected_preloaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; matching fsverity_digest permits the library; signed root permits the runtime.
        # Input: identical library bytes without either permitted property.
        # Match: library default DENY -> no constructor output; loader refuses its segment mapping.
        *(
            execute_preload.preload_case(
                id=f'execute_mmap_ld_preload_fsverity_digest_{algorithm}_plain_denied',
                policy=preload_fsverity_digest_policy(algorithm=algorithm),
                library=layout.guest.FSVERITY_PLAIN_PRELOAD_LIBRARY,
                expected_returncode=0,
                expected_preloaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
