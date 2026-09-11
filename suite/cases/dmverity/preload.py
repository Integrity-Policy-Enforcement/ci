# SPDX-License-Identifier: GPL-2.0-only
"""LD_PRELOAD library cases using dm-verity properties."""

import hashes
import layout
from assets import (
    EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    preload_dmverity_roothash_policy,
)
from model import Case
from operations import preload as execute_preload


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; dmverity_signature=TRUE permits both the root runtime and the library.
        # Input: library on dm-verity with a verified root-hash signature.
        # Match: library ALLOW -> constructor prints preload; the client exits zero.
        *(
            execute_preload.preload_case(
                id=f'execute_mmap_ld_preload_dmverity_signature_true_{algorithm}_signed_ok',
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                library=layout.guest.dmverity_preload_library(algorithm=algorithm, signed=True),
                expected_returncode=0,
                expected_preloaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; dmverity_signature=TRUE permits both the root runtime and the library.
        # Input: identical library bytes without either permitted property.
        # Match: library default DENY -> no constructor output; loader refuses its segment mapping.
        execute_preload.preload_case(
            id='execute_mmap_ld_preload_dmverity_signature_true_plain_denied',
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            library=layout.guest.PLAIN_PRELOAD_LIBRARY,
            expected_returncode=0,
            expected_preloaded=False,
        ),
        # Policy: EXECUTE default DENY; matching dmverity_roothash permits the library; signed root permits the runtime.
        # Input: library on matching unsigned dm-verity, so the signed-root allowance cannot match it.
        # Match: library ALLOW -> constructor prints preload; the client exits zero.
        *(
            execute_preload.preload_case(
                id=f'execute_mmap_ld_preload_dmverity_roothash_{algorithm}_unsigned_ok',
                policy=preload_dmverity_roothash_policy(algorithm=algorithm),
                library=layout.guest.dmverity_preload_library(algorithm=algorithm, signed=False),
                expected_returncode=0,
                expected_preloaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; matching dmverity_roothash permits the library; signed root permits the runtime.
        # Input: identical library bytes without either permitted property.
        # Match: library default DENY -> no constructor output; loader refuses its segment mapping.
        *(
            execute_preload.preload_case(
                id=f'execute_mmap_ld_preload_dmverity_roothash_{algorithm}_plain_denied',
                policy=preload_dmverity_roothash_policy(algorithm=algorithm),
                library=layout.guest.PLAIN_PRELOAD_LIBRARY,
                expected_returncode=0,
                expected_preloaded=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
