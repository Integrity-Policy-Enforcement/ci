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
    """Return this operation's cases."""
    return (
        # LD_PRELOAD cases run /usr/bin/true with LD_PRELOAD naming a copy of
        # preload.so. IPE checks /usr/bin/true at bprm_check and its ELF loader and
        # libc at their executable mmaps; all three are on the guest root and are
        # permitted by the signed-root dmverity_signature=TRUE rule. The library
        # copies on the payload disk cannot match that rule, so only the property
        # under test can allow the loader to map them.
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /usr/bin/true
        #         on the signed root; ALLOW fsverity_signature=TRUE.
        # Input: LD_PRELOAD a library with a verified built-in fs-verity signature.
        # Match: fsverity_signature=TRUE matches the library -> ALLOW; its constructor
        #        prints "preload"; exit 0.
        *(
            execute_preload.preload_case(
                id=(
                    "execute_mmap_ld_preload_"
                    f"fsverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=PRELOAD_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                library=layout.guest.fsverity_preload_library(algorithm=algorithm),
                expected_preloaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /usr/bin/true
        #         on the signed root; ALLOW fsverity_signature=TRUE.
        # Input: LD_PRELOAD the identical library without fs-verity on the payload disk.
        # Match: the library matches no rule -> default DENY -> the loader cannot map
        #        it, reports that and skips it; no "preload"; exit 0.
        execute_preload.preload_case(
            id="execute_mmap_ld_preload_fsverity_signature_true_plain_denied",
            policy=PRELOAD_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            library=layout.guest.FSVERITY_PLAIN_PRELOAD_LIBRARY,
            expected_preloaded=False,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /usr/bin/true
        #         on the signed root; ALLOW the library's exact fsverity_digest.
        # Input: LD_PRELOAD the library copy with fs-verity and a built-in signature
        #        ("signed" in the ID). No fsverity_signature rule exists here, so only
        #        its digest can allow it.
        # Match: the digest rule matches the library -> ALLOW; its constructor prints
        #        "preload"; exit 0.
        *(
            execute_preload.preload_case(
                id=(
                    "execute_mmap_ld_preload_"
                    f"fsverity_digest_{algorithm}_signed_ok"
                ),
                policy=preload_fsverity_digest_policy(algorithm=algorithm),
                library=layout.guest.fsverity_preload_library(algorithm=algorithm),
                expected_preloaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /usr/bin/true
        #         on the signed root; ALLOW the library's exact fsverity_digest.
        # Input: LD_PRELOAD the identical library without fs-verity on the payload disk.
        # Match: the library matches no rule -> default DENY -> the loader cannot map
        #        it, reports that and skips it; no "preload"; exit 0.
        *(
            execute_preload.preload_case(
                id=(
                    "execute_mmap_ld_preload_"
                    f"fsverity_digest_{algorithm}_plain_denied"
                ),
                policy=preload_fsverity_digest_policy(algorithm=algorithm),
                library=layout.guest.FSVERITY_PLAIN_PRELOAD_LIBRARY,
                expected_preloaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
