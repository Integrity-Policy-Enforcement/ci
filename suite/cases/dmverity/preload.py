# SPDX-License-Identifier: GPL-2.0-only
"""LD_PRELOAD library cases using dm-verity properties."""

import hashes
import layout
from assets import (
    EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    preload_dmverity_roothash_policy,
)
from model import Case
from operations import preload


def cases() -> tuple[Case, ...]:
    """Return this operation's cases."""
    return (
        # LD_PRELOAD cases run /usr/bin/true with LD_PRELOAD naming preload.so, built
        # from test-programs/preload-library.c. IPE checks three components:
        #   1. /usr/bin/true, at bprm_check;
        #   2. its ELF loader and libc, at their executable mmaps;
        #   3. preload.so, when the loader maps it executable: only the property
        #      under test can allow it.
        # 1 and 2 are the guest root's coreutils (declared in image/mkosi.conf) and
        # glibc. mkosi builds that root with a signed dm-verity root hash
        # (Verity=signed), so the dmverity_signature=TRUE rule in every preload
        # policy permits them. When IPE denies 3, the loader reports the failed
        # mapping, skips preload.so and still runs /usr/bin/true, which exits 0.
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        #         The same rule permits /usr/bin/true and its runtime on the signed root.
        # Input: LD_PRELOAD a library on dm-verity with a verified root-hash signature.
        # Match: dmverity_signature=TRUE matches the library -> ALLOW; its constructor
        #        prints "preload"; exit 0.
        *(
            preload.preload_case(
                id=(
                    "execute_mmap_ld_preload_"
                    f"dmverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                library=layout.guest.dmverity_preload_library(
                    algorithm=algorithm, signed=True
                ),
                expected_preloaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        #         The same rule permits /usr/bin/true and its runtime on the signed root.
        # Input: LD_PRELOAD the identical library from plain tmpfs, without dm-verity.
        # Match: the library matches no rule -> default DENY -> the loader cannot map
        #        it, reports that and skips it; no "preload"; exit 0.
        preload.preload_case(
            id="execute_mmap_ld_preload_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            library=layout.guest.PLAIN_PRELOAD_LIBRARY,
            expected_preloaded=False,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /usr/bin/true
        #         on the signed root; ALLOW the matching dmverity_roothash.
        # Input: LD_PRELOAD a library on unsigned dm-verity with a matching root hash.
        # Match: the root-hash rule matches the library -> ALLOW; its constructor
        #        prints "preload"; exit 0.
        *(
            preload.preload_case(
                id=(
                    "execute_mmap_ld_preload_"
                    f"dmverity_roothash_{algorithm}_unsigned_ok"
                ),
                policy=preload_dmverity_roothash_policy(algorithm=algorithm),
                library=layout.guest.dmverity_preload_library(
                    algorithm=algorithm, signed=False
                ),
                expected_preloaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /usr/bin/true
        #         on the signed root; ALLOW the matching dmverity_roothash.
        # Input: LD_PRELOAD the identical library from plain tmpfs, without dm-verity.
        # Match: the library matches no rule -> default DENY -> the loader cannot map
        #        it, reports that and skips it; no "preload"; exit 0.
        *(
            preload.preload_case(
                id=(
                    "execute_mmap_ld_preload_"
                    f"dmverity_roothash_{algorithm}_plain_denied"
                ),
                policy=preload_dmverity_roothash_policy(algorithm=algorithm),
                library=layout.guest.PLAIN_PRELOAD_LIBRARY,
                expected_preloaded=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
