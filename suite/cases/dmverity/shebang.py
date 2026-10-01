# SPDX-License-Identifier: GPL-2.0-only
"""Shebang script execution cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    shebang_dmverity_roothash_policy,
)
from model import Case

from .. import execute


def cases() -> tuple[Case, ...]:
    """Return this operation's cases."""
    return (
        # Shebang cases exec test-media/execute/shebang.sh directly; there is no
        # test interpreter. IPE checks three components of each exec:
        #   1. the script, at bprm_check: only the property under test can allow it;
        #   2. /bin/sh named by '#!', at the next bprm_check;
        #   3. the ELF loader and shared libraries of /bin/sh, at their executable mmaps.
        # 2 and 3 are the guest root's bash, declared in image/mkosi.conf. mkosi builds
        # that root with a signed dm-verity root hash (Verity=signed), so the
        # dmverity_signature=TRUE rule in every shebang policy permits them.
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        #         The same rule permits /bin/sh and its runtime on the signed root.
        # Input: execve a '#!/bin/sh' script on dm-verity with a verified root-hash signature.
        # Match: dmverity_signature=TRUE matches both the script and /bin/sh -> ALLOW; exit 0.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_shebang_"
                    f"dmverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_shebang_test_script(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_returncode=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        #         The same rule permits /bin/sh and its runtime on the signed root.
        # Input: execve the identical script from plain tmpfs, without dm-verity.
        # Match: the script matches no rule -> default DENY -> EACCES; /bin/sh never starts.
        execute.execve_case(
            id="execute_bprm_check_execve_shebang_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_SHEBANG_TEST_SCRIPT,
            expected_errno=errno.EACCES,
            expected_returncode=None,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /bin/sh on the
        #         signed root; ALLOW the matching dmverity_roothash.
        # Input: execve a '#!/bin/sh' script on unsigned dm-verity with a matching root hash.
        # Match: the root-hash rule matches the script; the signed-root rule matches /bin/sh -> ALLOW; exit 0.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_shebang_"
                    f"dmverity_roothash_{algorithm}_unsigned_ok"
                ),
                policy=shebang_dmverity_roothash_policy(algorithm=algorithm),
                binary=layout.guest.dmverity_shebang_test_script(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=0,
                expected_returncode=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /bin/sh on the
        #         signed root; ALLOW the matching dmverity_roothash.
        # Input: execve the identical script from plain tmpfs, without dm-verity.
        # Match: the script matches no rule -> default DENY -> EACCES; /bin/sh never starts.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_shebang_"
                    f"dmverity_roothash_{algorithm}_plain_denied"
                ),
                policy=shebang_dmverity_roothash_policy(algorithm=algorithm),
                binary=layout.guest.PLAIN_SHEBANG_TEST_SCRIPT,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
