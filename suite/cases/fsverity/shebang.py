# SPDX-License-Identifier: GPL-2.0-only
"""Shebang script execution cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    SHEBANG_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    shebang_fsverity_digest_policy,
)
from model import Case

from .. import execute


def cases() -> tuple[Case, ...]:
    """Return this operation's cases."""
    return (
        # Shebang cases exec test-media/execute/shebang.sh directly. IPE checks the
        # script at bprm_check; /bin/sh from '#!' and its ELF loader and shared
        # libraries are the guest root's bash, permitted by the signed-root
        # dmverity_signature=TRUE rule. The script copies on the payload disk cannot
        # match that rule, so only the property under test can allow them.
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /bin/sh on the
        #         signed root; ALLOW fsverity_signature=TRUE.
        # Input: execve a '#!/bin/sh' script with a verified built-in fs-verity signature.
        # Match: fsverity_signature=TRUE matches the script; the signed-root rule matches /bin/sh -> ALLOW; exit 0.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_shebang_"
                    f"fsverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=SHEBANG_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_shebang_test_script(algorithm=algorithm),
                expected_errno=0,
                expected_returncode=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /bin/sh on the
        #         signed root; ALLOW fsverity_signature=TRUE.
        # Input: execve the identical script without fs-verity on the payload disk.
        # Match: the script matches no rule -> default DENY -> EACCES; /bin/sh never starts.
        execute.execve_case(
            id="execute_bprm_check_execve_shebang_fsverity_signature_true_plain_denied",
            policy=SHEBANG_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_SHEBANG_TEST_SCRIPT,
            expected_errno=errno.EACCES,
            expected_returncode=None,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /bin/sh on the
        #         signed root; ALLOW the script's exact fsverity_digest.
        # Input: execve the '#!/bin/sh' script copy with fs-verity and a built-in signature
        #        ("signed" in the ID). No fsverity_signature rule exists here, so only its
        #        digest can allow it.
        # Match: the digest rule matches the script; the signed-root rule matches /bin/sh -> ALLOW; exit 0.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_shebang_"
                    f"fsverity_digest_{algorithm}_signed_ok"
                ),
                policy=shebang_fsverity_digest_policy(algorithm=algorithm),
                binary=layout.guest.fsverity_shebang_test_script(algorithm=algorithm),
                expected_errno=0,
                expected_returncode=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE for /bin/sh on the
        #         signed root; ALLOW the script's exact fsverity_digest.
        # Input: execve the identical script without fs-verity on the payload disk.
        # Match: the script matches no rule -> default DENY -> EACCES; /bin/sh never starts.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_shebang_"
                    f"fsverity_digest_{algorithm}_plain_denied"
                ),
                policy=shebang_fsverity_digest_policy(algorithm=algorithm),
                binary=layout.guest.FSVERITY_PLAIN_SHEBANG_TEST_SCRIPT,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
