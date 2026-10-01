# SPDX-License-Identifier: GPL-2.0-only
"""Interpreter file and stdin cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    interpreter_fsverity_digest_policy,
)
from model import Case
from operations import interpreter


def cases() -> tuple[Case, ...]:
    """Return this operation's cases."""
    return (
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: '+' script with a verified built-in fs-verity signature over the script digest; open the script path in the interpreter.
        # Match: script property matches -> check errno 0 -> interpret and print 1.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_file_fsverity_signature_true_{algorithm}_signed_ok',
                policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                script=layout.guest.fsverity_interpreter_test_script(algorithm=algorithm),
                from_stdin=False,
                expected_errno=0,
                expected_returncode=0,
                expected_output='1\n',
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: identical '+' script without the required file property; open the script path in the interpreter.
        # Match: no script property match -> EACCES -> no interpretation or stdout.
        interpreter.interpreter_case(
            id='execute_bprm_creds_for_exec_interpreter_file_fsverity_signature_true_plain_denied',
            policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            script=layout.guest.FSVERITY_PLAIN_INTERPRETER_TEST_SCRIPT,
            from_stdin=False,
            expected_errno=errno.EACCES,
            expected_returncode=1,
            expected_output='',
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: '+' script with a verified built-in fs-verity signature over the script digest; pass its original fd as stdin.
        # Match: script property matches -> check errno 0 -> interpret and print 1.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_stdin_fsverity_signature_true_{algorithm}_signed_ok',
                policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                script=layout.guest.fsverity_interpreter_test_script(algorithm=algorithm),
                from_stdin=True,
                expected_errno=0,
                expected_returncode=0,
                expected_output='1\n',
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: identical '+' script without the required file property; pass its original fd as stdin.
        # Match: no script property match -> EACCES -> no interpretation or stdout.
        interpreter.interpreter_case(
            id='execute_bprm_creds_for_exec_interpreter_stdin_fsverity_signature_true_plain_denied',
            policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            script=layout.guest.FSVERITY_PLAIN_INTERPRETER_TEST_SCRIPT,
            from_stdin=True,
            expected_errno=errno.EACCES,
            expected_returncode=1,
            expected_output='',
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: '+' script with signed fs-verity and a matching script digest; open the script path in the interpreter.
        # Match: script property matches -> check errno 0 -> interpret and print 1.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_file_fsverity_digest_{algorithm}_signed_ok',
                policy=interpreter_fsverity_digest_policy(algorithm=algorithm),
                script=layout.guest.fsverity_interpreter_test_script(algorithm=algorithm),
                from_stdin=False,
                expected_errno=0,
                expected_returncode=0,
                expected_output='1\n',
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: identical '+' script without the required file property; open the script path in the interpreter.
        # Match: no script property match -> EACCES -> no interpretation or stdout.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_file_fsverity_digest_{algorithm}_plain_denied',
                policy=interpreter_fsverity_digest_policy(algorithm=algorithm),
                script=layout.guest.FSVERITY_PLAIN_INTERPRETER_TEST_SCRIPT,
                from_stdin=False,
                expected_errno=errno.EACCES,
                expected_returncode=1,
                expected_output='',
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: '+' script with signed fs-verity and a matching script digest; pass its original fd as stdin.
        # Match: script property matches -> check errno 0 -> interpret and print 1.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_stdin_fsverity_digest_{algorithm}_signed_ok',
                policy=interpreter_fsverity_digest_policy(algorithm=algorithm),
                script=layout.guest.fsverity_interpreter_test_script(algorithm=algorithm),
                from_stdin=True,
                expected_errno=0,
                expected_returncode=0,
                expected_output='1\n',
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: identical '+' script without the required file property; pass its original fd as stdin.
        # Match: no script property match -> EACCES -> no interpretation or stdout.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_stdin_fsverity_digest_{algorithm}_plain_denied',
                policy=interpreter_fsverity_digest_policy(algorithm=algorithm),
                script=layout.guest.FSVERITY_PLAIN_INTERPRETER_TEST_SCRIPT,
                from_stdin=True,
                expected_errno=errno.EACCES,
                expected_returncode=1,
                expected_output='',
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
