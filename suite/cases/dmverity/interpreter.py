# SPDX-License-Identifier: GPL-2.0-only
"""Interpreter file and stdin cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    INTERPRETER_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    interpreter_dmverity_roothash_policy,
)
from model import Case
from operations import interpreter


def cases() -> tuple[Case, ...]:
    """Return this operation's cases."""
    return (
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE;
        #         a separate exact fs-verity digest permits only the interpreter.
        # Input: '+' script path on dm-verity with a verified root-hash signature.
        # Match: the script signature is TRUE -> check returns 0 -> interpret '+'.
        *(
            interpreter.interpreter_case(
                id=(
                    "execute_bprm_creds_for_exec_interpreter_file_"
                    f"dmverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=INTERPRETER_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                script=layout.guest.dmverity_interpreter_test_script(
                    algorithm=algorithm, signed=True
                ),
                from_stdin=False,
                expected_errno=0,
                expected_returncode=0,
                expected_output="1\n",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: identical '+' script without the required file property; open the script path in the interpreter.
        # Match: no script property match -> EACCES -> no interpretation or stdout.
        interpreter.interpreter_case(
            id='execute_bprm_creds_for_exec_interpreter_file_dmverity_signature_true_plain_denied',
            policy=INTERPRETER_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            script=layout.guest.PLAIN_INTERPRETER_TEST_SCRIPT,
            from_stdin=False,
            expected_errno=errno.EACCES,
            expected_returncode=1,
            expected_output='',
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: '+' script with a verified mapping root-hash signature; pass its original fd as stdin.
        # Match: script property matches -> check errno 0 -> interpret and print 1.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_stdin_dmverity_signature_true_{algorithm}_signed_ok',
                policy=INTERPRETER_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                script=layout.guest.dmverity_interpreter_test_script(algorithm=algorithm, signed=True),
                from_stdin=True,
                expected_errno=0,
                expected_returncode=0,
                expected_output='1\n',
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: identical '+' script without the required file property; pass its original fd as stdin.
        # Match: no script property match -> EACCES -> no interpretation or stdout.
        interpreter.interpreter_case(
            id='execute_bprm_creds_for_exec_interpreter_stdin_dmverity_signature_true_plain_denied',
            policy=INTERPRETER_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            script=layout.guest.PLAIN_INTERPRETER_TEST_SCRIPT,
            from_stdin=True,
            expected_errno=errno.EACCES,
            expected_returncode=1,
            expected_output='',
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: '+' script with a matching root hash, without a mapping signature; open the script path in the interpreter.
        # Match: script property matches -> check errno 0 -> interpret and print 1.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_file_dmverity_roothash_{algorithm}_unsigned_ok',
                policy=interpreter_dmverity_roothash_policy(algorithm=algorithm),
                script=layout.guest.dmverity_interpreter_test_script(algorithm=algorithm, signed=False),
                from_stdin=False,
                expected_errno=0,
                expected_returncode=0,
                expected_output='1\n',
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: identical '+' script without the required file property; open the script path in the interpreter.
        # Match: no script property match -> EACCES -> no interpretation or stdout.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_file_dmverity_roothash_{algorithm}_plain_denied',
                policy=interpreter_dmverity_roothash_policy(algorithm=algorithm),
                script=layout.guest.PLAIN_INTERPRETER_TEST_SCRIPT,
                from_stdin=False,
                expected_errno=errno.EACCES,
                expected_returncode=1,
                expected_output='',
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: '+' script with a matching root hash, without a mapping signature; pass its original fd as stdin.
        # Match: script property matches -> check errno 0 -> interpret and print 1.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_stdin_dmverity_roothash_{algorithm}_unsigned_ok',
                policy=interpreter_dmverity_roothash_policy(algorithm=algorithm),
                script=layout.guest.dmverity_interpreter_test_script(algorithm=algorithm, signed=False),
                from_stdin=True,
                expected_errno=0,
                expected_returncode=0,
                expected_output='1\n',
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        #         Only the interpreter has a separate exact fs-verity digest allowance.
        # Input: identical '+' script without the required file property; pass its original fd as stdin.
        # Match: no script property match -> EACCES -> no interpretation or stdout.
        *(
            interpreter.interpreter_case(
                id=f'execute_bprm_creds_for_exec_interpreter_stdin_dmverity_roothash_{algorithm}_plain_denied',
                policy=interpreter_dmverity_roothash_policy(algorithm=algorithm),
                script=layout.guest.PLAIN_INTERPRETER_TEST_SCRIPT,
                from_stdin=True,
                expected_errno=errno.EACCES,
                expected_returncode=1,
                expected_output='',
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
