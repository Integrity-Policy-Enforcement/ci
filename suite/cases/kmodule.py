# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import ipe
import layout
import modules
import steps
from model import Case, CaseState, Observation

# insmod reports a failed insertion with process return code 1, not an errno.
INSMOD_REFUSED_RETURN_CODE = 1
# This exact target name also reserves its prefix for case cleanup.
KMODULE_TEST_BINARY_NAME = layout.guest.KMODULE_TEST_BINARY.stem


def call_insmod(binary: Path, state: CaseState) -> Observation:
    """Try insmod and return what happened, without raising."""
    finished = modules.insmod(binary)
    return Observation(
        returncode=finished.returncode,
        message=finished.stderr.strip(),
    )


def call_init_module(binary: Path, state: CaseState) -> Observation:
    """Pass a module binary to init_module and report its errno."""
    return Observation(errno=modules.init_module_from_buffer(binary.read_bytes()))


def insmod_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_returncode: int,
    expected_loaded: bool,
) -> Case:
    """Run insmod and check its return code and the module's loaded state."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(call_insmod, binary=binary),
        checks=(
            partial(
                checks.returncode_is,
                expected=expected_returncode,
            ),
            partial(
                modules.check_loaded,
                name=KMODULE_TEST_BINARY_NAME,
                expected_loaded=expected_loaded,
            ),
        ),
        extra_scopes=(
            partial(modules.loaded_scope, prefix=KMODULE_TEST_BINARY_NAME),
        ),
    )


def init_module_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_errno: int,
    expected_loaded: bool,
) -> Case:
    """Run init_module and check its errno and the module's loaded state."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(
            call_init_module,
            binary=binary,
        ),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(
                modules.check_loaded,
                name=KMODULE_TEST_BINARY_NAME,
                expected_loaded=expected_loaded,
            ),
        ),
        extra_scopes=(
            partial(modules.loaded_scope, prefix=KMODULE_TEST_BINARY_NAME),
        ),
    )
