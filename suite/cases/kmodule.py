# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import checks
import ipe
import modules
import runtime
import steps
from model import Case
from operations import KMODULE
from scope import Collection


def case(id, policy, module, allowed):
    return Case(
        id=id,
        setup=(
            partial(steps.activate_policy, policy),
            partial(ipe.set_enforcement, True),
        ),
        trigger=partial(KMODULE.attempt, module),
        expect=0 if allowed else KMODULE.refused,
        check=partial(checks.operation_completed_is, KMODULE, allowed),
        scope=partial(runtime.case.scope, Collection(modules.loaded, modules.remove)),
    )
