# SPDX-License-Identifier: GPL-2.0-only
"""The signing identities prepare-keys.py makes, and the files it writes for each.

An identity called builtin owns build/keys/builtin-key.pem and its certificate
beside it as builtin-cert.pem.  scripts/prepare-keys.py lists every file the
seven of them come to.
"""

from dataclasses import dataclass
from pathlib import Path

import layout


@dataclass(frozen=True)
class Identity:
    name: str

    @property
    def key(self) -> Path:
        return layout.build.KEYS / f"{self.name}-key.pem"

    @property
    def certificate(self) -> Path:
        return layout.build.KEYS / f"{self.name}-cert.pem"


BUILTIN = Identity("builtin")
INTERMEDIATE = Identity("intermediate")
SECONDARY = Identity("secondary")
REVOKED = Identity("revoked")
UNTRUSTED = Identity("untrusted")
SECUREBOOT = Identity("secureboot")
FSVERITY = Identity("fsverity")

# The kernel build wants one file holding both, so this one is not an identity
# in the sense above.
MODULE_SIGNING = layout.build.KEYS / "module-signing.pem"
