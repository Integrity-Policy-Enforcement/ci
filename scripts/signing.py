# SPDX-License-Identifier: GPL-2.0-only
"""The signing identities prepare-keys.py makes, and the files it writes for each.

    build/keys/<name>-key.pem     the private key
    build/keys/<name>-cert.pem    its certificate
    build/keys/<name>-cert.der    the same certificate, where a keyring wants DER
"""

from dataclasses import dataclass

import layout


@dataclass(frozen=True)
class Identity:
    name: str

    @property
    def key(self):
        return layout.build.KEYS / f"{self.name}-key.pem"

    @property
    def certificate(self):
        return layout.build.KEYS / f"{self.name}-cert.pem"

    @property
    def certificate_der(self):
        return layout.build.KEYS / f"{self.name}-cert.der"


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
