# SPDX-License-Identifier: GPL-2.0-only
"""Hash algorithms exercised for each verity mechanism."""

DMVERITY_ALGORITHMS = (
    "blake2b-512",
    "md4",
    "md5",
    "rmd160",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3-224",
    "sha3-256",
    "sha3-384",
    "sha3-512",
    "sm3",
)
# The fs-verity ABI defines only SHA-256 and SHA-512.
FSVERITY_ALGORITHMS = ("sha256", "sha512")
