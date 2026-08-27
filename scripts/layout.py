# SPDX-License-Identifier: GPL-2.0-only
"""Paths and names shared between the build scripts and the test suite.

Both sides import this file, so every path or filename is defined once.
scripts/run-vm.py copies it into the payload alongside the suite.

Guest layout after boot:

    /sys/kernel/security/ipe/          IPE's securityfs tree
    /dev/virtio-ports/ipe-tests-result TAP output collected by scripts/run-vm.py

    /usr/lib/ipe-tests/                initrd: suite, layout.py, policies, module
    /run/ipe-boot-verified             initrd → real root: boot_verified results

    /run/ipe-tests/                    payload disk (ext4, mounted rw)
        run-tests                          entry point
        policies/<group>/<name>.{pol,p7s}  signed policy fixtures
        dmverity/                          dm-verity image and its hashes
            dmverity.squashfs                  the squashfs holding the module
            dmverity.hash                      its Merkle tree
            dmverity.roothash                  the root hash (ASCII hex)
            dmverity.p7s                       the root hash signed
        fsverity/                          fs-verity digest and signature
            ipe_test.digest                    the digest, as ASCII hex
            ipe_test.p7s                       the digest signed
        ipe_test.ko                        the module the copies are made from
        fsverity-modules/                  copies with different fs-verity states
            signed-ipe_test.ko                 fsverity enable --signature
            unsigned-ipe_test.ko               fsverity enable (no signature)
            plain-ipe_test.ko                  untouched

    /run/ipe-media/                    test mounts (batch creates, scope removes)
        dmverity-signed/                   squashfs via veritysetup --root-hash-signature
        dmverity-unsigned/                 same squashfs, no signature argument
        plain/                             tmpfs, no block device at all
"""

from pathlib import Path

# --- VM wiring ---------------------------------------------------------------

RESULT_CHANNEL = "/dev/virtio-ports/ipe-tests-result"
SECURITYFS = Path("/sys/kernel/security/ipe")

# --- payload (ext4 disk, /run/ipe-tests) -------------------------------------

PAYLOAD = Path("/run/ipe-tests")
RUNNER = PAYLOAD / "run-tests"
POLICIES = PAYLOAD / "policies"

# What both media are measured with.  veritysetup and fsverity are told to use
# it rather than asked what they picked, so a policy can name it.
HASH_ALGORITHM = "sha256"
OTHER_HASH_ALGORITHM = "sha512"
HASH_ALGORITHMS = (HASH_ALGORITHM, OTHER_HASH_ALGORITHM)

DMVERITY_ASSETS = PAYLOAD / "dmverity"
SQUASHFS = "dmverity.squashfs"


def hash_tree(algorithm):
    return f"dmverity-{algorithm}.hash"


def root_hash(algorithm):
    return f"dmverity-{algorithm}.roothash"


def root_hash_signature(algorithm):
    return f"dmverity-{algorithm}.p7s"


FSVERITY_ASSETS = PAYLOAD / "fsverity"


def fsverity_signature(algorithm):
    return f"ipe_test-{algorithm}.p7s"


def fsverity_digest(algorithm):
    return f"ipe_test-{algorithm}.digest"

TEST_MODULE = "ipe_test"
TEST_MODULE_FILE = f"{TEST_MODULE}.ko"

FSVERITY_MODULES = PAYLOAD / "fsverity-modules"

FSVERITY_PLAIN_MODULE = FSVERITY_MODULES / f"plain-{TEST_MODULE_FILE}"


def fsverity_unsigned_module(algorithm):
    return FSVERITY_MODULES / f"unsigned-{algorithm}-{TEST_MODULE_FILE}"


def fsverity_signed_module(algorithm):
    return FSVERITY_MODULES / f"signed-{algorithm}-{TEST_MODULE_FILE}"

# --- initrd ------------------------------------------------------------------

INITRD = Path("/usr/lib/ipe-tests")

BOOT_VERIFIED_RECORD = Path("/run/ipe-boot-verified")
BOOT_TMPFS_DIRECTORY = Path("/run/ipe-boot-verified-tmpfs")

# --- test media (/run/ipe-media, scoped to the batch) ------------------------

MEDIA = Path("/run/ipe-media")


def dmverity_device(algorithm, signed):
    return f"ipe-dmverity-{algorithm}-{'signed' if signed else 'unsigned'}"


def dmverity_mount(algorithm, signed):
    return MEDIA / f"dmverity-{algorithm}-{'signed' if signed else 'unsigned'}"


PLAIN_MOUNT = MEDIA / "plain"
