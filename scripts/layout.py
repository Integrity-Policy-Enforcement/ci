# SPDX-License-Identifier: GPL-2.0-only
"""Paths and names shared between the build scripts and the test suite.

Both sides import this file, so every path or filename is defined once.
scripts/run-vm.py copies it into the payload alongside the suite.

Guest layout after boot:

    /sys/kernel/security/ipe/          IPE's securityfs tree
    /dev/virtio-ports/ipe-tests-result TAP output collected by scripts/run-vm.py

    /run/ipe-tests/                    payload disk (ext4, mounted rw)
        run-tests                          entry point
        policies/<group>/<name>.{pol,p7s}  signed policy fixtures
        dmverity/                          dm-verity image and its hashes
            dmverity.squashfs                  the squashfs holding the module
            dmverity.hash                      its Merkle tree
            dmverity.roothash                  the root hash (ASCII hex)
            dmverity.p7s                       the root hash signed
        ipe_test.ko                        the module the copies are made from

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

DMVERITY_ASSETS = PAYLOAD / "dmverity"
SQUASHFS = "dmverity.squashfs"
HASH_TREE = "dmverity.hash"
ROOT_HASH = "dmverity.roothash"
SIGNATURE = "dmverity.p7s"

TEST_MODULE = "ipe_test"
TEST_MODULE_FILE = f"{TEST_MODULE}.ko"

MEDIA = Path("/run/ipe-media")

DMVERITY_SIGNED_DEVICE = "ipe-dmverity-signed"
DMVERITY_SIGNED_MOUNT = MEDIA / "dmverity-signed"
DMVERITY_UNSIGNED_DEVICE = "ipe-dmverity-unsigned"
DMVERITY_UNSIGNED_MOUNT = MEDIA / "dmverity-unsigned"

PLAIN_MOUNT = MEDIA / "plain"
