# SPDX-License-Identifier: GPL-2.0-only
"""The dm-verity batch: shared setup, scopes and explicit case order."""

import shutil
from functools import partial

import hashes
import ipe
import layout
from command import run
from model import Batch
from resources import files, modules, mounts

from . import (
    execute,
    firmware,
    interpreter,
    kexec_image,
    kexec_initramfs,
    kmodule,
    memfd,
    mmap,
    mprotect,
    policy_op,
    preload,
    x509,
)

# Signed/unsigned refers to the mapping's root-hash signature, not an
# embedded module signature or a signature attached to an input file.
# It also does not refer to the issuer signature inside an X.509 certificate.

# dm-verity mappings under this prefix are reserved for batch cleanup.
DMVERITY_DEVICE_PREFIX = "ipe-dmverity-"


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="dmverity",
            cases=(
                # Preserve TAP order; declarations live in per-operation modules.
                *execute.signature_true_cases(),
                *x509.cases(),
                *policy_op.cases(),
                *kexec_initramfs.cases(),
                *kexec_image.cases(),
                *firmware.cases(),
                *kmodule.cases(),
                *execute.signature_false_cases(),
                *execute.roothash_cases(),
                *mmap.cases(),
                *mprotect.cases(),
                *interpreter.cases(),
                *memfd.cases(),
                *preload.cases(),
            ),
            setup=(
                partial(ipe.set_enforcement, enabled=False),
                partial(
                    files.prepare_fsverity_test_binary,
                    source=layout.guest.INTERPRETER_TEST_BINARY,
                    target=layout.guest.FSVERITY_INTERPRETER_TEST_BINARY,
                    algorithm=layout.INTERPRETER_HASH,
                ),
                partial(run, "insmod", layout.guest.POLICY_OP_TEST_MODULE),
                partial(run, "insmod", layout.guest.X509_TEST_MODULE),
                *(
                    partial(
                        mounts.dmverity,
                        prefix=DMVERITY_DEVICE_PREFIX,
                        algorithm=algorithm,
                        signed=signed,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                    for signed in (True, False)
                ),
                partial(mounts.tmpfs, point=layout.guest.PLAIN_MOUNT_DIR),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KMODULE_TEST_BINARY,
                    target=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                ),
                partial(
                    layout.guest.PLAIN_FIRMWARE_TEST_BINARY.parent.mkdir,
                    parents=True,
                    exist_ok=True,
                ),
                partial(
                    shutil.copy,
                    src=layout.guest.FIRMWARE_TEST_BINARY,
                    dst=layout.guest.PLAIN_FIRMWARE_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                    target=layout.guest.PLAIN_KEXEC_IMAGE_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KEXEC_INITRAMFS_TEST_BINARY,
                    target=layout.guest.PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.POLICY_OP_TEST_BINARY,
                    target=layout.guest.PLAIN_POLICY_OP_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.X509_TEST_BINARY,
                    target=layout.guest.PLAIN_X509_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.EXECUTE_TEST_BINARY,
                    target=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.SCRIPT_TEST_BINARY,
                    target=layout.guest.PLAIN_SCRIPT_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.SHEBANG_TEST_SCRIPT,
                    target=layout.guest.PLAIN_SHEBANG_TEST_SCRIPT,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.PRELOAD_LIBRARY,
                    target=layout.guest.PLAIN_PRELOAD_LIBRARY,
                ),
            ),
            extra_scopes=(
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_EXECUTE_DIR,
                ),
                partial(
                    mounts.dmverity_scope,
                    prefix=DMVERITY_DEVICE_PREFIX,
                ),
                partial(
                    mounts.mounted_scope,
                    directory=layout.guest.MEDIA_DIR,
                ),
                partial(
                    modules.loaded_scope,
                    prefix=layout.guest.POLICY_OP_TEST_MODULE.stem,
                ),
                partial(
                    modules.loaded_scope,
                    prefix=layout.guest.X509_TEST_MODULE.stem,
                ),
            ),
        ),
    )
