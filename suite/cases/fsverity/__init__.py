# SPDX-License-Identifier: GPL-2.0-only
"""The fs-verity batch: shared setup, scopes and explicit case order."""

from functools import partial

import files
import hashes
import ipe
import layout
import modules
from command import run
from execute_memfd import hugepages_scope
from model import Batch

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

# Here "signed" means fs-verity's built-in signature, not module signing.
# For DER inputs it is not the certificate issuer signature.
# Signed and unsigned files both have fs-verity enabled; plain files do not.
# For .ko.gz, the signed fs-verity digest is computed from compressed bytes.


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="fsverity",
            cases=(
                # Preserve TAP order; declarations live in per-operation modules.
                *x509.cases(),
                *policy_op.cases(),
                *kexec_initramfs.cases(),
                *kexec_image.cases(),
                *firmware.cases(),
                *kmodule.cases(),
                *execute.cases(),
                *mmap.cases(),
                *mprotect.cases(),
                *interpreter.cases(),
                *memfd.cases(),
                *preload.cases(),
            ),
            # Prepare fixtures with enforcement off; each case then activates
            # its selected policy and enables enforcement for its operation.
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
                        files.prepare_fsverity_test_binary,
                        source=(
                            layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY
                            if compressed
                            else layout.guest.KMODULE_TEST_BINARY
                        ),
                        target=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=compressed
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_signature(
                            algorithm=algorithm, compressed=compressed
                        ),
                    )
                    for compressed in (False, True)
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Unsigned still runs fsverity enable; signature=None omits --signature.
                # The plain copies below skip fsverity enable entirely.
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=(
                            layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY
                            if compressed
                            else layout.guest.KMODULE_TEST_BINARY
                        ),
                        target=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm, compressed=compressed
                        ),
                        algorithm=algorithm,
                    )
                    for compressed in (False, True)
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_COMPRESSED_KMODULE_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KMODULE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.FIRMWARE_TEST_BINARY,
                        target=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_firmware_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.FIRMWARE_TEST_BINARY,
                        target=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.FIRMWARE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_FIRMWARE_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        target=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_kexec_image_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        target=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_KEXEC_IMAGE_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.KEXEC_INITRAMFS_TEST_BINARY,
                        target=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_kexec_initramfs_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.KEXEC_INITRAMFS_TEST_BINARY,
                        target=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KEXEC_INITRAMFS_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.POLICY_OP_TEST_BINARY,
                        target=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_policy_op_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.POLICY_OP_TEST_BINARY,
                        target=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.POLICY_OP_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_POLICY_OP_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.X509_TEST_BINARY,
                        target=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_x509_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.X509_TEST_BINARY,
                        target=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.X509_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_X509_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.EXECUTE_TEST_BINARY,
                        target=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_execute_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.EXECUTE_TEST_BINARY,
                        target=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.EXECUTE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.SCRIPT_TEST_BINARY,
                        target=layout.guest.fsverity_script_test_binary(algorithm=algorithm),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_script_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.SCRIPT_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_SCRIPT_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.SHEBANG_TEST_SCRIPT,
                        target=layout.guest.fsverity_shebang_test_script(algorithm=algorithm),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_shebang_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.SHEBANG_TEST_SCRIPT,
                    target=layout.guest.FSVERITY_PLAIN_SHEBANG_TEST_SCRIPT,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.MEMFD_TEST_BINARY,
                        target=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_memfd_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.PRELOAD_LIBRARY,
                        target=layout.guest.fsverity_preload_library(algorithm=algorithm),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_preload_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.PRELOAD_LIBRARY,
                    target=layout.guest.FSVERITY_PLAIN_PRELOAD_LIBRARY,
                ),
            ),
            extra_scopes=(
                hugepages_scope,
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_EXECUTE_DIR,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_MODULES_DIR,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_FIRMWARE_DIR,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_KEXEC_IMAGES_DIR,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_POLICY_OP_DIR,
                ),
                partial(
                    modules.loaded_scope,
                    prefix=layout.guest.POLICY_OP_TEST_MODULE.stem,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_X509_DIR,
                ),
                partial(
                    modules.loaded_scope,
                    prefix=layout.guest.X509_TEST_MODULE.stem,
                ),
            ),
        ),
    )
