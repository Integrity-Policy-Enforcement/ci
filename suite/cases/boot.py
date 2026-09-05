# SPDX-License-Identifier: GPL-2.0-only
"""Define the boot_verified cases and expose their saved outcomes to TAP.

IPE evaluates boot_verified for the file being authorized: a file from the
initramfs matches TRUE, while the same file copied to a separate tmpfs matches
FALSE. The initrd program image/initrd/boot-verified.py runs INITRAMFS_CASES
before switch_root and stores their outcomes in /run/ipe-boot-verified.

After switch_root, build() creates reporting-only cases. Each reads one saved
outcome instead of trying to access the removed initramfs files again.
"""

import errno
from functools import partial

import checks
import ipe
import layout
from model import Batch, Case

from . import kmodule

KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY = ipe.Policy(
    signed=layout.initrd.KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY_SIGNATURE,
    name="ipe_test_kmodule_boot_verified_true",
)
KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY = ipe.Policy(
    signed=layout.initrd.KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY_SIGNATURE,
    name="ipe_test_kmodule_boot_verified_false",
)
INITRAMFS_KMODULE_TEST_BINARY = layout.initrd.KMODULE_TEST_BINARY
TMPFS_KMODULE_TEST_BINARY = layout.initrd.BOOT_TMPFS_KMODULE_TEST_BINARY


INITRAMFS_CASES = (
    kmodule.insmod_case(
        id="kmodule_kernel_read_insmod_boot_verified_true_initramfs_ok",
        policy=KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=INITRAMFS_KMODULE_TEST_BINARY,
        expected_returncode=0,
        expected_loaded=True,
    ),
    kmodule.init_module_case(
        id="kmodule_kernel_load_init_module_boot_verified_true_initramfs_denied",
        policy=KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=INITRAMFS_KMODULE_TEST_BINARY,
        expected_errno=errno.EACCES,
        expected_loaded=False,
    ),
    kmodule.insmod_case(
        id="kmodule_kernel_read_insmod_boot_verified_true_tmpfs_denied",
        policy=KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=TMPFS_KMODULE_TEST_BINARY,
        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
        expected_loaded=False,
    ),
    kmodule.insmod_case(
        id="kmodule_kernel_read_insmod_boot_verified_false_initramfs_ok",
        policy=KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=INITRAMFS_KMODULE_TEST_BINARY,
        expected_returncode=0,
        expected_loaded=True,
    ),
    kmodule.init_module_case(
        id="kmodule_kernel_load_init_module_boot_verified_false_initramfs_denied",
        policy=KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=INITRAMFS_KMODULE_TEST_BINARY,
        expected_errno=errno.EACCES,
        expected_loaded=False,
    ),
    kmodule.insmod_case(
        id="kmodule_kernel_read_insmod_boot_verified_false_tmpfs_denied",
        policy=KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=TMPFS_KMODULE_TEST_BINARY,
        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
        expected_loaded=False,
    ),
)


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="boot",
            cases=tuple(
                Case(
                    id=case.id,
                    checks=(partial(checks.initramfs_case_passed, id=case.id),),
                )
                for case in INITRAMFS_CASES
            ),
        ),
    )
