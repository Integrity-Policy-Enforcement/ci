# SPDX-License-Identifier: GPL-2.0-only
"""The absolute paths the build scripts and the test suite agree on.

Both sides import this file, so each is written once.  scripts/run-vm.py
copies it into the payload alongside the suite.  mkosi copies it into
the initrd.

source: where a file lives in this checkout.
build: what the build scripts make from it.

    build/
      keys/                       prepare-keys.py
        builtin-key.pem           private key that signs policies and root hashes
        builtin-cert.pem          self-signed CA certificate built into the kernel
        module-signing.pem        builtin key and certificate joined for the kernel
        intermediate-key.pem      private key for the intermediate CA
        intermediate-cert.pem     certificate signed by builtin; issues secondary
        secondary-key.pem         private key for the secondary identity
        secondary-cert.pem        certificate signed by intermediate
        revoked-key.pem           private key for the revoked identity
        revoked-cert.pem          self-signed certificate built into the blacklist
        untrusted-key.pem         private key for the untrusted identity
        untrusted-cert.pem        self-signed certificate in no trusted keyring
        secureboot-key.pem        private key for the Secure Boot identity
        secureboot-cert.pem       certificate enrolled in the UEFI db
        fsverity-key.pem          private key that signs fs-verity digests
        fsverity-cert.pem         certificate added to .fs-verity by the initrd
        fsverity-cert.der         DER encoding of fsverity-cert.pem for keyctl
      kernel/                     build-kernel.py, an in-tree build
      kernel-install/             its modules_install staging
      kernel-modules/             build-kernel-modules.py
        ipe_test.ko               binary loaded by the KMODULE cases
      dmverity/                   build-dmverity-image.py
        dmverity.squashfs         squashfs used by the dm-verity cases
        dmverity-sha256.hash      sha256 Merkle tree over dmverity.squashfs
        dmverity-sha256.roothash  root of the sha256 tree, as ASCII hex
        dmverity-sha256.p7s       builtin signature over the sha256 root hash
        dmverity-sha512.hash      sha512 Merkle tree over dmverity.squashfs
        dmverity-sha512.roothash  root of the sha512 tree, as ASCII hex
        dmverity-sha512.p7s       builtin signature over the sha512 root hash
      fsverity/                   build-fsverity-signature.py
        ipe_test-sha256.digest    sha256 digest of ipe_test.ko, as ASCII hex
        ipe_test-sha256.p7s       fsverity signature over the sha256 digest
        ipe_test-sha512.digest    sha512 digest of ipe_test.ko, as ASCII hex
        ipe_test-sha512.p7s       fsverity signature over the sha512 digest
      policies/                   source policy tree copied, expanded and signed
        signers/intermediate.der  DER certificate linked by the keyring case

initrd: what boots before the real root, and what it leaves behind.

    /usr/lib/ipe/
        fsverity-cert.der                  added before .fs-verity is sealed
    /usr/lib/ipe-tests/                the suite and layout.py; the boot path uses:
        ipe_test.ko                        the module the cases load
        boot-verified-true.p7s             allow KMODULE when boot_verified
        boot-verified-false.p7s            deny KMODULE when it is false
    /run/ipe-boot-verified             how each initramfs case came out
    /run/ipe-boot-verified-tmpfs       a mount that is not the initramfs

guest: what the tests find after the switch.

    /usr/lib/ipe/
        root-policy.p7s                    activated once the verified root is up
    /sys/kernel/security/ipe/          IPE's securityfs tree
    /dev/virtio-ports/ipe-tests-result TAP output collected by scripts/run-vm.py

    /run/ipe-tests/                    payload disk (ext4, mounted rw)
        run-tests.py                       entry point
        layout.py                          absolute paths in the guest
        hashes.py                          the two measurement algorithms
        kernel-modules/                    kernel module test binaries
            ipe_test.ko                        KMODULE test binary
        policies/                         signed copy of the source policy tree
        dmverity/                          dm-verity image and its hashes
            dmverity.squashfs                  the squashfs holding the module
            dmverity-sha256.hash               sha256 Merkle tree
            dmverity-sha256.roothash           root of the sha256 tree
            dmverity-sha256.p7s                signature over the sha256 root hash
            dmverity-sha512.hash               sha512 Merkle tree
            dmverity-sha512.roothash           root of the sha512 tree
            dmverity-sha512.p7s                signature over the sha512 root hash
        fsverity/                          fs-verity digests and signatures
            ipe_test-sha256.digest             sha256 digest of ipe_test.ko
            ipe_test-sha256.p7s                signature over the sha256 digest
            ipe_test-sha512.digest             sha512 digest of ipe_test.ko
            ipe_test-sha512.p7s                signature over the sha512 digest
        fsverity-modules/                  a batch writes these, a scope removes
            signed-sha256-ipe_test.ko          sha256 fs-verity digest and signature
            unsigned-sha256-ipe_test.ko        sha256 fs-verity digest, no signature
            signed-sha512-ipe_test.ko          sha512 fs-verity digest and signature
            unsigned-sha512-ipe_test.ko        sha512 fs-verity digest, no signature
            plain-ipe_test.ko                  fs-verity not enabled

    /run/ipe-media/                    test mounts (batch creates, scope removes)
        dmverity-sha256-signed/            sha256 tree, signature passed while opening
        dmverity-sha256-unsigned/          sha256 tree, no signature argument
        dmverity-sha512-signed/            sha512 tree, signature passed while opening
        dmverity-sha512-unsigned/          sha512 tree, no signature argument
        plain/                             tmpfs, no block device at all
"""

from pathlib import Path

_KMODULE_TEST_BINARY_NAME = "ipe_test.ko"
_DMVERITY_DIR_NAME = "dmverity"
_FSVERITY_DIR_NAME = "fsverity"
_POLICIES_DIR_NAME = "policies"
_SIGNERS_DIR_NAME = "signers"
_FSVERITY_CERTIFICATE_NAME = "fsverity-cert.der"
_INTERMEDIATE_CERTIFICATE_NAME = "intermediate.der"

_SECONDARY_POLICY = Path("policy_signature/secondary.pol")
_PLATFORM_POLICY = Path("policy_signature/platform.pol")
_REVOKED_POLICY = Path("policy_signature/revoked.pol")
_UNTRUSTED_POLICY = Path("policy_signature/untrusted.pol")
_TAMPERED_POLICY = Path("policy_signature/tampered.pol")


def _hash_tree_name(algorithm: str) -> str:
    return f"dmverity-{algorithm}.hash"


def _root_hash_name(algorithm: str) -> str:
    return f"dmverity-{algorithm}.roothash"


def _root_hash_signature_name(algorithm: str) -> str:
    return f"dmverity-{algorithm}.p7s"


def _fsverity_signature_name(algorithm: str) -> str:
    return f"ipe_test-{algorithm}.p7s"


def _fsverity_digest_name(algorithm: str) -> str:
    return f"ipe_test-{algorithm}.digest"


class test_media:
    """Paths relative to a test-media root."""

    KERNEL_MODULES_DIR = Path("kernel-modules")
    KMODULE_TEST_BINARY = KERNEL_MODULES_DIR / _KMODULE_TEST_BINARY_NAME


class source:
    ROOT_DIR = Path(__file__).resolve().parent.parent

    SCRIPTS_DIR = ROOT_DIR / "scripts"
    LAYOUT_MODULE = SCRIPTS_DIR / "layout.py"
    HASHES_MODULE = SCRIPTS_DIR / "hashes.py"
    SUITE_DIR = ROOT_DIR / "suite"
    IMAGE_DIR = ROOT_DIR / "image"
    POLICIES_DIR = ROOT_DIR / "policies"
    KERNEL_MODULES_DIR = ROOT_DIR / "kernel-modules"
    KERNEL_CONFIG = ROOT_DIR / "config" / "ipe-tests.config"
    BOOT_POLICY = ROOT_DIR / "config" / "boot-policy.pol"

    SECONDARY_POLICY_TEXT = POLICIES_DIR / _SECONDARY_POLICY
    PLATFORM_POLICY_TEXT = POLICIES_DIR / _PLATFORM_POLICY
    REVOKED_POLICY_TEXT = POLICIES_DIR / _REVOKED_POLICY
    UNTRUSTED_POLICY_TEXT = POLICIES_DIR / _UNTRUSTED_POLICY
    TAMPERED_POLICY_TEXT = POLICIES_DIR / _TAMPERED_POLICY


class build:
    ROOT_DIR = source.ROOT_DIR / "build"

    KEYS_DIR = ROOT_DIR / "keys"
    FSVERITY_CERTIFICATE = KEYS_DIR / _FSVERITY_CERTIFICATE_NAME

    KERNEL_DIR = ROOT_DIR / "kernel"
    KERNEL_STAGING_DIR = ROOT_DIR / "kernel-install"
    KERNEL_CONFIG = KERNEL_DIR / ".config"

    KERNEL_MODULES_DIR = ROOT_DIR / test_media.KERNEL_MODULES_DIR
    KMODULE_TEST_BINARY = ROOT_DIR / test_media.KMODULE_TEST_BINARY

    POLICIES_DIR = ROOT_DIR / _POLICIES_DIR_NAME
    SECONDARY_POLICY_TEXT = (
        POLICIES_DIR / source.SECONDARY_POLICY_TEXT.relative_to(source.POLICIES_DIR)
    )
    PLATFORM_POLICY_TEXT = (
        POLICIES_DIR / source.PLATFORM_POLICY_TEXT.relative_to(source.POLICIES_DIR)
    )
    REVOKED_POLICY_TEXT = (
        POLICIES_DIR / source.REVOKED_POLICY_TEXT.relative_to(source.POLICIES_DIR)
    )
    UNTRUSTED_POLICY_TEXT = (
        POLICIES_DIR / source.UNTRUSTED_POLICY_TEXT.relative_to(source.POLICIES_DIR)
    )
    TAMPERED_POLICY_TEXT = (
        POLICIES_DIR / source.TAMPERED_POLICY_TEXT.relative_to(source.POLICIES_DIR)
    )
    SIGNER_CERTIFICATES_DIR = POLICIES_DIR / _SIGNERS_DIR_NAME
    INTERMEDIATE_CERTIFICATE = SIGNER_CERTIFICATES_DIR / _INTERMEDIATE_CERTIFICATE_NAME

    DMVERITY_ASSETS_DIR = ROOT_DIR / _DMVERITY_DIR_NAME
    SQUASHFS = DMVERITY_ASSETS_DIR / "dmverity.squashfs"

    @staticmethod
    def hash_tree(algorithm: str) -> Path:
        """The Merkle tree the build made with this hash."""
        return build.DMVERITY_ASSETS_DIR / _hash_tree_name(algorithm)

    @staticmethod
    def root_hash(algorithm: str) -> Path:
        """The root hash for the Merkle tree built with this hash."""
        return build.DMVERITY_ASSETS_DIR / _root_hash_name(algorithm)

    @staticmethod
    def root_hash_signature(algorithm: str) -> Path:
        """The builtin identity signature over this root hash."""
        return build.DMVERITY_ASSETS_DIR / _root_hash_signature_name(algorithm)

    FSVERITY_ASSETS_DIR = ROOT_DIR / _FSVERITY_DIR_NAME

    @staticmethod
    def fsverity_signature(algorithm: str) -> Path:
        """The fs-verity identity signature over this digest."""
        return build.FSVERITY_ASSETS_DIR / _fsverity_signature_name(algorithm)

    @staticmethod
    def fsverity_digest(algorithm: str) -> Path:
        """The test module digest made with this hash."""
        return build.FSVERITY_ASSETS_DIR / _fsverity_digest_name(algorithm)

    GUEST_IMAGE = source.IMAGE_DIR / "output" / "ipe-tests.raw"


class guest:
    # ipe-root-policy.service reads /usr/lib/ipe/root-policy.p7s directly.
    IPE_DIR = Path("/usr/lib/ipe")
    ROOT_POLICY = IPE_DIR / "root-policy.p7s"

    RESULT_CHANNEL = Path("/dev/virtio-ports/ipe-tests-result")
    SECURITYFS_DIR = Path("/sys/kernel/security/ipe")

    PAYLOAD_DIR = Path("/run/ipe-tests")
    RUNNER = PAYLOAD_DIR / "run-tests.py"
    LAYOUT_MODULE = PAYLOAD_DIR / "layout.py"
    HASHES_MODULE = PAYLOAD_DIR / "hashes.py"
    KERNEL_MODULES_DIR = PAYLOAD_DIR / test_media.KERNEL_MODULES_DIR
    KMODULE_TEST_BINARY = PAYLOAD_DIR / test_media.KMODULE_TEST_BINARY

    POLICIES_DIR = PAYLOAD_DIR / _POLICIES_DIR_NAME

    @staticmethod
    def policy_signature(asset: str) -> Path:
        """The absolute path to a policy's signature in the guest."""
        return guest.POLICIES_DIR / f"{asset}.p7s"

    SECONDARY_POLICY_SIGNATURE = (POLICIES_DIR / _SECONDARY_POLICY).with_suffix(".p7s")
    PLATFORM_POLICY_SIGNATURE = (POLICIES_DIR / _PLATFORM_POLICY).with_suffix(".p7s")
    REVOKED_POLICY_SIGNATURE = (POLICIES_DIR / _REVOKED_POLICY).with_suffix(".p7s")
    UNTRUSTED_POLICY_SIGNATURE = (POLICIES_DIR / _UNTRUSTED_POLICY).with_suffix(".p7s")
    TAMPERED_POLICY_TEXT = POLICIES_DIR / _TAMPERED_POLICY
    TAMPERED_POLICY_SIGNATURE = TAMPERED_POLICY_TEXT.with_suffix(".p7s")
    TAMPERED_POLICY_REPLACEMENT = TAMPERED_POLICY_TEXT.with_suffix(".replacement")
    SIGNER_CERTIFICATES_DIR = POLICIES_DIR / _SIGNERS_DIR_NAME
    INTERMEDIATE_CERTIFICATE = SIGNER_CERTIFICATES_DIR / _INTERMEDIATE_CERTIFICATE_NAME

    DMVERITY_ASSETS_DIR = PAYLOAD_DIR / _DMVERITY_DIR_NAME
    SQUASHFS = DMVERITY_ASSETS_DIR / "dmverity.squashfs"

    @staticmethod
    def hash_tree(algorithm: str) -> Path:
        """The guest path to the Merkle tree built with this hash."""
        return guest.DMVERITY_ASSETS_DIR / _hash_tree_name(algorithm)

    @staticmethod
    def root_hash(algorithm: str) -> Path:
        """The guest path to the root hash for this Merkle tree."""
        return guest.DMVERITY_ASSETS_DIR / _root_hash_name(algorithm)

    @staticmethod
    def root_hash_signature(algorithm: str) -> Path:
        """The guest path to the signature over this root hash."""
        return guest.DMVERITY_ASSETS_DIR / _root_hash_signature_name(algorithm)

    FSVERITY_ASSETS_DIR = PAYLOAD_DIR / _FSVERITY_DIR_NAME

    @staticmethod
    def fsverity_signature(algorithm: str) -> Path:
        """The guest path to the signature over this digest."""
        return guest.FSVERITY_ASSETS_DIR / _fsverity_signature_name(algorithm)

    FSVERITY_MODULES_DIR = PAYLOAD_DIR / "fsverity-modules"
    FSVERITY_PLAIN_KMODULE_TEST_BINARY = (
        FSVERITY_MODULES_DIR / f"plain-{_KMODULE_TEST_BINARY_NAME}"
    )

    @staticmethod
    def fsverity_unsigned_kmodule_test_binary(algorithm: str) -> Path:
        """The KMODULE test binary with unsigned fs-verity enabled."""
        return (
            guest.FSVERITY_MODULES_DIR
            / f"unsigned-{algorithm}-{_KMODULE_TEST_BINARY_NAME}"
        )

    @staticmethod
    def fsverity_signed_kmodule_test_binary(algorithm: str) -> Path:
        """The KMODULE test binary with signed fs-verity enabled."""
        return (
            guest.FSVERITY_MODULES_DIR
            / f"signed-{algorithm}-{_KMODULE_TEST_BINARY_NAME}"
        )

    MEDIA_DIR = Path("/run/ipe-media")

    @staticmethod
    def dmverity_mount_dir(algorithm: str, signed: bool) -> Path:
        """The mount point for this hash and signature state."""
        state = "signed" if signed else "unsigned"
        return guest.MEDIA_DIR / f"dmverity-{algorithm}-{state}"

    @staticmethod
    def dmverity_kmodule_test_binary(algorithm: str, signed: bool) -> Path:
        """The KMODULE test binary on a mounted dm-verity image."""
        return (
            guest.dmverity_mount_dir(algorithm, signed)
            / test_media.KMODULE_TEST_BINARY
        )

    PLAIN_MOUNT_DIR = MEDIA_DIR / "plain"
    PLAIN_KMODULE_TEST_BINARY = PLAIN_MOUNT_DIR / test_media.KMODULE_TEST_BINARY


class initrd:
    # anchor-fsverity.service reads /usr/lib/ipe/fsverity-cert.der directly.
    IPE_DIR = Path("/usr/lib/ipe")
    FSVERITY_CERTIFICATE = IPE_DIR / _FSVERITY_CERTIFICATE_NAME

    TESTS_DIR = Path("/usr/lib/ipe-tests")
    KMODULE_TEST_BINARY = TESTS_DIR / _KMODULE_TEST_BINARY_NAME
    KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY_SIGNATURE = (
        TESTS_DIR / "boot-verified-true.p7s"
    )
    KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY_SIGNATURE = (
        TESTS_DIR / "boot-verified-false.p7s"
    )

    BOOT_VERIFIED_RECORD = Path("/run/ipe-boot-verified")
    BOOT_TMPFS_DIR = Path("/run/ipe-boot-verified-tmpfs")
    BOOT_TMPFS_KMODULE_TEST_BINARY = BOOT_TMPFS_DIR / _KMODULE_TEST_BINARY_NAME
