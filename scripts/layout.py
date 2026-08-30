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
      kernel-module/              build-kernel-module.py
        ipe_test.ko               loadable module every KMODULE case attempts
      dmverity/                   build-dmverity-image.py
        dmverity.squashfs         squashfs containing only ipe_test.ko
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
        fsverity-cert.der                  added to .fs-verity, then closed
    /usr/lib/ipe-tests/                the test suite, layout.py, hashes.py and:
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
        run-tests                          entry point
        layout.py                          absolute paths in the guest
        hashes.py                          the two measurement algorithms
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
        ipe_test.ko                        the module the copies are made from
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

_TEST_MODULE_NAME = "ipe_test.ko"
_DMVERITY_DIRECTORY = "dmverity"
_FSVERITY_DIRECTORY = "fsverity"
_POLICY_DIRECTORY = "policies"
_SIGNER_DIRECTORY = "signers"
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


class source:
    ROOT = Path(__file__).resolve().parent.parent

    SCRIPTS = ROOT / "scripts"
    LAYOUT = SCRIPTS / "layout.py"
    HASHES = SCRIPTS / "hashes.py"
    SUITE = ROOT / "suite"
    IMAGE = ROOT / "image"
    POLICIES = ROOT / "policies"
    KERNEL_MODULE = ROOT / "kernel-module" / "ipe-test-module.c"
    KERNEL_CONFIG = ROOT / "config" / "ipe-tests.config"
    BOOT_POLICY = ROOT / "config" / "boot-policy.pol"

    SECONDARY_POLICY_TEXT = POLICIES / _SECONDARY_POLICY
    PLATFORM_POLICY_TEXT = POLICIES / _PLATFORM_POLICY
    REVOKED_POLICY_TEXT = POLICIES / _REVOKED_POLICY
    UNTRUSTED_POLICY_TEXT = POLICIES / _UNTRUSTED_POLICY
    TAMPERED_POLICY_TEXT = POLICIES / _TAMPERED_POLICY


class build:
    ROOT = source.ROOT / "build"

    KEYS = ROOT / "keys"
    FSVERITY_CERTIFICATE = KEYS / _FSVERITY_CERTIFICATE_NAME

    KERNEL = ROOT / "kernel"
    KERNEL_STAGING = ROOT / "kernel-install"
    KERNEL_CONFIG = KERNEL / ".config"

    KERNEL_MODULE = ROOT / "kernel-module"
    TEST_MODULE = KERNEL_MODULE / _TEST_MODULE_NAME

    POLICIES = ROOT / _POLICY_DIRECTORY
    SECONDARY_POLICY_TEXT = (
        POLICIES / source.SECONDARY_POLICY_TEXT.relative_to(source.POLICIES)
    )
    PLATFORM_POLICY_TEXT = (
        POLICIES / source.PLATFORM_POLICY_TEXT.relative_to(source.POLICIES)
    )
    REVOKED_POLICY_TEXT = (
        POLICIES / source.REVOKED_POLICY_TEXT.relative_to(source.POLICIES)
    )
    UNTRUSTED_POLICY_TEXT = (
        POLICIES / source.UNTRUSTED_POLICY_TEXT.relative_to(source.POLICIES)
    )
    TAMPERED_POLICY_TEXT = (
        POLICIES / source.TAMPERED_POLICY_TEXT.relative_to(source.POLICIES)
    )
    SIGNER_CERTIFICATES = POLICIES / _SIGNER_DIRECTORY
    INTERMEDIATE_CERTIFICATE = SIGNER_CERTIFICATES / _INTERMEDIATE_CERTIFICATE_NAME

    DMVERITY_ASSETS = ROOT / _DMVERITY_DIRECTORY
    SQUASHFS = DMVERITY_ASSETS / "dmverity.squashfs"

    @staticmethod
    def hash_tree(algorithm: str) -> Path:
        """The Merkle tree the build made with this hash."""
        return build.DMVERITY_ASSETS / _hash_tree_name(algorithm)

    @staticmethod
    def root_hash(algorithm: str) -> Path:
        """The root hash for the Merkle tree built with this hash."""
        return build.DMVERITY_ASSETS / _root_hash_name(algorithm)

    @staticmethod
    def root_hash_signature(algorithm: str) -> Path:
        """The builtin identity signature over this root hash."""
        return build.DMVERITY_ASSETS / _root_hash_signature_name(algorithm)

    FSVERITY_ASSETS = ROOT / _FSVERITY_DIRECTORY

    @staticmethod
    def fsverity_signature(algorithm: str) -> Path:
        """The fs-verity identity signature over this digest."""
        return build.FSVERITY_ASSETS / _fsverity_signature_name(algorithm)

    @staticmethod
    def fsverity_digest(algorithm: str) -> Path:
        """The test module digest made with this hash."""
        return build.FSVERITY_ASSETS / _fsverity_digest_name(algorithm)

    GUEST_IMAGE = source.IMAGE / "output" / "ipe-tests.raw"


class guest:
    IPE = Path("/usr/lib/ipe")
    ROOT_POLICY = IPE / "root-policy.p7s"

    RESULT_CHANNEL = Path("/dev/virtio-ports/ipe-tests-result")
    SECURITYFS = Path("/sys/kernel/security/ipe")

    PAYLOAD = Path("/run/ipe-tests")
    RUNNER = PAYLOAD / "run-tests"
    TEST_MODULE = PAYLOAD / _TEST_MODULE_NAME

    POLICIES = PAYLOAD / _POLICY_DIRECTORY

    @staticmethod
    def policy_text(asset: str) -> Path:
        """The absolute path to a policy's text in the guest."""
        return guest.POLICIES / f"{asset}.pol"

    @staticmethod
    def policy_signature(asset: str) -> Path:
        """The absolute path to a policy's signature in the guest."""
        return guest.POLICIES / f"{asset}.p7s"

    SECONDARY_POLICY_SIGNATURE = (POLICIES / _SECONDARY_POLICY).with_suffix(".p7s")
    PLATFORM_POLICY_SIGNATURE = (POLICIES / _PLATFORM_POLICY).with_suffix(".p7s")
    REVOKED_POLICY_SIGNATURE = (POLICIES / _REVOKED_POLICY).with_suffix(".p7s")
    UNTRUSTED_POLICY_SIGNATURE = (POLICIES / _UNTRUSTED_POLICY).with_suffix(".p7s")
    TAMPERED_POLICY_TEXT = POLICIES / _TAMPERED_POLICY
    TAMPERED_POLICY_SIGNATURE = TAMPERED_POLICY_TEXT.with_suffix(".p7s")
    TAMPERED_POLICY_REPLACEMENT = TAMPERED_POLICY_TEXT.with_suffix(".replacement")
    SIGNER_CERTIFICATES = POLICIES / _SIGNER_DIRECTORY
    INTERMEDIATE_CERTIFICATE = SIGNER_CERTIFICATES / _INTERMEDIATE_CERTIFICATE_NAME

    DMVERITY_ASSETS = PAYLOAD / _DMVERITY_DIRECTORY
    SQUASHFS = DMVERITY_ASSETS / "dmverity.squashfs"

    @staticmethod
    def hash_tree(algorithm: str) -> Path:
        """The guest path to the Merkle tree built with this hash."""
        return guest.DMVERITY_ASSETS / _hash_tree_name(algorithm)

    @staticmethod
    def root_hash(algorithm: str) -> Path:
        """The guest path to the root hash for this Merkle tree."""
        return guest.DMVERITY_ASSETS / _root_hash_name(algorithm)

    @staticmethod
    def root_hash_signature(algorithm: str) -> Path:
        """The guest path to the signature over this root hash."""
        return guest.DMVERITY_ASSETS / _root_hash_signature_name(algorithm)

    FSVERITY_ASSETS = PAYLOAD / _FSVERITY_DIRECTORY

    @staticmethod
    def fsverity_signature(algorithm: str) -> Path:
        """The guest path to the signature over this digest."""
        return guest.FSVERITY_ASSETS / _fsverity_signature_name(algorithm)

    @staticmethod
    def fsverity_digest(algorithm: str) -> Path:
        """The guest path to the module digest made with this hash."""
        return guest.FSVERITY_ASSETS / _fsverity_digest_name(algorithm)

    FSVERITY_MODULES = PAYLOAD / "fsverity-modules"
    FSVERITY_PLAIN_MODULE = FSVERITY_MODULES / f"plain-{_TEST_MODULE_NAME}"

    @staticmethod
    def fsverity_unsigned_module(algorithm: str) -> Path:
        """The copy with fs-verity enabled without a signature."""
        return guest.FSVERITY_MODULES / f"unsigned-{algorithm}-{_TEST_MODULE_NAME}"

    @staticmethod
    def fsverity_signed_module(algorithm: str) -> Path:
        """The copy with fs-verity enabled with a signature."""
        return guest.FSVERITY_MODULES / f"signed-{algorithm}-{_TEST_MODULE_NAME}"

    MEDIA = Path("/run/ipe-media")

    @staticmethod
    def dmverity_mount(algorithm: str, signed: bool) -> Path:
        """The mount point for this hash and signature state."""
        state = "signed" if signed else "unsigned"
        return guest.MEDIA / f"dmverity-{algorithm}-{state}"

    PLAIN_MOUNT = MEDIA / "plain"


class initrd:
    IPE = Path("/usr/lib/ipe")
    FSVERITY_CERTIFICATE = IPE / _FSVERITY_CERTIFICATE_NAME

    TESTS = Path("/usr/lib/ipe-tests")
    TEST_MODULE = TESTS / _TEST_MODULE_NAME
    BOOT_VERIFIED_TRUE_POLICY = TESTS / "boot-verified-true.p7s"
    BOOT_VERIFIED_FALSE_POLICY = TESTS / "boot-verified-false.p7s"

    BOOT_VERIFIED_RECORD = Path("/run/ipe-boot-verified")
    BOOT_TMPFS_DIRECTORY = Path("/run/ipe-boot-verified-tmpfs")
    BOOT_TMPFS_MODULE = BOOT_TMPFS_DIRECTORY / _TEST_MODULE_NAME
