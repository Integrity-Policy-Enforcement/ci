# SPDX-License-Identifier: GPL-2.0-only
"""The absolute paths the build scripts and the test suite agree on.

Both sides import this file, so each is written once.  scripts/run-vm.py
copies it into the payload alongside the suite.  mkosi copies it into
the initrd.

source: where a file lives in this checkout.
build: what the build scripts make from it.

    build/
      keys/                       prepare-keys.py
        builtin-key.pem           the CA the kernel trusts
        builtin-cert.pem          this is what the kernel is built to trust
        module-signing.pem        key and certificate joined, for the kernel
        intermediate-key.pem      issued by builtin, issues secondary
        intermediate-cert.pem
        secondary-key.pem         trusted only once linked into a keyring
        secondary-cert.pem
        revoked-key.pem           on the kernel blacklist
        revoked-cert.pem
        untrusted-key.pem         issued by nobody the kernel knows
        untrusted-cert.pem
        secureboot-key.pem        enrolled in the UEFI db
        secureboot-cert.pem
        fsverity-key.pem          added to .fs-verity from the initrd
        fsverity-cert.pem
        fsverity-cert.der         the form keyctl takes, and the only DER here
      kernel/                     build-kernel.py, an in-tree build
      kernel-install/             its modules_install staging
      kernel-module/              build-kernel-module.py
        ipe_test.ko
      dmverity/                   build-dmverity-image.py
        dmverity.squashfs         holds ipe_test.ko, nothing else
        dmverity-sha256.hash      the Merkle tree veritysetup formatted
        dmverity-sha256.roothash  its root hash, as ASCII hex
        dmverity-sha256.p7s       that root hash signed by builtin
        dmverity-sha512.hash      the same three, over the same image
        dmverity-sha512.roothash
        dmverity-sha512.p7s
      fsverity/                   build-fsverity-signature.py
        ipe_test-sha256.digest    the module's digest, as ASCII hex
        ipe_test-sha256.p7s       that digest signed by fsverity
        ipe_test-sha512.digest
        ipe_test-sha512.p7s
      policies/                   prepare-policies.py, signed and expanded
        <group>/<name>.pol        the policy, placeholders replaced
        <group>/<name>.p7s        it signed
        signers/intermediate.der  the certificate a keyring case links

initrd: what boots before the real root, and what it leaves behind.

    /usr/lib/ipe-tests/                the suite, layout.py, hashes.py and:
        ipe_test.ko                        the module the cases load
        boot-verified-true.p7s             allow KMODULE when boot_verified
        boot-verified-false.p7s            deny KMODULE when it is false
        root-policy.p7s                    activated once the root is up
        fsverity-cert.der                  added to .fs-verity, then closed
    /run/ipe-boot-verified             how each initramfs case came out
    /run/ipe-boot-verified-tmpfs       a mount that is not the initramfs

guest: what the tests find after the switch.

    /sys/kernel/security/ipe/          IPE's securityfs tree
    /dev/virtio-ports/ipe-tests-result TAP output collected by scripts/run-vm.py

    /run/ipe-tests/                    payload disk (ext4, mounted rw)
        run-tests                          entry point
        layout.py                          absolute paths in the guest
        hashes.py                          the two measurement algorithms
        policies/                         signed copy of the source policy tree
        dmverity/                          dm-verity image and its hashes
            dmverity.squashfs                  the squashfs holding the module
            dmverity-sha256.hash               its Merkle tree
            dmverity-sha256.roothash           that tree's root hash (ASCII hex)
            dmverity-sha256.p7s                that root hash signed
            dmverity-sha512.hash               the same three, over the same image
            dmverity-sha512.roothash
            dmverity-sha512.p7s
        fsverity/                          fs-verity digests and signatures
            ipe_test-sha256.digest             the digest, as ASCII hex
            ipe_test-sha256.p7s                that digest signed
            ipe_test-sha512.digest
            ipe_test-sha512.p7s
        ipe_test.ko                        the module the copies are made from
        fsverity-modules/                  a batch writes these, a scope removes
            signed-sha256-ipe_test.ko          fsverity enable --signature
            unsigned-sha256-ipe_test.ko        fsverity enable, no signature
            signed-sha512-ipe_test.ko
            unsigned-sha512-ipe_test.ko
            plain-ipe_test.ko                  untouched

    /run/ipe-media/                    test mounts (batch creates, scope removes)
        dmverity-sha256-signed/            squashfs via --root-hash-signature
        dmverity-sha256-unsigned/          same squashfs, no signature argument
        dmverity-sha512-signed/            the tree the other hash built
        dmverity-sha512-unsigned/
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
    TAMPERED_POLICY_SIGNATURE = (POLICIES / _TAMPERED_POLICY).with_suffix(".p7s")
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
    ROOT = Path("/usr/lib/ipe-tests")

    TEST_MODULE = ROOT / _TEST_MODULE_NAME
    BOOT_VERIFIED_TRUE_POLICY = ROOT / "boot-verified-true.p7s"
    BOOT_VERIFIED_FALSE_POLICY = ROOT / "boot-verified-false.p7s"
    ROOT_POLICY = ROOT / "root-policy.p7s"
    FSVERITY_CERTIFICATE = ROOT / _FSVERITY_CERTIFICATE_NAME

    BOOT_VERIFIED_RECORD = Path("/run/ipe-boot-verified")
    BOOT_TMPFS_DIRECTORY = Path("/run/ipe-boot-verified-tmpfs")
    BOOT_TMPFS_MODULE = BOOT_TMPFS_DIRECTORY / _TEST_MODULE_NAME
