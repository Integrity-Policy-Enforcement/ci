# SPDX-License-Identifier: GPL-2.0-only
"""Every path and name the build scripts and the test suite agree on.

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

    /usr/lib/ipe-tests/                the suite, layout.py and:
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
        policies/<group>/<name>.{pol,p7s}  the policies, and their signatures
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

# What both media are measured with.  veritysetup and fsverity are told to use
# it rather than asked what they picked, so a policy can name it.
HASH_ALGORITHMS = ("sha256", "sha512")
TEST_MODULE = "ipe_test"
TEST_MODULE_FILE = f"{TEST_MODULE}.ko"

# The policies prepare-policies.py signs with a key of their own; the builtin
# key signs the rest, and neither side names those one by one.
SECONDARY_POLICY = "policy_signature/secondary"
PLATFORM_POLICY = "policy_signature/platform"
REVOKED_POLICY = "policy_signature/revoked"
UNTRUSTED_POLICY = "policy_signature/untrusted"
TAMPERED_POLICY = "policy_signature/tampered"

# The keyring cases link a signer's certificate, which the guest can only reach
# if it travels with the policies.
SIGNER_CERTIFICATES = "signers"

# What prepare-policies.py writes beside each policy, and the suite then reads.
POLICY_TEXT_SUFFIX = ".pol"
POLICY_SIGNATURE_SUFFIX = ".p7s"

# Relative to the kernel tree a run is given, not to this checkout.
KERNEL_MERGE_CONFIG = Path("scripts") / "kconfig" / "merge_config.sh"


class guest:
    RESULT_CHANNEL = "/dev/virtio-ports/ipe-tests-result"
    SECURITYFS = Path("/sys/kernel/security/ipe")
    PAYLOAD = Path("/run/ipe-tests")
    RUNNER = PAYLOAD / "run-tests"
    POLICIES = PAYLOAD / "policies"
    DMVERITY_ASSETS = PAYLOAD / "dmverity"
    SQUASHFS = "dmverity.squashfs"

    @staticmethod
    def hash_tree(algorithm: str) -> str:
        return f"dmverity-{algorithm}.hash"

    @staticmethod
    def root_hash(algorithm: str) -> str:
        return f"dmverity-{algorithm}.roothash"

    @staticmethod
    def root_hash_signature(algorithm: str) -> str:
        return f"dmverity-{algorithm}.p7s"

    FSVERITY_ASSETS = PAYLOAD / "fsverity"

    @staticmethod
    def fsverity_signature(algorithm: str) -> str:
        return f"ipe_test-{algorithm}.p7s"

    @staticmethod
    def fsverity_digest(algorithm: str) -> str:
        return f"ipe_test-{algorithm}.digest"

    FSVERITY_MODULES = PAYLOAD / "fsverity-modules"
    FSVERITY_PLAIN_MODULE = FSVERITY_MODULES / f"plain-{TEST_MODULE_FILE}"

    @staticmethod
    def fsverity_unsigned_module(algorithm: str) -> Path:
        return guest.FSVERITY_MODULES / f"unsigned-{algorithm}-{TEST_MODULE_FILE}"

    @staticmethod
    def fsverity_signed_module(algorithm: str) -> Path:
        return guest.FSVERITY_MODULES / f"signed-{algorithm}-{TEST_MODULE_FILE}"

    MEDIA = Path("/run/ipe-media")

    @staticmethod
    def dmverity_device(algorithm: str, signed: bool) -> str:
        return f"ipe-dmverity-{algorithm}-{'signed' if signed else 'unsigned'}"

    @staticmethod
    def dmverity_mount(algorithm: str, signed: bool) -> Path:
        return guest.MEDIA / f"dmverity-{algorithm}-{'signed' if signed else 'unsigned'}"

    PLAIN_MOUNT = MEDIA / "plain"


class initrd:
    ROOT = Path("/usr/lib/ipe-tests")
    BOOT_VERIFIED_RECORD = Path("/run/ipe-boot-verified")
    BOOT_TMPFS_DIRECTORY = Path("/run/ipe-boot-verified-tmpfs")


class source:
    ROOT = Path(__file__).resolve().parent.parent

    SCRIPTS = ROOT / "scripts"
    LAYOUT = SCRIPTS / "layout.py"
    SUITE = ROOT / "suite"
    IMAGE = ROOT / "image"
    POLICIES = ROOT / "policies"
    KERNEL_MODULE = ROOT / "kernel-module" / "ipe-test-module.c"
    KERNEL_CONFIG = ROOT / "config" / "ipe-tests.config"
    BOOT_POLICY = ROOT / "config" / "boot-policy.pol"


class build:
    ROOT = source.ROOT / "build"

    KEYS = ROOT / "keys"
    KERNEL = ROOT / "kernel"
    KERNEL_STAGING = ROOT / "kernel-install"
    KERNEL_CONFIG = KERNEL / ".config"
    KERNEL_MODULE = ROOT / "kernel-module"
    TEST_MODULE = KERNEL_MODULE / TEST_MODULE_FILE
    POLICIES = ROOT / "policies"
    DMVERITY_ASSETS = ROOT / guest.DMVERITY_ASSETS.name
    FSVERITY_ASSETS = ROOT / guest.FSVERITY_ASSETS.name
    GUEST_IMAGE = source.IMAGE / "output" / "ipe-tests.raw"


class output:
    """What a run leaves in the output directory for scripts/verdict.py to read."""

    VM_EXIT_CODE = "vm_exit_code"

    RESULT = "result.log"
    CONSOLE = "console.log"
    PAYLOAD = "payload.raw"
    VERDICT = "verdict.json"
    VM_FACTS = "host.json"
