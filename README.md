# IPE CI

This project builds and boots a Fedora image for testing Integrity Policy Enforcement (IPE).

The image follows a production-style trust chain:

- the kernel contains a built-in IPE boot policy;
- mkosi builds a Unified Kernel Image (UKI) signed for UEFI Secure Boot;
- the Fedora root filesystem is protected by signed dm-verity;
- the boot policy allows execution only from the verified initramfs or the signed dm-verity root.

The built-in IPE policy denies `EXECUTE` by default. It allows execution when IPE reports `boot_verified=TRUE` or `dmverity_signature=TRUE`. In this image, those properties cover the initramfs before `switch_root` and the signed dm-verity root afterwards.

`run.py` creates test keys, signs IPE policies, builds the kernel, checks the final kernel configuration, builds the image, boots it with QEMU, and evaluates the TAP results returned by the guest.

## Run with Podman

Start with an IPE kernel tree that is ready to build:

```sh
export KERNEL=/path/to/linux
sudo podman build -t ipe-ci .
mkdir -p out
sudo podman run --rm --privileged --device /dev/kvm \
    -v "$KERNEL:/kernel:ro,Z" \
    -v "$PWD/out:/work/out:Z" \
    ipe-ci /kernel /work/out
```

The result is written to `out/verdict.json`. Detailed boot and test evidence is stored in `out/console.log` and `out/result.log`.

This image configuration can also serve as a small reference for building an IPE system with Secure Boot, a signed UKI, a signed dm-verity root, and a restrictive boot policy.
