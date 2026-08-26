# IPE CI

This project builds and boots a Fedora image for testing Integrity Policy Enforcement (IPE).

The image follows a production-style trust chain:

- the kernel contains a built-in IPE boot policy;
- mkosi builds a Unified Kernel Image (UKI) signed for UEFI Secure Boot;
- the Fedora root filesystem is protected by signed dm-verity;
- the boot policy allows execution only from the verified initramfs or the signed dm-verity root.

The built-in IPE policy denies `EXECUTE` by default. It allows execution when IPE reports `boot_verified=TRUE` or `dmverity_signature=TRUE`. In this image, those properties cover the initramfs before `switch_root` and the signed dm-verity root afterwards.

`run.py` creates test keys, signs IPE policies, builds the kernel, checks the final kernel configuration, builds the image, boots it with QEMU, and evaluates the TAP results returned by the guest.

## Usage

Clone the repositories and build the container image:

```sh
git clone https://github.com/Integrity-Policy-Enforcement/ci.git
cd ci
git clone https://github.com/Integrity-Policy-Enforcement/linux.git kernel
podman build -t ipe-ci .
```

### One-shot run

```sh
podman run --rm --privileged --device /dev/kvm \
    -v "$PWD/kernel:/kernel:z" -v "$PWD/out:/work/out:z" \
    ipe-ci /kernel /work/out
```

Results land in `out/verdict.json`, `out/console.log`, and `out/result.log`.

### Development

Use the container to keep toolchain versions consistent with CI (a different
systemd on the host can silently change whether an initrd unit gets enabled,
for example).  Keep one running with the repository and kernel bind-mounted
so edits take effect immediately:

```sh
podman run -d --name ipe-build --privileged --device /dev/kvm --group-add keep-groups \
    -v "$PWD:/work:z" -v "$PWD/kernel:/kernel:z" \
    --entrypoint sleep ipe-ci infinity
```

Then run only the step a change reaches:

```sh
podman exec ipe-build sh -c 'cd /work && python3 scripts/run-vm.py out'           # suite/
podman exec ipe-build sh -c 'cd /work && mkosi --directory image -f build'        # image/
podman exec ipe-build sh -c 'cd /work && python3 scripts/build-kernel.py /kernel' # kernel config
podman exec ipe-build sh -c 'cd /work && ./run.py /kernel out'                    # full run
```

`--group-add keep-groups` gives QEMU access to `/dev/kvm`; without it the
guest falls back to emulation.  Package downloads are cached in
`build/mkosi-cache` and persist across container restarts.

This image configuration can also serve as a small reference for building an IPE system with Secure Boot, a signed UKI, a signed dm-verity root, and a restrictive boot policy.
