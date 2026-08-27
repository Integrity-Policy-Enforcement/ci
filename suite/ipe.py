# SPDX-License-Identifier: GPL-2.0-only

import errno
import os
from dataclasses import dataclass
from pathlib import Path

# security/ipe/fs.c and security/ipe/policy_fs.c create IPE_ROOT's securityfs tree.
IPE_ROOT = Path("/sys/kernel/security/ipe")
POLICY_ROOT = Path("/run/ipe-tests/policies")


@dataclass(frozen=True)
class Policy:
    """A signed policy and the name the kernel will know it by."""

    signed: Path
    name: str


def policy_path(name):
    return IPE_ROOT / "policies" / name


def node_path(node, policy=None):
    return IPE_ROOT / node if policy is None else policy_path(policy) / node


def write(path, data):
    payload = data.encode() if isinstance(data, str) else data
    descriptor = os.open(path, os.O_WRONLY)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def policy_asset(name, suffix=".pol"):
    return POLICY_ROOT / f"{name}{suffix}"


def signed_policy(name):
    return policy_asset(name, ".p7s").read_bytes()


def policy_names():
    return frozenset(path.name for path in node_path("policies").iterdir() if path.is_dir())


def policy_present(name):
    return policy_path(name).is_dir()


def policy_version(name):
    try:
        return node_path("version", name).read_text().strip()
    except OSError:
        return None


def policy_active(name):
    return node_path("active", name).read_text().strip() == "1"


def deploy_policy(signed):
    write(node_path("new_policy"), signed.read_bytes())


def activate_policy(name):
    if node_path("active", name).read_text().strip() != "1":
        write(node_path("active", name), "1")


def delete_policy(name):
    if policy_present(name):
        write(node_path("delete", name), "1")
    if policy_present(name):
        raise RuntimeError(f"policy {name} was not deleted")


def set_enforcement(enabled):
    write(node_path("enforce"), "1" if enabled else "0")


def set_success_audit(enabled):
    write(node_path("success_audit"), "1" if enabled else "0")


def load_baseline(asset, name):
    expected = policy_asset(asset).read_bytes().rstrip(b"\n")
    if policy_present(name):
        loaded = node_path("policy", name).read_bytes().rstrip(b"\n")
        if loaded != expected:
            raise RuntimeError(f"loaded policy {name} differs from {asset}.pol")
    else:
        try:
            deploy_policy(policy_asset(asset, ".p7s"))
        except OSError as failure:
            if failure.errno != errno.EEXIST:
                raise
    activate_policy(name)
    return name
