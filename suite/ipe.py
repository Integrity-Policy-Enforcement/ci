# SPDX-License-Identifier: GPL-2.0-only

import errno
import os
from dataclasses import dataclass
from pathlib import Path

import layout

IPE_ROOT = layout.guest.SECURITYFS
POLICY_ROOT = layout.guest.POLICIES


@dataclass(frozen=True)
class Policy:
    """The files prepare-policies.py wrote for one policy, and the name it declares."""

    asset: Path
    name: str

    @property
    def text(self) -> Path:
        """The .pol file beside the asset."""
        return self.asset.with_name(self.asset.name + layout.POLICY_TEXT_SUFFIX)

    @property
    def signed(self) -> Path:
        """The .p7s signature beside the asset."""
        return self.asset.with_name(self.asset.name + layout.POLICY_SIGNATURE_SUFFIX)


class node:
    """The entries IPE puts in securityfs, at its root or under one policy."""

    POLICIES = "policies"
    NEW_POLICY = "new_policy"
    ENFORCE = "enforce"
    SUCCESS_AUDIT = "success_audit"

    ACTIVE = "active"
    DELETE = "delete"
    UPDATE = "update"
    VERSION = "version"
    POLICY = "policy"


def policy_path(name: str) -> Path:
    """The directory the kernel created for this policy under securityfs."""
    return IPE_ROOT / node.POLICIES / name


def node_path(entry: str, policy: Policy | None = None) -> Path:
    """A securityfs path: a root entry, or one under a loaded policy."""
    return IPE_ROOT / entry if policy is None else policy_path(policy.name) / entry


def write(path: Path, data: bytes | str) -> None:
    """Write to a securityfs node; open/write/close to match the kernel ABI."""
    payload = data.encode() if isinstance(data, str) else data
    descriptor = os.open(path, os.O_WRONLY)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def policy_names() -> frozenset[str]:
    """Every policy the kernel currently holds, by the name it declared."""
    return frozenset(path.name for path in node_path(node.POLICIES).iterdir() if path.is_dir())


def policy_present(name: str) -> bool:
    """Whether the kernel holds a policy by this name."""
    return policy_path(name).is_dir()


def policy_version(name: str) -> str | None:
    """The version string the kernel reports for this policy, or None."""
    try:
        return (policy_path(name) / node.VERSION).read_text().strip()
    except OSError:
        return None


def policy_active(name: str) -> bool:
    """Whether this policy is the one the kernel enforces."""
    return (policy_path(name) / node.ACTIVE).read_text().strip() == "1"


def deploy_policy(signed: Path) -> None:
    """Write a signed policy into new_policy; the kernel parses and loads it."""
    write(node_path(node.NEW_POLICY), signed.read_bytes())


def activate_policy(name: str) -> None:
    """Make an already-loaded policy the one the kernel enforces."""
    active = policy_path(name) / node.ACTIVE
    if active.read_text().strip() != "1":
        write(active, "1")


def delete_policy(name: str) -> None:
    """Remove a loaded policy and verify it is gone."""
    if policy_present(name):
        write(policy_path(name) / node.DELETE, "1")
    if policy_present(name):
        raise RuntimeError(f"policy {name} was not deleted")


def enforcement() -> bool:
    """Whether IPE is in enforcing mode."""
    return node_path(node.ENFORCE).read_text().strip() == "1"


def success_audit() -> bool:
    """Whether IPE logs allowed operations, not just denied ones."""
    return node_path(node.SUCCESS_AUDIT).read_text().strip() == "1"


def active_policy() -> str | None:
    """The name of the currently active policy, or None."""
    for name in policy_names():
        if policy_active(name):
            return name
    return None


def set_enforcement(enabled: bool) -> None:
    """Switch IPE between enforcing and permissive."""
    write(node_path(node.ENFORCE), "1" if enabled else "0")


def set_success_audit(enabled: bool) -> None:
    """Toggle whether IPE logs allowed operations."""
    write(node_path(node.SUCCESS_AUDIT), "1" if enabled else "0")


def load_baseline(policy: Policy) -> str:
    """Deploy and activate the baseline, or verify the one already loaded matches."""
    expected = policy.text.read_bytes().rstrip(b"\n")
    if policy_present(policy.name):
        loaded = (policy_path(policy.name) / node.POLICY).read_bytes().rstrip(b"\n")
        if loaded != expected:
            raise RuntimeError(f"loaded policy {policy.name} differs from {policy.text}")
    else:
        try:
            deploy_policy(policy.signed)
        except OSError as failure:
            if failure.errno != errno.EEXIST:
                raise
    activate_policy(policy.name)
    return policy.name
