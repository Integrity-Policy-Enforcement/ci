# SPDX-License-Identifier: GPL-2.0-only

from dataclasses import dataclass
from pathlib import Path

import layout
import nodeio

@dataclass(frozen=True)
class Policy:
    """A signed policy and the name it declares."""

    signed: Path
    name: str


# Reserved for this suite. Scope cleanup may delete any policy with this
# prefix that appears while the tests are running.
TEST_POLICY_PREFIX = "ipe_test_"


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


def policy_dir(name: str) -> Path:
    """The directory the kernel created for this policy under securityfs."""
    return layout.guest.SECURITYFS_DIR / node.POLICIES / name


def node_path(entry: str, policy: Policy | None = None) -> Path:
    """A securityfs path: a root entry, or one under a loaded policy."""
    return (
        layout.guest.SECURITYFS_DIR / entry
        if policy is None
        else policy_dir(policy.name) / entry
    )


def policy_names() -> frozenset[str]:
    """Every policy the kernel currently holds, by the name it declared."""
    return frozenset(path.name for path in node_path(node.POLICIES).iterdir() if path.is_dir())


def test_policy_names() -> frozenset[str]:
    """Return policies in the suite-reserved cleanup namespace.

    Unrelated policies must not use TEST_POLICY_PREFIX while the suite runs:
    a scope may treat a newly appearing name with that prefix as test-owned
    state and delete it.
    """
    return frozenset(name for name in policy_names() if name.startswith(TEST_POLICY_PREFIX))


def policy_present(name: str) -> bool:
    """Whether the kernel holds a policy by this name."""
    return policy_dir(name).is_dir()


def policy_version(name: str) -> str | None:
    """The version string the kernel reports for this policy, or None."""
    try:
        return (policy_dir(name) / node.VERSION).read_text().strip()
    except OSError:
        return None


def policy_active(name: str) -> bool:
    """Whether this policy is the one the kernel enforces."""
    return (policy_dir(name) / node.ACTIVE).read_text().strip() == "1"


def deploy_policy(signed: Path) -> None:
    """Write a signed policy into new_policy; the kernel parses and loads it."""
    nodeio.write_path(node_path(node.NEW_POLICY), signed.read_bytes())


def activate_policy(name: str) -> None:
    """Make an already-loaded policy the one the kernel enforces."""
    active = policy_dir(name) / node.ACTIVE
    if active.read_text().strip() != "1":
        nodeio.write_path(active, "1")


def delete_policy(name: str) -> None:
    """Remove a loaded policy and verify it is gone."""
    if policy_present(name):
        nodeio.write_path(policy_dir(name) / node.DELETE, "1")
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
    nodeio.write_path(node_path(node.ENFORCE), "1" if enabled else "0")


def set_success_audit(enabled: bool) -> None:
    """Toggle whether IPE logs allowed operations."""
    nodeio.write_path(node_path(node.SUCCESS_AUDIT), "1" if enabled else "0")
