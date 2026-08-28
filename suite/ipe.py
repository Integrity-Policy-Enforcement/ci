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
    def text(self):
        return self.asset.with_name(self.asset.name + layout.POLICY_TEXT_SUFFIX)

    @property
    def signed(self):
        return self.asset.with_name(self.asset.name + layout.POLICY_SIGNATURE_SUFFIX)

    @property
    def certificate(self):
        return self.asset.with_name(self.asset.name + ".der")


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


def policy_path(name):
    return IPE_ROOT / node.POLICIES / name


def node_path(entry, policy=None):
    return IPE_ROOT / entry if policy is None else policy_path(policy.name) / entry


def write(path, data):
    payload = data.encode() if isinstance(data, str) else data
    descriptor = os.open(path, os.O_WRONLY)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def policy_names():
    return frozenset(path.name for path in node_path(node.POLICIES).iterdir() if path.is_dir())


def policy_present(name):
    return policy_path(name).is_dir()


def policy_version(name):
    try:
        return (policy_path(name) / node.VERSION).read_text().strip()
    except OSError:
        return None


def policy_active(name):
    return (policy_path(name) / node.ACTIVE).read_text().strip() == "1"


def deploy_policy(signed):
    write(node_path(node.NEW_POLICY), signed.read_bytes())


def activate_policy(name):
    active = policy_path(name) / node.ACTIVE
    if active.read_text().strip() != "1":
        write(active, "1")


def delete_policy(name):
    if policy_present(name):
        write(policy_path(name) / node.DELETE, "1")
    if policy_present(name):
        raise RuntimeError(f"policy {name} was not deleted")


def enforcement():
    return node_path(node.ENFORCE).read_text().strip() == "1"


def success_audit():
    return node_path(node.SUCCESS_AUDIT).read_text().strip() == "1"


def active_policy():
    for name in policy_names():
        if policy_active(name):
            return name
    return None


def set_enforcement(enabled):
    write(node_path(node.ENFORCE), "1" if enabled else "0")


def set_success_audit(enabled):
    write(node_path(node.SUCCESS_AUDIT), "1" if enabled else "0")


def load_baseline(policy):
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
