# SPDX-License-Identifier: GPL-2.0-only

import errno
import os
from dataclasses import dataclass
from pathlib import Path

import layout

IPE_ROOT = layout.SECURITYFS
POLICY_ROOT = layout.POLICIES


@dataclass(frozen=True)
class Policy:
    """The files prepare-policies.py wrote for one policy, and the name it declares."""

    asset: Path
    name: str

    @property
    def text(self):
        return self.asset.with_name(self.asset.name + ".pol")

    @property
    def signed(self):
        return self.asset.with_name(self.asset.name + ".p7s")

    @property
    def certificate(self):
        return self.asset.with_name(self.asset.name + ".der")


def policy_path(name):
    return IPE_ROOT / "policies" / name


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
    return frozenset(path.name for path in node_path("policies").iterdir() if path.is_dir())


def policy_present(name):
    return policy_path(name).is_dir()


def policy_version(name):
    try:
        return (policy_path(name) / "version").read_text().strip()
    except OSError:
        return None


def policy_active(name):
    return (policy_path(name) / "active").read_text().strip() == "1"


def deploy_policy(signed):
    write(node_path("new_policy"), signed.read_bytes())


def activate_policy(name):
    active = policy_path(name) / "active"
    if active.read_text().strip() != "1":
        write(active, "1")


def delete_policy(name):
    if policy_present(name):
        write(policy_path(name) / "delete", "1")
    if policy_present(name):
        raise RuntimeError(f"policy {name} was not deleted")


def enforcement():
    return node_path("enforce").read_text().strip() == "1"


def success_audit():
    return node_path("success_audit").read_text().strip() == "1"


def active_policy():
    for name in policy_names():
        if policy_active(name):
            return name
    return None


def set_enforcement(enabled):
    write(node_path("enforce"), "1" if enabled else "0")


def set_success_audit(enabled):
    write(node_path("success_audit"), "1" if enabled else "0")


def load_baseline(policy):
    expected = policy.text.read_bytes().rstrip(b"\n")
    if policy_present(policy.name):
        loaded = (policy_path(policy.name) / "policy").read_bytes().rstrip(b"\n")
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
