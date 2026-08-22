# SPDX-License-Identifier: GPL-2.0-only

import ctypes

LINUX_CAPABILITY_VERSION_3 = 0x20080522
LINUX_CAPABILITY_U32S_3 = 2
CAP_MAC_ADMIN = 33
CAPABILITY_WORD_BITS = 32
MAC_ADMIN_WORD = CAP_MAC_ADMIN // CAPABILITY_WORD_BITS
MAC_ADMIN_MASK = 1 << (CAP_MAC_ADMIN % CAPABILITY_WORD_BITS)


class CapabilityHeader(ctypes.Structure):
    _fields_ = (("version", ctypes.c_uint32), ("pid", ctypes.c_int))


class CapabilityData(ctypes.Structure):
    _fields_ = (
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    )


libc = ctypes.CDLL(None, use_errno=True)
libc.capget.argtypes = (ctypes.POINTER(CapabilityHeader), ctypes.POINTER(CapabilityData))
libc.capset.argtypes = (ctypes.POINTER(CapabilityHeader), ctypes.POINTER(CapabilityData))


def read():
    header = CapabilityHeader(LINUX_CAPABILITY_VERSION_3, 0)
    values = (CapabilityData * LINUX_CAPABILITY_U32S_3)()
    ctypes.set_errno(0)
    if libc.capget(ctypes.byref(header), values) != 0:
        raise OSError(ctypes.get_errno(), "capget failed")
    return header, values


def write(header, values):
    ctypes.set_errno(0)
    if libc.capset(ctypes.byref(header), values) != 0:
        raise OSError(ctypes.get_errno(), "capset failed")


def set_mac_admin_effective(enabled):
    header, values = read()
    if enabled:
        values[MAC_ADMIN_WORD].effective |= MAC_ADMIN_MASK
    else:
        values[MAC_ADMIN_WORD].effective &= ~MAC_ADMIN_MASK
    write(header, values)
    _, current = read()
    actual = bool(current[MAC_ADMIN_WORD].effective & MAC_ADMIN_MASK)
    if actual != enabled:
        raise RuntimeError(f"CAP_MAC_ADMIN effective={actual}, expected {enabled}")


def drop_mac_admin():
    header, values = read()
    values[MAC_ADMIN_WORD].effective &= ~MAC_ADMIN_MASK
    values[MAC_ADMIN_WORD].permitted &= ~MAC_ADMIN_MASK
    write(header, values)
    _, current = read()
    if current[MAC_ADMIN_WORD].effective & MAC_ADMIN_MASK:
        raise RuntimeError("CAP_MAC_ADMIN remains effective")
