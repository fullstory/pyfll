# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import types

import pytest

from pyfll.exceptions import FllError
from pyfll.isodd import assert_device_unmounted, storage_partition_dev


def _fake_lsblk(monkeypatch, returncode=0, stdout="", stderr=""):
    import pyfll.isodd as isodd

    monkeypatch.setattr(
        isodd.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(
            returncode=returncode, stdout=stdout, stderr=stderr
        ),
    )


def test_assert_device_unmounted_ok_when_no_mountpoints(monkeypatch):
    # lsblk lists the device + partitions with empty mountpoints
    _fake_lsblk(monkeypatch, stdout="\n\n\n")
    assert_device_unmounted("/dev/sdX")  # must not raise


def test_assert_device_unmounted_raises_when_mounted(monkeypatch):
    # a partition on the target is mounted (e.g. the running system disk)
    _fake_lsblk(monkeypatch, stdout="\n/\n/boot/efi\n")
    with pytest.raises(FllError, match="mounted"):
        assert_device_unmounted("/dev/sda")


def test_assert_device_unmounted_raises_when_not_a_block_device(monkeypatch):
    _fake_lsblk(monkeypatch, returncode=1, stderr="not a block device")
    with pytest.raises(FllError, match="cannot inspect"):
        assert_device_unmounted("/tmp/typo.iso")


def test_storage_partition_dev_raises_fllerror_not_sysexit(monkeypatch):
    """A library function must raise FllError, not sys.exit, so callers like
    builder.gen_live_media can catch and handle it (P2.A1)."""
    import pyfll.isodd as isodd

    monkeypatch.setattr(isodd, "run_process", lambda *a, **k: ["no partitions here"])

    with pytest.raises(FllError, match="could not determine storage partition"):
        storage_partition_dev("/dev/null")


def test_iso_has_rootfs_uuid(monkeypatch):
    import pyfll.isodd as isodd

    monkeypatch.setattr(
        isodd, "read_iso_boot_configs", lambda *a, **k: ["... rootfs_uuid=dead-beef ..."]
    )
    assert isodd.iso_has_rootfs_uuid("/tmp/erofs.iso") is True

    monkeypatch.setattr(isodd, "read_iso_boot_configs", lambda *a, **k: ["... quiet ..."])
    assert isodd.iso_has_rootfs_uuid("/tmp/squashfs.iso") is False


def test_write_iso_persist_refuses_iso_without_rootfs_uuid(monkeypatch):
    """A squashfs image boots by mounting the iso9660 container on the parent
    device, so a persist partition behind it is unreachable. Refuse before the
    device is touched."""
    import pyfll.isodd as isodd

    calls = []
    monkeypatch.setattr(isodd, "assert_device_unmounted", lambda *a, **k: None)
    monkeypatch.setattr(isodd, "iso_has_rootfs_uuid", lambda *a, **k: False)
    monkeypatch.setattr(isodd, "run_process", lambda cmd, *a, **k: calls.append(cmd))

    with pytest.raises(FllError, match="no rootfs_uuid"):
        isodd.write_iso("/tmp/squashfs.iso", "/dev/sdX", persist=True)

    assert calls == []


def test_write_iso_without_persist_ignores_rootfs_uuid(monkeypatch):
    """A plain dd of a squashfs image is exactly what a user does; only the
    persist provisioning needs the rootfs partition by UUID."""
    import pyfll.isodd as isodd

    calls = []
    monkeypatch.setattr(isodd, "assert_device_unmounted", lambda *a, **k: None)
    monkeypatch.setattr(isodd, "iso_has_rootfs_uuid", lambda *a, **k: False)
    monkeypatch.setattr(isodd, "run_process", lambda cmd, *a, **k: calls.append(cmd))

    isodd.write_iso("/tmp/squashfs.iso", "/dev/sdX", persist=False, log_fn=lambda *a: None)

    assert any(c[0] == "dd" for c in calls)
