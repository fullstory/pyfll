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
