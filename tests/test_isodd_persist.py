# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import os
import shutil
import subprocess

import pytest

from pyfll.isodd import reset_cow_preserve_etc

# Real btrfs on a loop device: needs root and the btrfs/loop tooling. Unlike the
# rest of the suite (unprivileged, mocked/tmp_path), this is an integration test
# and is skipped when it cannot run.
_TOOLS = ("losetup", "mkfs.btrfs", "btrfs", "mount", "umount")
pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or not all(shutil.which(t) for t in _TOOLS),
    reason="requires root and btrfs/loop tooling (losetup, mkfs.btrfs, btrfs)",
)


@pytest.fixture
def btrfs_loop(tmp_path):
    """A freshly-mkfs'd btrfs loop device; detached and removed on teardown."""
    img = tmp_path / "persist.img"
    with open(img, "wb") as f:
        f.truncate(512 * 1024 * 1024)  # sparse: instant
    out = subprocess.run(
        ["losetup", "--find", "--show", str(img)],
        capture_output=True, text=True, check=True,
    )
    loop = out.stdout.strip()
    try:
        subprocess.run(["mkfs.btrfs", "-q", "-f", loop], check=True)
        yield loop
    finally:
        subprocess.run(["losetup", "-d", loop], check=False)


def _mount(loop, mnt):
    mnt.mkdir(exist_ok=True)
    subprocess.run(
        ["mount", "-o", "subvolid=5", "-t", "btrfs", loop, str(mnt)], check=True
    )


def _umount(mnt):
    subprocess.run(["umount", str(mnt)], check=False)


def test_reset_cow_preserve_etc_keeps_etc_resets_rest(btrfs_loop, tmp_path):
    mnt = tmp_path / "mnt"

    # Lay out a persist @root as the initramfs would after a live session:
    # one COW dir per flavour, with /etc edits plus other upper dirs and a
    # stale overlay workdir. A second flavour has no upper/ and must be skipped.
    _mount(btrfs_loop, mnt)
    try:
        subprocess.run(
            ["btrfs", "subvolume", "create", str(mnt / "@root")], check=True
        )
        flav = mnt / "@root" / "aptosid.budgie-lite"
        (flav / "upper" / "etc").mkdir(parents=True)
        (flav / "upper" / "usr" / "bin").mkdir(parents=True)
        (flav / "upper" / "var" / "lib").mkdir(parents=True)
        (flav / "work" / "work").mkdir(parents=True)
        (flav / "upper" / "etc" / "hostname").write_text("myhost\n")
        (flav / "upper" / "usr" / "bin" / "foo").write_text("x")
        (mnt / "@root" / "aptosid.kde" / "work").mkdir(parents=True)
    finally:
        _umount(mnt)

    reset_cow_preserve_etc(btrfs_loop, verbose=False, log_fn=lambda *a, **k: None)

    _mount(btrfs_loop, mnt)
    try:
        flav = mnt / "@root" / "aptosid.budgie-lite"
        # /etc carried forward verbatim
        assert (flav / "upper" / "etc" / "hostname").read_text() == "myhost\n"
        # everything else in the COW layer reset
        assert not (flav / "upper" / "usr").exists()
        assert not (flav / "upper" / "var").exists()
        # stale workdir cleared (the initramfs recreates it at boot)
        assert not (flav / "work").exists()
    finally:
        _umount(mnt)
