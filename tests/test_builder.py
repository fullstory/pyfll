# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import argparse
import logging
import os
import shutil
import subprocess
import sys

import pytest

from pyfll.builder import FLLBuilder
from pyfll.exceptions import FllError


def _builder(tmp_path, keyfile):
    b = FLLBuilder.__new__(FLLBuilder)
    b.log = logging.getLogger("test_builder")
    b.temp = str(tmp_path)
    b.conf = {"options": {"ssh_authorized_keys": keyfile}}
    os.mkdir(os.path.join(str(tmp_path), "chroot"))
    return b


def test_ssh_authorized_keys_noop_when_unset(tmp_path):
    b = _builder(tmp_path, None)
    b.write_ssh_authorized_keys("chroot")
    assert not os.path.exists(tmp_path / "chroot/var/lib/fll/ssh_authorized_keys")


def test_ssh_authorized_keys_baked_when_set(tmp_path):
    pub = tmp_path / "id_ed25519.pub"
    pub.write_text("ssh-ed25519 AAAAkey dev@host\n")
    b = _builder(tmp_path, str(pub))
    b.write_ssh_authorized_keys("chroot")
    dest = tmp_path / "chroot/var/lib/fll/ssh_authorized_keys"
    assert dest.read_text() == "ssh-ed25519 AAAAkey dev@host\n"
    assert (os.stat(dest).st_mode & 0o777) == 0o644  # public key, world-readable


def test_ssh_authorized_keys_missing_file_raises(tmp_path):
    b = _builder(tmp_path, str(tmp_path / "nonexistent.pub"))
    with pytest.raises(FllError):
        b.write_ssh_authorized_keys("chroot")


def _report_builder(tmp_path, no_report=False):
    b = FLLBuilder.__new__(FLLBuilder)
    b.log = logging.getLogger("test_builder")
    b.run_id = "cafe0123"
    config = tmp_path / "fll.conf"
    config.write_text("[distro]\n")
    b.opts = argparse.Namespace(
        no_report=no_report, config=str(config), output_dir=str(tmp_path)
    )
    (tmp_path / f"distro-202601010000.{b.run_id}.log").write_text("main log\n")
    (tmp_path / f"distro-202601010000.{b.run_id}.log.chroot").write_text("chroot\n")
    (tmp_path / "distro-202601010000.deadbeef.log").write_text("other run\n")
    return b


def _fake_pastebinit(monkeypatch, uploads):
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/pastebinit")

    def fake_run(cmd, **kwargs):
        uploads.append(cmd[-1])
        return subprocess.CompletedProcess(cmd, 0, stdout="https://paste.debian.net/1\n")

    monkeypatch.setattr(subprocess, "run", fake_run)


def test_report_failure_prompt_accepted(tmp_path, monkeypatch, capsys):
    b = _report_builder(tmp_path)
    uploads = []
    _fake_pastebinit(monkeypatch, uploads)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "")  # default is yes
    b.report_failure()
    # config first, then this run's logfiles only (not other runs')
    assert uploads == [
        b.opts.config,
        str(tmp_path / f"distro-202601010000.{b.run_id}.log"),
        str(tmp_path / f"distro-202601010000.{b.run_id}.log.chroot"),
    ]
    assert "https://paste.debian.net/1" in capsys.readouterr().out


def test_report_failure_prompt_declined(tmp_path, monkeypatch):
    b = _report_builder(tmp_path)
    uploads = []
    _fake_pastebinit(monkeypatch, uploads)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    b.report_failure()
    assert uploads == []


def test_report_failure_no_report_suppresses(tmp_path, monkeypatch):
    b = _report_builder(tmp_path, no_report=True)
    uploads = []
    _fake_pastebinit(monkeypatch, uploads)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("prompted"))
    b.report_failure()
    assert uploads == []


def test_report_failure_not_a_tty_skips_prompt(tmp_path, monkeypatch):
    b = _report_builder(tmp_path)
    uploads = []
    _fake_pastebinit(monkeypatch, uploads)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr("builtins.input", lambda prompt: pytest.fail("prompted"))
    b.report_failure()
    assert uploads == []


def test_report_failure_missing_pastebinit(tmp_path, monkeypatch, caplog):
    b = _report_builder(tmp_path)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("ran pastebinit")
    )
    with caplog.at_level(logging.ERROR, logger="test_builder"):
        b.report_failure()
    assert "pastebinit not found" in caplog.text


SHARE_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "share")


@pytest.mark.parametrize(
    "arch, bcj",
    [("amd64", "x86"), ("i386", "x86"), ("arm64", "arm64"), ("riscv64", None)],
)
def test_squashfs_xz_bcj_filter_follows_arch(tmp_path, arch, bcj):
    """The xz BCJ filter is a branch-call-jump converter for one instruction
    set; the wrong one makes the image larger, not invalid, so it must follow
    the chroot's arch and be left out where xz has none."""
    b = FLLBuilder.__new__(FLLBuilder)
    b.log = logging.getLogger("test_builder")
    b.temp = str(tmp_path)
    b.opts = argparse.Namespace(share=SHARE_DIR)
    b.conf = {
        "options": {"readonly_filesystem": "squashfs", "squashfs_comp": "xz"},
        "chroots": {"c": {"packages": {"arch": arch}}},
    }
    b.get_distro_imagefile = lambda chroot: "/c.squashfs"
    os.makedirs(tmp_path / "c/fll")
    calls = []
    b.chroot_exec = lambda chroot, cmd, resolv_conf=None: calls.append(cmd)

    b.mkreadonlyfs_chroot("c")

    cmd = calls[0]
    if bcj:
        assert cmd[cmd.index("-Xbcj") + 1] == bcj
    else:
        assert "-Xbcj" not in cmd


@pytest.mark.parametrize(
    "bootloader, arch, ok",
    [("grub", "amd64", True), ("grub", "i386", True), ("grub", "arm64", False),
     ("grub-efi", "arm64", True)],
)
def test_validate_bootloader_arch(bootloader, arch, ok):
    """grub means the BIOS+EFI hybrid with an i386-pc El Torito image, which
    only x86 can stage; the config must say so before any chroot is built."""
    b = FLLBuilder.__new__(FLLBuilder)
    b.log = logging.getLogger("test_builder")
    b.conf = {
        "options": {"bootloader": bootloader},
        "chroots": {"c": {"packages": {"arch": arch}}},
    }
    if ok:
        b.validate_bootloader_arch()
    else:
        with pytest.raises(FllError):
            b.validate_bootloader_arch()
