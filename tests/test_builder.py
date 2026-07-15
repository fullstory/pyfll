# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import os

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
