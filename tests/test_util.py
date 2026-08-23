# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import re
import subprocess

import pytest

import pyfll.util as util
from pyfll.exceptions import FllError
from pyfll.util import (
    deduplicate_list,
    exclusion_glob_to_regex,
    host_timezone,
    multiline_to_list,
    strip_common_words,
)


def test_deduplicate_list():
    assert deduplicate_list(["b", "a", "b", "c"]) == ["a", "b", "c"]


def test_strip_common_words_word_boundary():
    # the motivating bug: 'labwc' then 'lxqt' share a leading 'l' character but
    # no leading word, so 'lxqt' must survive intact (not become 'xqt').
    assert (
        strip_common_words("debian-sid-amd64-labwc", "debian-sid-amd64-lxqt")
        == "lxqt"
    )
    assert (
        strip_common_words("debian-sid-amd64-cinnamon", "debian-sid-amd64-labwc")
        == "labwc"
    )


def test_strip_common_words_no_common():
    assert strip_common_words("foo-bar", "baz-qux") == "baz-qux"


def test_strip_common_words_multiword_suffix():
    # only whole shared leading words drop; the remainder rejoins with the sep
    assert strip_common_words("debian-sid-amd64-x", "debian-sid-arm64-y") == "arm64-y"


def _excluded(pattern, path):
    # anchored fullmatch, as builder wraps fragments in ^(...)$
    return re.fullmatch(exclusion_glob_to_regex(pattern), path) is not None


def test_exclusion_glob_star_stays_within_segment():
    assert _excluded("proc/*", "proc/cpuinfo")
    assert not _excluded("proc/*", "proc")
    # descent into matched dirs is pruned by mkfs.erofs, not the regex
    assert not _excluded("proc/*", "proc/1/fd")


def test_exclusion_glob_star_skips_leading_dot():
    assert not _excluded("proc/*", "proc/.hidden")
    assert _excluded("dev/.*", "dev/.udev")
    assert not _excluded("dev/.*", "dev/udev")


def test_exclusion_glob_escapes_regex_specials():
    assert _excluded("boot/initrd.img-*", "boot/initrd.img-6.16-2-amd64")
    assert not _excluded("boot/initrd.img-*", "boot/initrdXimg-1")
    assert _excluded("etc/fstab", "etc/fstab")
    assert not _excluded("etc/fstab", "etc/fstab2")


def test_exclusion_glob_mid_and_trailing_star():
    assert _excluded("etc/*-", "etc/passwd-")
    assert not _excluded("etc/*-", "etc/.foo-")
    assert _excluded("etc/console-setup/*.gz", "etc/console-setup/cached.acm.gz")


def test_multiline_to_list_skips_blank_and_comment_lines():
    text = "foo\n# comment\n\n  bar  \n"
    assert multiline_to_list(text) == ["foo", "bar"]


def test_host_timezone_missing_binary_raises_fllerror(monkeypatch):
    def fake_run(*a, **k):
        raise FileNotFoundError("no such file: timedatectl")

    monkeypatch.setattr(util.subprocess, "run", fake_run)

    with pytest.raises(FllError):
        host_timezone()


def test_host_timezone_failing_command_raises_fllerror(monkeypatch):
    def fake_run(cmd, capture_output=False, check=False):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(util.subprocess, "run", fake_run)

    with pytest.raises(FllError):
        host_timezone()


def test_host_timezone_empty_output_raises_fllerror(monkeypatch):
    class FakeResult:
        stdout = b""

    monkeypatch.setattr(util.subprocess, "run", lambda *a, **k: FakeResult())

    with pytest.raises(FllError):
        host_timezone()


def test_host_timezone_success(monkeypatch):
    class FakeResult:
        stdout = b"Australia/Brisbane\n"

    monkeypatch.setattr(util.subprocess, "run", lambda *a, **k: FakeResult())

    assert host_timezone() == "Australia/Brisbane"
