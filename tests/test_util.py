# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import subprocess

import pytest

import pyfll.util as util
from pyfll.exceptions import FllError
from pyfll.util import (
    deduplicate_list,
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
