# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import subprocess

import pytest

import pyfll.util as util
from pyfll.exceptions import FllError
from pyfll.util import deduplicate_list, host_timezone, multiline_to_list


def test_deduplicate_list():
    assert deduplicate_list(["b", "a", "b", "c"]) == ["a", "b", "c"]


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
