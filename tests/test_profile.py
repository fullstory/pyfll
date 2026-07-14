# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import os

from pyfll.exceptions import FllError
from pyfll.profile import (
    PackageProfileMixin,
    parse_dependency_groups,
    source_pkg_specs,
)


def test_parse_dependency_groups_simple():
    assert parse_dependency_groups("foo, bar (>= 1.0)") == [["foo"], ["bar"]]


def test_parse_dependency_groups_alternatives():
    assert parse_dependency_groups("foo | bar (>= 1.0), baz") == [
        ["foo", "bar"],
        ["baz"],
    ]


def test_parse_dependency_groups_empty():
    assert parse_dependency_groups("") == []


def test_source_pkg_specs_binnmu():
    """A binNMU (+bN) binary version doesn't exist as a source version;
    the spec must be built from the parsed source name/version instead."""
    status = {
        "foo-bin": {
            "version": "1.2-3+b1",
            "source": "foo",
            "source_version": "1.2-3",
        },
        "foo-lib": {
            "version": "1.2-3+b1",
            "source": "foo",
            "source_version": "1.2-3",
        },
    }
    specs = source_pkg_specs(status, ["foo-bin", "foo-lib"])
    assert specs == ["foo=1.2-3"]


def test_source_pkg_specs_skips_cdebootstrap_helper():
    status = {
        "cdebootstrap-helper-diverts": {
            "version": "1.0",
            "source": "cdebootstrap-helper",
            "source_version": "1.0",
        },
        "bash": {"version": "5.0-1", "source": "bash", "source_version": "5.0-1"},
    }
    specs = source_pkg_specs(status, list(status.keys()))
    assert specs == ["bash=5.0-1"]


DPKG_STATUS = """\
Package: foo-bin
Status: install ok installed
Version: 1.2-3+b1
Source: foo (1.2-3)

Package: foo-lib
Status: install ok installed
Version: 1.2-3+b1
Source: foo (1.2-3)

Package: bash
Status: install ok installed
Version: 5.0-1

Package: half-removed-pkg
Status: deinstall ok config-files
Version: 1.0-1
"""


def test_read_dpkg_status_parses_binnmu_source_version(tmp_path):
    chroot_dir = tmp_path / "chroot"
    status_dir = chroot_dir / "var" / "lib" / "dpkg"
    status_dir.mkdir(parents=True)
    (status_dir / "status").write_text(DPKG_STATUS)

    profile = PackageProfileMixin.__new__(PackageProfileMixin)
    profile.temp = str(tmp_path)

    packages = profile._read_dpkg_status("chroot")

    assert packages["foo-bin"] == {
        "version": "1.2-3+b1",
        "source": "foo",
        "source_version": "1.2-3",
    }
    # no Source: field means the package is its own source
    assert packages["bash"] == {
        "version": "5.0-1",
        "source": "bash",
        "source_version": "5.0-1",
    }
    # only "installed" status stanzas are kept
    assert "half-removed-pkg" not in packages


APT_PACKAGES = """\
Package: foo
Version: 1.0-1
Recommends: bar

Package: foo
Version: 2.0-1
Recommends: bar, baz
"""


def test_read_apt_packages_keeps_highest_version(tmp_path):
    chroot_dir = tmp_path / "chroot"
    lists_dir = chroot_dir / "var" / "lib" / "apt" / "lists"
    lists_dir.mkdir(parents=True)
    (lists_dir / "example_Packages").write_text(APT_PACKAGES)

    profile = PackageProfileMixin.__new__(PackageProfileMixin)
    profile.temp = str(tmp_path)

    packages = profile._read_apt_packages("chroot")

    assert packages["foo"]["version"] == "2.0-1"
    assert packages["foo"]["recommends"] == "bar, baz"


def test_read_apt_packages_missing_lists_dir(tmp_path):
    profile = PackageProfileMixin.__new__(PackageProfileMixin)
    profile.temp = str(tmp_path)
    assert profile._read_apt_packages("chroot") == {}


def _make_profile_with_log():
    profile = PackageProfileMixin.__new__(PackageProfileMixin)
    profile.log = logging.getLogger("test_resolve_source_uris")
    return profile


def test_resolve_source_uris_bulk_success(caplog):
    profile = _make_profile_with_log()
    calls = []

    def fake_chroot_output(chroot, args, quiet=False):
        calls.append(args)
        return "'http://example/foo_1.0.dsc' foo_1.0.dsc 100 SHA256:abc\n"

    profile.chroot_output = fake_chroot_output

    output = profile._resolve_source_uris("chroot", ["foo=1.0", "bar=2.0"])

    assert len(calls) == 1
    assert calls[0] == [
        "apt-get", "source", "--print-uris", "--only-source", "foo=1.0", "bar=2.0",
    ]
    assert "foo_1.0.dsc" in output


def test_resolve_source_uris_falls_back_per_package_and_skips_failures(caplog):
    """One unresolvable spec must not take down the whole batch (the bug
    behind the fll-live-boot/libxml2 failures in a real sid build log)."""
    profile = _make_profile_with_log()
    calls = []

    def fake_chroot_output(chroot, args, quiet=False):
        calls.append((args, quiet))
        if len(args) > 5:
            # the bulk attempt (>1 spec after the fixed prefix): simulate one
            # bad spec poisoning the batch
            raise FllError
        spec = args[-1]
        if spec == "broken=1.0":
            raise FllError
        return f"'http://example/{spec}.dsc' ok 1 SHA256:abc\n"

    profile.chroot_output = fake_chroot_output

    with caplog.at_level(logging.WARNING):
        output = profile._resolve_source_uris(
            "chroot", ["foo=1.0", "broken=1.0", "bar=2.0"]
        )

    # bulk attempt, then one call per spec
    assert len(calls) == 1 + 3
    assert calls[0][0] == [
        "apt-get", "source", "--print-uris", "--only-source",
        "foo=1.0", "broken=1.0", "bar=2.0",
    ]
    # bulk and per-package retries are all quiet: a miss here is expected and
    # handled, not a reason to dump apt's full raw output at CRITICAL level
    assert all(quiet for _, quiet in calls)

    assert "foo=1.0" in output
    assert "bar=2.0" in output
    assert "broken=1.0" not in output

    warnings = [r.message for r in caplog.records]
    assert any("bulk source URI resolution failed" in w for w in warnings)
    assert any("could not resolve source package: broken=1.0" in w for w in warnings)
