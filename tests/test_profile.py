# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import os

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
