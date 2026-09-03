# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import os
import types

import pytest

from pyfll.exceptions import FllError
from pyfll.profile import (
    FllProfile,
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


SHARE_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "share")


def _make_profile_expander(browser):
    """A PackageProfileMixin wired up just enough for expand_pkg_profile, with
    the real fll.profile.spec so the profile file parses as it would in a build.
    """
    profile = PackageProfileMixin.__new__(PackageProfileMixin)
    profile.log = logging.getLogger("test_expand_pkg_profile")
    profile.opts = types.SimpleNamespace(share=SHARE_DIR)
    profile.validate_configobj = lambda obj: None
    profile.conf = {
        "chroots": {
            "kde": {
                "packages": {
                    "packages": [],
                    "arch": "amd64",
                    "linux": "aptosid-amd64",
                    "browser": browser,
                },
                "flatpak": {
                    "flathub": {"flatpaks": []},
                    "flathub-beta": {"flatpaks": []},
                },
            }
        },
        "options": {
            "readonly_filesystem": "squashfs",
            "initramfs_tool": "dracut",
            "bootloader": "grub-efi",
        },
    }
    return profile


def test_expand_pkg_profile_includes_browser_by_default(tmp_path):
    """The build path must keep getting the chroot's browser; the audit's
    browser=False is opt-in only."""
    profile_file = tmp_path / "kde-lite"
    profile_file.write_text("packages = yakuake\n")

    pkg_profile = _make_profile_expander(["chromium"]).expand_pkg_profile(
        "kde", str(profile_file), str(tmp_path)
    )

    assert "chromium" in pkg_profile.packages
    assert "yakuake" in pkg_profile.packages


def test_expand_pkg_profile_browser_false_omits_browser(tmp_path):
    """A browser is orthogonal to a profile, so the audit resolves it as its
    own target instead of bolting it onto every profile."""
    profile_file = tmp_path / "kde-lite"
    profile_file.write_text("packages = yakuake\n")

    pkg_profile = _make_profile_expander(["chromium"]).expand_pkg_profile(
        "kde", str(profile_file), str(tmp_path), browser=False
    )

    assert "chromium" not in pkg_profile.packages
    # Everything else the chroot contributes is untouched.
    assert "yakuake" in pkg_profile.packages
    assert "squashfs-tools" in pkg_profile.packages
    assert "linux-image-aptosid-amd64" in pkg_profile.packages


def _make_configobj_reader():
    profile = PackageProfileMixin.__new__(PackageProfileMixin)
    profile.log = logging.getLogger("test_read_configobj")
    return profile


def test_read_configobj_malformed_raises_fllerror(caplog, tmp_path):
    """A stray triple-quote orphans every line after it. share/modules/
    virt-manager shipped like this and surfaced as a raw ConfigObjError
    traceback rather than a message naming the file."""
    broken = tmp_path / "virt-manager"
    broken.write_text('packages = """\n\n"""\n\tlibvirt-clients\n\tvirt-manager\n"""\n')

    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(FllError):
            _make_configobj_reader()._read_configobj(str(broken))

    assert f"failed to parse {broken}" in caplog.text
    assert "line 4: libvirt-clients" in caplog.text


def test_read_configobj_truncates_error_cascade(caplog, tmp_path):
    """One bad quote invalidates every following line, so only the first few
    are worth printing."""
    lines = "".join(f"\tpkg{n}\n" for n in range(10))
    broken = tmp_path / "mod"
    broken.write_text(f'packages = """\n"""\n{lines}"""\n')

    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(FllError):
            _make_configobj_reader()._read_configobj(str(broken))

    # Three lines shown, the rest summarised.
    assert "pkg0" in caplog.text
    assert "pkg3" not in caplog.text
    assert "pkg9" not in caplog.text
    assert "more line(s)" in caplog.text


def test_read_configobj_valid_file_without_configspec(tmp_path):
    good = tmp_path / "mod"
    good.write_text('packages = """\n\tbat\n"""\n')

    conf = _make_configobj_reader()._read_configobj(str(good))

    assert [line.strip() for line in conf["packages"].splitlines() if line.strip()] == [
        "bat"
    ]


def test_read_configobj_validates_when_configspec_given(tmp_path):
    """With a configspec the file is validated too; without one it is not."""
    spec = tmp_path / "spec"
    spec.write_text("packages = string()\nwanted = string()\n")
    incomplete = tmp_path / "mod"
    incomplete.write_text('packages = """\n\tbat\n"""\n')
    reader = _make_configobj_reader()
    reader.validate_configobj = lambda obj: (_ for _ in ()).throw(FllError)

    reader._read_configobj(str(incomplete))

    with pytest.raises(FllError):
        reader._read_configobj(str(incomplete), configspec=str(spec))


def expanded(*declarations):
    """An FllProfile as expand_pkg_profile returns one: packages recorded
    against the file that declared them, no closures yet."""
    profile = FllProfile()
    for name, source in declarations:
        profile.add_package(name, source)
    return profile


def test_duplicates_within_a_single_profile():
    profile = expanded(("mpv", "modules/a"), ("mpv", "modules/b"))

    assert profile.duplicates == {"mpv": ["modules/a", "modules/b"]}
    assert profile.overlaps == {}


def test_merged_profiles_overlap_rather_than_duplicate():
    """kodi and kde-lite each name sddm so either builds on its own; that is
    expected overlap, not a duplicate declaration to clean up."""
    chroot = FllProfile()
    chroot.merge(expanded(("sddm", "profiles/kodi-flatpak")))
    chroot.merge(expanded(("sddm", "modules/kde-essential")))

    assert chroot.duplicates == {}
    assert chroot.overlaps == {
        "sddm": ["modules/kde-essential", "profiles/kodi-flatpak"]
    }


def test_duplicate_inside_one_closure_survives_the_merge():
    """Two files of the same profile naming one package is still a finding
    when that profile is merged alongside another."""
    chroot = FllProfile()
    chroot.merge(expanded(("mesa-vulkan-drivers", "modules/steam"),
                          ("mesa-vulkan-drivers", "modules/xserver")))
    chroot.merge(expanded(("mesa-vulkan-drivers", "modules/kodi-essential")))

    assert chroot.duplicates == {
        "mesa-vulkan-drivers": ["modules/steam", "modules/xserver"]
    }
    assert chroot.overlaps == {}


def test_shared_module_is_not_an_overlap():
    """Both profiles pull modules/essential, so adduser reaches the chroot
    through one file expanded twice - one declaration, nothing to count."""
    chroot = FllProfile()
    chroot.merge(expanded(("adduser", "modules/essential")))
    chroot.merge(expanded(("adduser", "modules/essential")))

    assert chroot.duplicates == {}
    assert chroot.overlaps == {}
