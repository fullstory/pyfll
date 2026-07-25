# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import os
import types

import pytest

from pyfll.apt import AptMixin, apt_spec_name, count_apt_actions, proxy_uri
from pyfll.exceptions import FllError

# _parse_apt_problems/_conflict_subjects don't touch self; call unbound.
mixin = AptMixin()


def test_proxy_uri_http():
    assert (
        proxy_uri("http://localhost:3142", "http://deb.debian.org/debian")
        == "http://localhost:3142/deb.debian.org/debian"
    )


def test_proxy_uri_https_with_path():
    assert (
        proxy_uri("http://localhost:3142", "https://deb.debian.org/debian/pool")
        == "http://localhost:3142/deb.debian.org/debian/pool"
    )


def test_proxy_uri_no_netloc_returned_unchanged():
    """A file: URI with no // has no netloc and can't be proxied; the old
    `uri.split("//")[1]` raised IndexError on this."""
    assert proxy_uri("http://localhost:3142", "file:/srv/mirror") == "file:/srv/mirror"


def test_apt_spec_name_plain():
    assert apt_spec_name("yakuake", {"yakuake"}) == "yakuake"


def test_apt_spec_name_unknown():
    assert apt_spec_name("nosuchpkg", {"yakuake"}) is None


def test_apt_spec_name_deselection():
    """A trailing '-' deselects a package (modules/distro-kde carries
    plasma-welcome-); it is not a missing package."""
    assert apt_spec_name("plasma-welcome-", {"plasma-welcome"}) == "plasma-welcome"


def test_apt_spec_name_literal_wins_over_modifier():
    """memtest86+ is a real package name ending in '+', not a modified
    'memtest86'. Stripping modifiers unconditionally would mis-resolve it."""
    assert apt_spec_name("memtest86+", {"memtest86+", "memtest86"}) == "memtest86+"


def test_apt_spec_name_stale_deselection_is_unknown():
    """apt errors on 'foo-' when foo does not exist, so a deselection of a
    package that has left the archive is a real build failure."""
    assert apt_spec_name("plasma-welcome-", {"yakuake"}) is None


APT_SIMULATE_PLAN = """\
NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
The following additional packages will be installed:
  libbar1 libbaz2
0 upgraded, 3 newly installed, 1 to remove and 0 not upgraded.
Remv plasma-welcome [6.5.0-1]
Inst libbar1 (1.2-1 Debian:unstable [amd64])
Inst libbaz2 (2.0-1 Debian:unstable [amd64])
Inst foo (2.0-1 Debian:unstable [amd64])
Conf libbar1 (1.2-1 Debian:unstable [amd64])
Conf libbaz2 (2.0-1 Debian:unstable [amd64])
Conf foo (2.0-1 Debian:unstable [amd64])
"""


def test_count_apt_actions_counts_inst_and_remv():
    """Conf lines mirror Inst lines and must not be double counted."""
    assert count_apt_actions(APT_SIMULATE_PLAN) == (3, 1)


def test_count_apt_actions_empty_output():
    assert count_apt_actions("") == (0, 0)


def test_count_apt_actions_ignores_prose_mentioning_inst():
    """Only the action lines count, not apt's surrounding narration."""
    prose = "The following NEW packages will be installed:\n  inst\n"

    assert count_apt_actions(prose) == (0, 0)


APT_SIMULATE_OUTPUT = """\
Reading package lists...
Building dependency tree...
Some packages could not be installed. This may mean that you have
requested an impossible situation or if you are using the unstable
distribution that some required packages have not yet been created
or been moved out of Incoming.
The following information may help to resolve the situation:

The following packages have unmet dependencies:
 foo : Depends: libbar1 (>= 1.2) but it is not going to be installed
 baz : Depends: libbar1 (>= 1.2) but it is not going to be installed
E: Unable to correct problems, you have held broken packages.
E: Trivial Only specified but this is not a trivial operation.
 1. libbar1:amd64=1.0-1 is selected for install
 2. foo:amd64=2.0-1 is selected for install
"""


def test_parse_apt_problems_splits_cascade_and_diagnosis():
    diagnosis, cascade = mixin._parse_apt_problems(APT_SIMULATE_OUTPUT)

    assert cascade == [
        "foo : Depends: libbar1 (>= 1.2) but it is not going to be installed",
        "baz : Depends: libbar1 (>= 1.2) but it is not going to be installed",
    ]
    assert diagnosis == [
        "E: Unable to correct problems, you have held broken packages.",
        "E: Trivial Only specified but this is not a trivial operation.",
        "1. libbar1:amd64=1.0-1 is selected for install",
        "2. foo:amd64=2.0-1 is selected for install",
    ]


def test_parse_apt_problems_no_problems():
    diagnosis, cascade = mixin._parse_apt_problems("Reading package lists...\nDone\n")
    assert diagnosis == []
    assert cascade == []


def test_conflict_subjects_strips_arch_and_version():
    diagnosis = [
        "E: some error",
        "1. libbar1:amd64=1.0-1 is selected for install",
        "2. foo:amd64=2.0-1 is selected for install",
        "3. foo:amd64=2.0-1 is selected for install",
    ]
    assert mixin._conflict_subjects(diagnosis) == ["libbar1", "foo"]


def test_conflict_subjects_ignores_non_numbered_lines():
    diagnosis = ["E: some error", "not a numbered line"]
    assert mixin._conflict_subjects(diagnosis) == []


def test_write_apt_lists_rewrites_uris_line_with_hash_and_ampersand(tmp_path, monkeypatch):
    """The old sed -i "s#^URIs: .*#URIs: {cached_uri}#" corrupted its own
    substitution when cached_uri contained '#' (delimiter) or '&' (sed's
    whole-match backreference); rewriting in Python must handle both."""
    chroot = "chroot"
    sources_d = tmp_path / chroot / "etc/apt/sources.list.d"
    sources_d.mkdir(parents=True)

    fetched_name = "apt.example.sources"

    def fake_exec_cmd(cmd, quiet=False):
        # simulate wget writing the fetched sources file
        if cmd[0] == "wget":
            (sources_d / fetched_name).write_text(
                "Types: deb\nURIs: http://apt.example/debian\nSuites: sid\n"
            )

    profile = AptMixin.__new__(AptMixin)
    profile.temp = str(tmp_path)
    profile.log = logging.getLogger("test_write_apt_lists")
    profile.exec_cmd = fake_exec_cmd
    profile._detect_apt_proxy = lambda: None
    profile.conf = {
        "chroots": {
            chroot: {
                "packages": {"distro": "example"},
                "repos": {
                    "example": {
                        "sources_uri": "http://apt.example/apt.example.sources",
                        "cached": "http://localhost:3142/apt.example#weird&value",
                    },
                },
            }
        }
    }

    profile.write_apt_lists(chroot, cached=True)

    text = (sources_d / fetched_name).read_text()
    assert "URIs: http://localhost:3142/apt.example#weird&value\n" in text
    assert "Types: deb\n" in text
    assert "Suites: sid\n" in text


def test_zero_logs_handles_chroot_name_embedded_in_build_path(tmp_path):
    """dirname.partition(chroot)[2] split at the FIRST occurrence of the
    chroot name anywhere in the path -- including inside the build dir
    itself (e.g. a build root of /srv/amd64/build with chroot 'amd64')."""
    chroot = "amd64"
    temp = tmp_path / "amd64" / "build"
    dirname = temp / chroot / "var" / "log" / "apt"
    dirname.mkdir(parents=True)
    (dirname / "history.log").write_text("junk\n")

    written = []

    profile = AptMixin.__new__(AptMixin)
    profile.temp = str(temp)
    profile.write_file = lambda chroot, filename, mode=0o644: written.append(filename)

    profile.zero_logs(chroot, str(dirname), ["history.log"])

    assert written == [os.path.join("var", "log", "apt", "history.log")]


def _make_apt_for_initramfs(initramfs_tool):
    profile = AptMixin.__new__(AptMixin)
    profile.log = logging.getLogger("test_create_initramfs")
    profile.conf = {"options": {"initramfs_tool": initramfs_tool}}
    profile.opts = types.SimpleNamespace(verbose=False, debug=False, quiet=False)
    profile.detect_linux_version = lambda chroot: ["6.1.0-amd64"]
    return profile


def test_create_initramfs_unknown_tool_raises_fllerror_not_exec_empty_string():
    """cmd used to default to "" and get exec'd as-is on an unrecognised
    initramfs_tool, crashing with an unhandled FileNotFoundError instead of
    a clean FllError."""
    profile = _make_apt_for_initramfs("mkinitcpio")
    calls = []
    profile.chroot_exec = lambda chroot, cmd: calls.append(cmd)

    with pytest.raises(FllError):
        profile.create_initramfs("chroot")

    assert calls == []


def test_create_initramfs_dracut_still_works():
    profile = _make_apt_for_initramfs("dracut")
    calls = []
    profile.chroot_exec = lambda chroot, cmd: calls.append(cmd)

    profile.create_initramfs("chroot")

    assert len(calls) == 1
    assert calls[0][0] == "dracut"


def make_lists(tmp_path, indexes):
    """indexes maps an apt list filename -> its Packages content."""
    lists_dir = tmp_path / "chroot" / "var" / "lib" / "apt" / "lists"
    lists_dir.mkdir(parents=True)
    for name, body in indexes.items():
        (lists_dir / name).write_text(body)
    apt = AptMixin()
    apt.temp = str(tmp_path)
    return apt


AMD64_INDEX = "Package: libegl1\nVersion: 1.7-1\nProvides: libegl-vendor\n\n"
I386_INDEX = "Package: libegl1\nVersion: 1.7-1\n\n"


def test_available_names_registers_arch_qualified(tmp_path):
    """modules/steam names its runtime libraries as '<pkg>:i386'. Registering
    only bare names reported all of them as missing from every repository."""
    apt = make_lists(
        tmp_path,
        {
            "deb.debian.org_dists_sid_main_binary-amd64_Packages": AMD64_INDEX,
            "deb.debian.org_dists_sid_main_binary-i386_Packages": I386_INDEX,
        },
    )

    names = apt._available_package_names("chroot")

    assert "libegl1" in names
    assert "libegl1:amd64" in names
    assert "libegl1:i386" in names


def test_available_names_qualifies_provides(tmp_path):
    apt = make_lists(
        tmp_path,
        {"deb.debian.org_dists_sid_main_binary-amd64_Packages": AMD64_INDEX},
    )

    names = apt._available_package_names("chroot")

    assert "libegl-vendor" in names
    assert "libegl-vendor:amd64" in names


def test_available_names_does_not_invent_missing_arch(tmp_path):
    """With no i386 index, ':i386' must stay unavailable - otherwise the check
    would wave through a package that genuinely has no i386 build."""
    apt = make_lists(
        tmp_path,
        {"deb.debian.org_dists_sid_main_binary-amd64_Packages": AMD64_INDEX},
    )

    names = apt._available_package_names("chroot")

    assert "libegl1:amd64" in names
    assert "libegl1:i386" not in names


def test_available_names_unrecognised_filename_still_yields_bare_names(tmp_path):
    """An index whose name carries no binary-<arch> part still contributes."""
    apt = make_lists(tmp_path, {"example_Packages": AMD64_INDEX})

    names = apt._available_package_names("chroot")

    assert "libegl1" in names
    assert not any(":" in name for name in names)


def test_apt_spec_name_arch_qualified():
    available = {"libegl1", "libegl1:amd64", "libegl1:i386"}

    assert apt_spec_name("libegl1:i386", available) == "libegl1:i386"


def test_apt_spec_name_arch_qualified_missing():
    assert apt_spec_name("libegl1:i386", {"libegl1", "libegl1:amd64"}) is None


def test_apt_spec_name_arch_qualified_deselection():
    """':i386' and a trailing '-' have to compose."""
    available = {"libegl1", "libegl1:i386"}

    assert apt_spec_name("libegl1:i386-", available) == "libegl1:i386"
