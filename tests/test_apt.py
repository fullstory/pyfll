# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import os

from pyfll.apt import AptMixin, proxy_uri

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
