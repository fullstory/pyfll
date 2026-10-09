# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import os
import types

from pyfll.apt import AptMixin, apt_spec_name, count_apt_actions, proxy_uri

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


def _make_apt_for_initramfs():
    profile = AptMixin.__new__(AptMixin)
    profile.log = logging.getLogger("test_create_initramfs")
    profile.conf = {"options": {}}
    profile.opts = types.SimpleNamespace(verbose=False, debug=False, quiet=False)
    profile.detect_linux_version = lambda chroot: ["6.1.0-amd64"]
    return profile


def test_create_initramfs_runs_dracut():
    profile = _make_apt_for_initramfs()
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


KEYRING = "aptosid-archive-keyring"


def make_host_keyring(host, layout="file-symlink", name=KEYRING):
    """Lay out a keyring under the fake build host root *host*: the aptosid
    package's symlink to a file, a symlink to a directory, or a plain file."""
    keyrings = host / "usr/share/keyrings"
    keyrings.mkdir(parents=True, exist_ok=True)
    pkg_dir = host / "usr/share" / name
    if layout == "file-symlink":
        pkg_dir.mkdir()
        (pkg_dir / f"{name}.gpg").write_bytes(b"KEY")
        (keyrings / f"{name}.gpg").symlink_to(f"../{name}/{name}.gpg")
    elif layout == "dir-symlink":
        (pkg_dir / "apt").mkdir(parents=True)
        (pkg_dir / "apt" / "key.asc").write_bytes(b"KEY")
        (keyrings / f"{name}.gpg").symlink_to(f"../{name}/apt")
    else:
        (keyrings / f"{name}.gpg").write_bytes(b"KEY")


def make_apt_for_prime(tmp_path, monkeypatch, repos):
    host = tmp_path / "host"
    host.mkdir()
    monkeypatch.setattr("pyfll.apt.HOST_ROOT", str(host))
    (tmp_path / "build" / "chroot").mkdir(parents=True)

    calls = []
    profile = AptMixin.__new__(AptMixin)
    profile.temp = str(tmp_path / "build")
    profile.log = logging.getLogger("test_prime_apt")
    profile.opts = types.SimpleNamespace(binary=True)
    profile.conf = {
        "options": {},
        "chroots": {"chroot": {"packages": {"distro": "debian"}, "repos": repos}},
    }
    profile.write_apt_lists = lambda chroot, cached=False, src_uri=False: None
    profile.apt_get = lambda chroot, command, args=None, insecure=False: calls.append(
        (command, args, insecure)
    )
    return profile, host, tmp_path / "build" / "chroot", calls


def test_prime_apt_no_keyring_unchanged(tmp_path, monkeypatch):
    profile, host, chroot_dir, calls = make_apt_for_prime(
        tmp_path, monkeypatch, {"debian": {"uri": "http://deb.debian.org/debian"}}
    )

    profile.prime_apt("chroot")

    assert calls == [("update", None, False), ("dist-upgrade", None, False)]
    assert not (chroot_dir / "usr").exists()


def test_prime_apt_seeds_host_keyring(tmp_path, monkeypatch, caplog):
    """With the keyring on the build host, no apt call is insecure and the
    package installs from the already verified repo."""
    profile, host, chroot_dir, calls = make_apt_for_prime(
        tmp_path, monkeypatch, {"aptosid": {"keyring": KEYRING}}
    )
    make_host_keyring(host)

    profile.prime_apt("chroot")

    assert calls == [
        ("update", None, False),
        ("install", [KEYRING], False),
        ("dist-upgrade", None, False),
    ]
    link = chroot_dir / f"usr/share/keyrings/{KEYRING}.gpg"
    # same link the package ships, so dpkg replaces it in place
    assert os.readlink(link) == f"../{KEYRING}/{KEYRING}.gpg"
    assert link.read_bytes() == b"KEY"
    assert not (chroot_dir / f"usr/share/{KEYRING}/{KEYRING}.gpg").is_symlink()
    assert "trusted on first use" not in caplog.text


def test_prime_apt_seeds_directory_keyring(tmp_path, monkeypatch):
    profile, host, chroot_dir, calls = make_apt_for_prime(
        tmp_path, monkeypatch, {"aptosid": {"keyring": KEYRING}}
    )
    make_host_keyring(host, layout="dir-symlink")

    profile.prime_apt("chroot")

    link = chroot_dir / f"usr/share/keyrings/{KEYRING}.gpg"
    assert os.readlink(link) == f"../{KEYRING}/apt"
    assert (link / "key.asc").read_bytes() == b"KEY"
    assert not any(insecure for _, _, insecure in calls)


def test_prime_apt_seeds_plain_keyring_file(tmp_path, monkeypatch):
    profile, host, chroot_dir, calls = make_apt_for_prime(
        tmp_path, monkeypatch, {"aptosid": {"keyring": KEYRING}}
    )
    make_host_keyring(host, layout="plain")

    profile.prime_apt("chroot")

    seeded = chroot_dir / f"usr/share/keyrings/{KEYRING}.gpg"
    assert not seeded.is_symlink()
    assert seeded.read_bytes() == b"KEY"
    assert not any(insecure for _, _, insecure in calls)


def test_prime_apt_missing_keyring_trusted_on_first_use(tmp_path, monkeypatch, caplog):
    profile, host, chroot_dir, calls = make_apt_for_prime(
        tmp_path, monkeypatch, {"aptosid": {"keyring": KEYRING}}
    )

    with caplog.at_level(logging.WARNING, logger="test_prime_apt"):
        profile.prime_apt("chroot")

    assert calls == [
        ("update", None, True),
        ("install", [KEYRING], True),
        ("update", None, False),
        ("dist-upgrade", None, False),
    ]
    assert f"{KEYRING} not on build host, trusted on first use" in caplog.text
    assert not (chroot_dir / "usr").exists()


def test_prime_apt_mixed_keyrings(tmp_path, monkeypatch, caplog):
    """Only the keyring the host lacks takes the insecure path."""
    profile, host, chroot_dir, calls = make_apt_for_prime(
        tmp_path,
        monkeypatch,
        {
            "debian": {"uri": "http://deb.debian.org/debian"},
            "aptosid": {"keyring": KEYRING},
            "extra": {"keyring": "extra-archive-keyring"},
        },
    )
    make_host_keyring(host)

    with caplog.at_level(logging.WARNING, logger="test_prime_apt"):
        profile.prime_apt("chroot")

    assert calls == [
        ("update", None, True),
        ("install", ["extra-archive-keyring"], True),
        ("update", None, False),
        ("install", [KEYRING], False),
        ("dist-upgrade", None, False),
    ]
    assert "extra-archive-keyring not on build host" in caplog.text
    assert KEYRING + " not on build host" not in caplog.text


def test_seed_keyring_keeps_existing_chroot_keyring(tmp_path, monkeypatch):
    """A keyring the bootstrap already installed is left alone."""
    profile, host, chroot_dir, calls = make_apt_for_prime(tmp_path, monkeypatch, {})
    keyrings = chroot_dir / "usr/share/keyrings"
    keyrings.mkdir(parents=True)
    (keyrings / "debian-archive-keyring.gpg").write_bytes(b"CHROOT")

    assert profile._seed_keyring("chroot", "debian-archive-keyring")
    assert (keyrings / "debian-archive-keyring.gpg").read_bytes() == b"CHROOT"
