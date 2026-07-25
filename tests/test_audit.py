# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import types

import pytest

from pyfll.apt import AptMixin
from pyfll.audit import AuditMixin, AuditResult, AuditTarget, is_list_file
from pyfll.exceptions import FllError
from pyfll.profile import FllProfile


def test_is_list_file_accepts_package_lists():
    assert is_list_file("kde-lite")
    assert is_list_file("distro-tools-x")


def test_is_list_file_rejects_maint_scripts_and_dotfiles():
    """A profile's maintainer scripts sit beside it in share/profiles; auditing
    them as package lists would parse a shell script as a ConfigObj."""
    assert not is_list_file("waydroid-kiosk.postinst")
    assert not is_list_file("steam.preinst")
    assert not is_list_file(".gitignore")


class FakeAudit(AuditMixin, AptMixin):
    """AuditMixin with just enough of FLLBuilder to exercise target selection,
    grouping and reporting without a chroot. AptMixin comes along for the real
    _chroot_locales()."""

    def __init__(self, conf=None, chroots=None, profiles=None, opts=None):
        self.conf = conf or {"chroots": {}}
        self.chroots = chroots or []
        self.profiles = profiles or {}
        self.opts = opts or types.SimpleNamespace(
            profiles=None, share="/share", locales=["en_US"]
        )
        self.log = logging.getLogger("test")
        self.expanded = []

    def expand_pkg_profile(self, chroot, profile, modules_dir):
        self.expanded.append((chroot, profile, modules_dir))
        return FllProfile()


def chroot_conf(**overrides):
    packages = {
        "distro": "debian",
        "codename": "sid",
        "arch": "amd64",
        "linux": "aptosid-amd64",
        "locales": [],
    }
    packages.update(overrides.pop("packages", {}))
    repos = overrides.pop(
        "repos", {"debian": {"uri": "https://deb.debian.org/debian/", "suite": "sid"}}
    )
    return {"packages": packages, "repos": repos}


def test_group_key_matches_for_identical_distro_and_repos():
    """The whole point of the audit: chroots sharing distro/codename/arch/repos
    resolve against one bootstrap."""
    conf = {"chroots": {"kde": chroot_conf(), "xfce": chroot_conf()}}
    audit = FakeAudit(conf, ["kde", "xfce"])

    assert audit._audit_group_key("kde") == audit._audit_group_key("xfce")


def test_group_key_ignores_kernel_flavour_and_locales():
    """These change the selection, not the apt state, so they must not force a
    second bootstrap."""
    conf = {
        "chroots": {
            "a": chroot_conf(packages={"linux": "aptosid-amd64", "locales": ["en_US"]}),
            "b": chroot_conf(packages={"linux": "amd64", "locales": ["de_DE"]}),
        }
    }
    audit = FakeAudit(conf, ["a", "b"])

    assert audit._audit_group_key("a") == audit._audit_group_key("b")


def test_group_key_differs_on_arch():
    conf = {
        "chroots": {
            "a": chroot_conf(),
            "b": chroot_conf(packages={"arch": "arm64"}),
        }
    }
    audit = FakeAudit(conf, ["a", "b"])

    assert audit._audit_group_key("a") != audit._audit_group_key("b")


def test_group_key_differs_on_repos():
    """An extra repository changes what is resolvable, so it needs its own
    bootstrap even at the same distro and arch."""
    conf = {
        "chroots": {
            "a": chroot_conf(),
            "b": chroot_conf(
                repos={
                    "debian": {"uri": "https://deb.debian.org/debian/", "suite": "sid"},
                    "aptosid": {"uri": "http://aptosid.com/debian/", "suite": "sid"},
                }
            ),
        }
    }
    audit = FakeAudit(conf, ["a", "b"])

    assert audit._audit_group_key("a") != audit._audit_group_key("b")


def test_group_key_stable_regardless_of_repo_ordering():
    """ConfigObj preserves file order; two configs listing the same repos in a
    different order must still share a bootstrap."""
    debian = {"uri": "https://deb.debian.org/debian/", "suite": "sid"}
    aptosid = {"uri": "http://aptosid.com/debian/", "suite": "sid"}
    conf = {
        "chroots": {
            "a": chroot_conf(repos={"debian": debian, "aptosid": aptosid}),
            "b": chroot_conf(repos={"aptosid": aptosid, "debian": debian}),
        }
    }
    audit = FakeAudit(conf, ["a", "b"])

    assert audit._audit_group_key("a") == audit._audit_group_key("b")


def test_targets_config_mode_uses_parsed_chroot_profiles():
    conf = {"chroots": {"kde": chroot_conf(), "xfce": chroot_conf()}}
    profiles = {"kde": FllProfile(), "xfce": FllProfile()}
    audit = FakeAudit(conf, ["kde", "xfce"], profiles=profiles)

    targets = audit._audit_targets()

    assert [t.name for t in targets] == ["kde", "xfce"]
    assert [t.base for t in targets] == ["kde", "xfce"]
    assert targets[0].profile is profiles["kde"]
    # No profile file is expanded: init_chroots already merged these.
    assert audit.expanded == []


def test_targets_profiles_mode_expands_each_against_base_chroot(tmp_path):
    (tmp_path / "profiles").mkdir()
    for name in ("kde-lite", "xfce"):
        (tmp_path / "profiles" / name).write_text("packages = foo\n")

    conf = {"chroots": {"kde": chroot_conf()}}
    opts = types.SimpleNamespace(
        profiles=["kde-lite", "xfce"], share=str(tmp_path), locales=["en_US"]
    )
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    targets = audit._audit_targets()

    assert [t.name for t in targets] == ["kde-lite", "xfce"]
    # Every profile resolves against the one base chroot definition.
    assert {t.base for t in targets} == {"kde"}
    assert [c for c, _, _ in audit.expanded] == ["kde", "kde"]


def test_targets_profiles_mode_all_skips_maint_scripts(tmp_path):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "kde-lite").write_text("packages = foo\n")
    (tmp_path / "profiles" / "kde-lite.postinst").write_text("#!/bin/sh -e\n")
    (tmp_path / "profiles" / "waydroid-kiosk").write_text("packages = bar\n")

    conf = {"chroots": {"kde": chroot_conf()}}
    opts = types.SimpleNamespace(
        profiles=["all"], share=str(tmp_path), locales=["en_US"]
    )
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    assert [t.name for t in audit._audit_targets()] == ["kde-lite", "waydroid-kiosk"]


def test_targets_profiles_mode_unknown_profile_is_fatal(tmp_path):
    (tmp_path / "profiles").mkdir()
    conf = {"chroots": {"kde": chroot_conf()}}
    opts = types.SimpleNamespace(
        profiles=["nosuch"], share=str(tmp_path), locales=["en_US"]
    )
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    with pytest.raises(FllError):
        audit._audit_targets()


def test_targets_carry_chroot_locales():
    """Sibling chroots resolve against one bootstrap, so each target must bring
    its own locales rather than inheriting the host chroot's."""
    conf = {
        "chroots": {
            "a": chroot_conf(packages={"locales": ["de_DE"]}),
            "b": chroot_conf(),
        }
    }
    audit = FakeAudit(conf, ["a", "b"], profiles={"a": FllProfile(), "b": FllProfile()})

    targets = {t.name: t.locales for t in audit._audit_targets()}

    assert targets["a"] == ["de_DE"]
    assert targets["b"] == ["en_US"]


def test_result_ok_when_nothing_found():
    assert AuditResult("kde", packages=1200).ok


@pytest.mark.parametrize(
    "kwargs",
    [
        {"unknown": ["ntfs-3g"]},
        {"diagnosis": ["E: Unable to correct problems"]},
        {"cascade": ["foo : Depends: libbar1 but it is not installable"]},
        {"debconf": ["bad line"]},
        {"error": "preinst script failed"},
    ],
)
def test_result_not_ok_for_each_finding(kwargs):
    assert not AuditResult("kde", **kwargs).ok


def test_result_ok_despite_duplicate_declarations():
    """A package named in two modules still installs; it's noise, not a
    failure, and must not fail the audit."""
    result = AuditResult("kde", duplicates={"mpv": ["modules/a", "modules/b"]})

    assert result.ok


def test_report_raises_on_failure(caplog):
    results = [AuditResult("kde"), AuditResult("xfce", unknown=["ntfs-3g"])]

    with caplog.at_level(logging.INFO):
        with pytest.raises(FllError):
            FakeAudit()._audit_report(results)

    assert "1/2 clean" in caplog.text
    assert "FAIL xfce" in caplog.text


def test_report_clean_does_not_raise(caplog):
    with caplog.at_level(logging.INFO):
        FakeAudit()._audit_report([AuditResult("kde", packages=1200)])

    assert "1/1 clean" in caplog.text


def test_audit_target_dataclass_fields():
    profile = FllProfile()
    target = AuditTarget("kde-lite", "kde", profile, ["en_US"])

    assert (target.name, target.base, target.locales) == ("kde-lite", "kde", ["en_US"])
    assert target.profile is profile
