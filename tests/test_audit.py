# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import sys
import types

import pytest

from pyfll.apt import AptMixin
from pyfll.audit import (
    AuditMixin,
    AuditResult,
    AuditTarget,
    is_list_file,
    shebang_interpreter,
    syntax_check_cmd,
)
from pyfll.exceptions import FllError
from pyfll.profile import FllProfile, PackageProfileMixin


def test_is_list_file_accepts_package_lists():
    assert is_list_file("kde-lite")
    assert is_list_file("distro-tools-x")


def test_is_list_file_rejects_maint_scripts_and_dotfiles():
    """A profile's maintainer scripts sit beside it in share/profiles; auditing
    them as package lists would parse a shell script as a ConfigObj."""
    assert not is_list_file("waydroid-kiosk.postinst")
    assert not is_list_file("steam.preinst")
    assert not is_list_file(".gitignore")


class FakeAudit(AuditMixin, AptMixin, PackageProfileMixin):
    """AuditMixin with just enough of FLLBuilder to exercise target selection,
    grouping and reporting without a chroot. The sibling mixins come along for
    the real _chroot_locales() and _read_configobj(), as in FLLBuilder."""

    def __init__(self, conf=None, chroots=None, profiles=None, opts=None):
        self.conf = conf or {"chroots": {}}
        self.chroots = chroots or []
        self.profiles = profiles or {}
        self.opts = opts or types.SimpleNamespace(
            profiles=None, share="/share", locales=["en_US"], config="fll.conf"
        )
        self.log = logging.getLogger("test")
        self.expanded = []

    def expand_pkg_profile(self, chroot, profile, modules_dir, browser=True):
        self.expanded.append((chroot, profile, modules_dir, browser))
        return FllProfile()


def chroot_conf(**overrides):
    packages = {
        "distro": "debian",
        "codename": "sid",
        "arch": "amd64",
        "linux": "aptosid-amd64",
        "locales": [],
        "browser": [],
        "profile": [],
        "modules": [],
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
        profiles=["kde-lite", "xfce"], share=str(tmp_path),
        locales=["en_US"], config="fll.conf"
    )
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    targets = audit._audit_targets()

    assert [t.name for t in targets] == ["kde-lite", "xfce"]
    # Every profile resolves against the one base chroot definition.
    assert {t.base for t in targets} == {"kde"}
    assert [c for c, _, _, _ in audit.expanded] == ["kde", "kde"]
    # The chroot's browser is deliberately left out of a profile audit.
    assert [b for _, _, _, b in audit.expanded] == [False, False]


def test_targets_profiles_mode_all_skips_maint_scripts(tmp_path):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "kde-lite").write_text("packages = foo\n")
    (tmp_path / "profiles" / "kde-lite.postinst").write_text("#!/bin/sh -e\n")
    (tmp_path / "profiles" / "waydroid-kiosk").write_text("packages = bar\n")

    conf = {"chroots": {"kde": chroot_conf()}}
    opts = types.SimpleNamespace(
        profiles=["all"], share=str(tmp_path), locales=["en_US"],
        config="fll.conf"
    )
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    assert [t.name for t in audit._audit_targets()] == ["kde-lite", "waydroid-kiosk"]


def test_targets_profiles_mode_unknown_profile_is_fatal(tmp_path):
    (tmp_path / "profiles").mkdir()
    conf = {"chroots": {"kde": chroot_conf()}}
    opts = types.SimpleNamespace(
        profiles=["nosuch"], share=str(tmp_path), locales=["en_US"],
        config="fll.conf"
    )
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    with pytest.raises(FllError):
        audit._audit_targets()


def test_browser_targets_one_per_distinct_browser():
    """Browsers are audited as their own dimension, deduplicated across
    chroots: N profiles + M browsers, not N*M."""
    conf = {
        "chroots": {
            "kde": chroot_conf(packages={"browser": ["chromium"]}),
            "xfce": chroot_conf(packages={"browser": ["firefox", "chromium"]}),
        }
    }
    audit = FakeAudit(conf, ["kde"])

    targets = audit._browser_targets("kde", ["en_US"])

    assert [t.name for t in targets] == ["browser:chromium", "browser:firefox"]
    assert {t.base for t in targets} == {"kde"}
    assert [sorted(t.profile.packages) for t in targets] == [["chromium"], ["firefox"]]


def test_browser_targets_record_config_as_origin():
    """So a browser failure traces back to where it was asked for, the way a
    profile failure names its module file."""
    conf = {"chroots": {"kde": chroot_conf(packages={"browser": ["firefox"]})}}
    audit = FakeAudit(conf, ["kde"])

    target = audit._browser_targets("kde", ["en_US"])[0]

    assert target.profile.sources["firefox"] == {"fll.conf browser="}


def test_browser_targets_none_configured(caplog):
    conf = {"chroots": {"kde": chroot_conf()}}
    audit = FakeAudit(conf, ["kde"])

    with caplog.at_level(logging.WARNING):
        assert audit._browser_targets("kde", ["en_US"]) == []

    assert "no browser is configured" in caplog.text


def test_browser_targets_included_in_profiles_mode(tmp_path):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "minimal").write_text("packages = foo\n")

    conf = {"chroots": {"kde": chroot_conf(packages={"browser": ["firefox"]})}}
    opts = types.SimpleNamespace(
        profiles=["minimal"], share=str(tmp_path), locales=["en_US"],
        config="fll.conf",
    )
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    assert [t.name for t in audit._audit_targets()] == ["minimal", "browser:firefox"]


def test_browser_targets_absent_in_config_mode():
    """A configured chroot already carries its own browser in its selection, so
    a separate browser target there would be redundant."""
    conf = {"chroots": {"kde": chroot_conf(packages={"browser": ["firefox"]})}}
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()})

    assert [t.name for t in audit._audit_targets()] == ["kde"]


def test_target_slug_is_filesystem_safe():
    """The overlay mountpoint is named after the target, so a ':' in the label
    must not reach the path."""
    target = AuditTarget("browser:firefox", "kde", FllProfile(), ["en_US"])

    assert target.slug == "browser-firefox"


def test_target_slug_unchanged_for_plain_names():
    assert AuditTarget("kde-lite", "kde", FllProfile(), []).slug == "kde-lite"


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
    assert AuditResult("kde", install=1230, selected=146).ok


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
        FakeAudit()._audit_report([AuditResult("kde", install=1230, selected=146)])

    assert "1/1 clean" in caplog.text


def test_report_leads_with_real_install_count(caplog):
    """The selection size excludes everything apt pulls in as a dependency, so
    the headline number must be apt's own count, not len(selection)."""
    with caplog.at_level(logging.INFO):
        FakeAudit()._audit_report([AuditResult("kde", install=1230, selected=146)])

    assert "1230 package(s) to install (146 selected)" in caplog.text


def test_report_shows_removals(caplog):
    """A '<pkg>-' entry taking effect shows up here, which is how you confirm a
    deselection is doing something."""
    with caplog.at_level(logging.INFO):
        FakeAudit()._audit_report(
            [AuditResult("kde", install=1230, selected=146, remove=1)]
        )

    assert "1 to remove" in caplog.text


def test_report_omits_removals_when_none(caplog):
    with caplog.at_level(logging.INFO):
        FakeAudit()._audit_report([AuditResult("kde", install=12, selected=3)])

    assert "to remove" not in caplog.text


def test_audit_target_dataclass_fields():
    profile = FllProfile()
    target = AuditTarget("kde-lite", "kde", profile, ["en_US"])

    assert (target.name, target.base, target.locales) == ("kde-lite", "kde", ["en_US"])
    assert target.profile is profile


def make_share(tmp_path, profiles=None, modules=()):
    """A minimal share/ tree: profiles maps name -> list of modules it names."""
    (tmp_path / "profiles").mkdir()
    (tmp_path / "modules").mkdir()
    for name, mods in (profiles or {}).items():
        body = "packages = foo\n"
        if mods:
            body += "modules = \"\"\"\n" + "".join(f"\t{m}\n" for m in mods) + '"""\n'
        (tmp_path / "profiles" / name).write_text(body)
    for name in modules:
        (tmp_path / "modules" / name).write_text("packages = bar\n")
    return str(tmp_path)


def completeness_audit(tmp_path, share, profile=(), modules=()):
    conf = {
        "chroots": {
            "kde": chroot_conf(packages={"profile": list(profile),
                                         "modules": list(modules)})
        }
    }
    opts = types.SimpleNamespace(
        profiles=None, share=share, locales=["en_US"], config="/etc/fll.conf"
    )
    return FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)


def test_completeness_clean_tree_is_quiet(caplog, tmp_path):
    share = make_share(tmp_path, {"kde-lite": ["kde-essential"]}, ["kde-essential"])
    audit = completeness_audit(tmp_path, share, profile=["kde-lite"])

    with caplog.at_level(logging.WARNING):
        audit._audit_completeness()

    assert caplog.text == ""


def test_references_clean_tree_does_not_raise(tmp_path):
    share = make_share(tmp_path, {"kde-lite": ["kde-essential"]}, ["kde-essential"])

    audit = completeness_audit(tmp_path, share, profile=["kde-lite"])

    assert audit._audit_references() == []


def test_completeness_warns_unbuilt_profiles(caplog, tmp_path):
    share = make_share(tmp_path, {"kde-lite": [], "gnome": []}, [])
    audit = completeness_audit(tmp_path, share, profile=["kde-lite"])

    with caplog.at_level(logging.WARNING):
        audit._audit_completeness()

    assert "1 profile(s) no chroot in fll.conf builds: gnome" in caplog.text


def test_completeness_module_via_built_profile_is_reachable(caplog, tmp_path):
    share = make_share(tmp_path, {"kde-lite": ["kde-essential"]}, ["kde-essential"])
    audit = completeness_audit(tmp_path, share, profile=["kde-lite"])

    with caplog.at_level(logging.WARNING):
        audit._audit_completeness()

    assert "kde-essential" not in caplog.text


def test_completeness_module_only_via_unbuilt_profile(caplog, tmp_path):
    """The distinguishing case: some profile does name the module, but no chroot
    builds that profile, so no build exercises it."""
    share = make_share(
        tmp_path, {"kde-lite": [], "gnome": ["gnome-desktop"]}, ["gnome-desktop"]
    )
    audit = completeness_audit(tmp_path, share, profile=["kde-lite"])

    with caplog.at_level(logging.WARNING):
        audit._audit_completeness()

    assert "reachable only through a profile no chroot builds" in caplog.text
    assert "gnome-desktop (via gnome)" in caplog.text


def test_completeness_module_referenced_nowhere(caplog, tmp_path):
    share = make_share(tmp_path, {"kde-lite": []}, ["wine"])
    audit = completeness_audit(tmp_path, share, profile=["kde-lite"])

    with caplog.at_level(logging.WARNING):
        audit._audit_completeness()

    assert "1 module(s) no chroot or profile references at all: wine" in caplog.text


def test_completeness_module_named_by_chroot_is_reachable(caplog, tmp_path):
    """A chroot may name a module directly, without any profile listing it."""
    share = make_share(tmp_path, {"kde-lite": []}, ["firmware"])
    audit = completeness_audit(
        tmp_path, share, profile=["kde-lite"], modules=["firmware"]
    )

    with caplog.at_level(logging.WARNING):
        audit._audit_completeness()

    assert "firmware" not in caplog.text


def test_completeness_recommends_whitelist_exempt(caplog, tmp_path):
    """modules/recommends is read directly by the resolver, so nothing lists it
    and it must not be reported as orphaned."""
    share = make_share(tmp_path, {"kde-lite": []}, ["recommends"])
    audit = completeness_audit(tmp_path, share, profile=["kde-lite"])

    with caplog.at_level(logging.WARNING):
        audit._audit_completeness()

    assert "recommends" not in caplog.text


def test_references_missing_module_is_fatal(caplog, tmp_path):
    share = make_share(tmp_path, {"kde-lite": ["nosuch"]}, [])
    audit = completeness_audit(tmp_path, share, profile=["kde-lite"])

    with caplog.at_level(logging.CRITICAL):
        assert audit._audit_references() == ["module nosuch (from profiles/kde-lite)"]

    assert "module nosuch (from profiles/kde-lite)" in caplog.text


def test_references_missing_module_named_by_chroot(caplog, tmp_path):
    share = make_share(tmp_path, {"kde-lite": []}, [])
    audit = completeness_audit(
        tmp_path, share, profile=["kde-lite"], modules=["nosuch"]
    )

    with caplog.at_level(logging.CRITICAL):
        assert audit._audit_references() == ["module nosuch (from chroot kde)"]

    assert "module nosuch (from chroot kde)" in caplog.text


def test_references_missing_profile_is_fatal(caplog, tmp_path):
    share = make_share(tmp_path, {}, [])
    audit = completeness_audit(tmp_path, share, profile=["nosuch"])

    with caplog.at_level(logging.CRITICAL):
        assert audit._audit_references() == ["profile nosuch (from fll.conf)"]

    assert "profile nosuch (from fll.conf)" in caplog.text


def test_shebang_interpreter_plain_shell():
    assert shebang_interpreter("#!/bin/sh -e\n") == "sh"


def test_shebang_interpreter_python():
    """share/profiles/waydroid-kiosk.postinst is Python, not shell."""
    assert shebang_interpreter("#!/usr/bin/python3\n") == "python3"


def test_shebang_interpreter_env_resolves_past_env():
    assert shebang_interpreter("#!/usr/bin/env python3\n") == "python3"


def test_shebang_interpreter_env_skips_options():
    assert shebang_interpreter("#!/usr/bin/env -S python3 -u\n") == "python3"


def test_shebang_interpreter_absent():
    assert shebang_interpreter("packages = foo\n") == ""


def test_syntax_check_cmd_shell_uses_dash_n():
    assert syntax_check_cmd("bash", "/x/y.postinst") == ["bash", "-n", "/x/y.postinst"]


def test_syntax_check_cmd_python_compiles_without_writing_pyc():
    """py_compile would drop a __pycache__ into share/profiles."""
    cmd = syntax_check_cmd("python3", "/x/y.postinst")

    assert cmd[0] == sys.executable
    assert cmd[1] == "-c"
    assert "py_compile" not in cmd[2]
    assert cmd[3] == "/x/y.postinst"


def test_syntax_check_cmd_unknown_interpreter():
    """None means 'cannot check', so the caller warns instead of passing it."""
    assert syntax_check_cmd("perl", "/x/y.postinst") is None
    assert syntax_check_cmd("", "/x/y.postinst") is None


def maint_script_audit(tmp_path, scripts):
    """scripts maps 'profiles/foo.postinst' -> file contents."""
    (tmp_path / "profiles").mkdir()
    (tmp_path / "modules").mkdir()
    for relpath, body in scripts.items():
        (tmp_path / relpath).write_text(body)
    opts = types.SimpleNamespace(
        profiles=None, share=str(tmp_path), locales=["en_US"], config="fll.conf"
    )
    return FakeAudit({"chroots": {}}, [], opts=opts)


def test_maint_scripts_clean_shell_passes(tmp_path):
    audit = maint_script_audit(
        tmp_path, {"modules/cli.postinst": "#!/bin/sh -e\necho hello\n"}
    )

    assert audit._audit_maint_scripts() == []


def test_maint_scripts_broken_shell_reported(caplog, tmp_path):
    audit = maint_script_audit(
        tmp_path, {"modules/cli.postinst": "#!/bin/sh -e\nif true; then\n"}
    )

    with caplog.at_level(logging.CRITICAL):
        assert audit._audit_maint_scripts() == ["modules/cli.postinst"]

    assert "sh syntax error in modules/cli.postinst" in caplog.text


def test_maint_scripts_python_not_judged_by_shell_grammar(tmp_path):
    """The regression this guards: 'def f():' is a syntax error to dash, so a
    blanket sh -n would fail a perfectly good Python script."""
    audit = maint_script_audit(
        tmp_path,
        {"profiles/waydroid.postinst": "#!/usr/bin/python3\ndef f():\n    pass\n"},
    )

    assert audit._audit_maint_scripts() == []


def test_maint_scripts_broken_python_reported(caplog, tmp_path):
    audit = maint_script_audit(
        tmp_path, {"profiles/waydroid.postinst": "#!/usr/bin/python3\ndef f(:\n"}
    )

    with caplog.at_level(logging.CRITICAL):
        assert audit._audit_maint_scripts() == ["profiles/waydroid.postinst"]

    assert "python3 syntax error in profiles/waydroid.postinst" in caplog.text


def test_maint_scripts_unknown_interpreter_warns_not_fails(caplog, tmp_path):
    audit = maint_script_audit(
        tmp_path, {"modules/odd.postinst": "#!/usr/bin/perl\nprint 1;\n"}
    )

    with caplog.at_level(logging.WARNING):
        assert audit._audit_maint_scripts() == []

    assert "cannot syntax-check modules/odd.postinst" in caplog.text


def test_maint_scripts_ignores_package_lists(tmp_path):
    """Only .preinst/.postinst are scripts; a package list is a ConfigObj."""
    audit = maint_script_audit(tmp_path, {"modules/cli": "packages = bat\n"})

    assert audit._audit_maint_scripts() == []


def test_preflight_reports_both_kinds_before_raising(caplog, tmp_path):
    """One pass surfaces every static problem: fixing a bad reference should not
    then reveal a broken script on the next run."""
    (tmp_path / "profiles").mkdir()
    (tmp_path / "modules").mkdir()
    (tmp_path / "profiles" / "kde-lite").write_text('modules = """\n\tnosuch\n"""\n')
    (tmp_path / "modules" / "cli.postinst").write_text("#!/bin/sh -e\nif true; then\n")
    opts = types.SimpleNamespace(
        profiles=None, share=str(tmp_path), locales=["en_US"], config="fll.conf"
    )
    conf = {"chroots": {"kde": chroot_conf(packages={"profile": ["kde-lite"]})}}
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(FllError):
            audit._audit_preflight()

    assert "module nosuch" in caplog.text
    assert "modules/cli.postinst" in caplog.text
    assert "2 problem(s) to fix" in caplog.text


def test_preflight_clean_tree_does_not_raise(tmp_path):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "modules").mkdir()
    (tmp_path / "profiles" / "kde-lite").write_text("packages = foo\n")
    (tmp_path / "modules" / "cli.postinst").write_text("#!/bin/sh -e\necho ok\n")
    opts = types.SimpleNamespace(
        profiles=None, share=str(tmp_path), locales=["en_US"], config="fll.conf"
    )
    conf = {"chroots": {"kde": chroot_conf(packages={"profile": ["kde-lite"]})}}

    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)

    audit._audit_preflight()


BROKEN_TREES = {
    "missing module": {"profiles/kde-lite": 'modules = """\n\tnosuch\n"""\n'},
    "broken script": {
        "profiles/kde-lite": "packages = foo\n",
        "modules/cli.postinst": "#!/bin/sh -e\nif true; then\n",
    },
}


@pytest.mark.parametrize("kind", sorted(BROKEN_TREES))
def test_audit_preflight_runs_before_any_bootstrap(caplog, tmp_path, kind):
    """audit() promises a broken tree costs nothing to discover. Only this pins
    the ordering: reshuffling audit() would otherwise leave every other test
    green while the guarantee quietly went away."""
    (tmp_path / "profiles").mkdir()
    (tmp_path / "modules").mkdir()
    for relpath, body in BROKEN_TREES[kind].items():
        (tmp_path / relpath).write_text(body)
    opts = types.SimpleNamespace(
        profiles=None, share=str(tmp_path), locales=["en_US"],
        config="fll.conf", complete=False,
    )
    conf = {"chroots": {"kde": chroot_conf(packages={"profile": ["kde-lite"]})}}
    audit = FakeAudit(conf, ["kde"], profiles={"kde": FllProfile()}, opts=opts)
    bootstrapped = []
    audit._audit_bootstrap = bootstrapped.append

    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(FllError):
            audit.audit()

    assert bootstrapped == []


def test_report_counts_cross_profile_overlaps(caplog):
    """A chroot combining package profiles declares shared packages once per
    profile on purpose, so the overlap is counted, never named."""
    with caplog.at_level(logging.INFO):
        FakeAudit()._audit_report(
            [AuditResult("kodi", install=1482, selected=612, overlaps=5)]
        )

    assert "5 cross-profile overlap(s)" in caplog.text
    assert "duplicate declaration(s)" not in caplog.text


def test_report_omits_overlaps_when_none(caplog):
    with caplog.at_level(logging.INFO):
        FakeAudit()._audit_report([AuditResult("kde", install=12, selected=3)])

    assert "overlap" not in caplog.text
