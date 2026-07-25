# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import contextlib
import os
import subprocess
from dataclasses import dataclass, field

from configobj import ConfigObj

from pyfll.apt import apt_spec_name
from pyfll.exceptions import FllError
from pyfll.profile import RECOMMENDS_WHITELIST
from pyfll.util import multiline_to_list

# Entries in share/{profiles,modules} that are maintainer scripts, not lists.
MAINT_SUFFIXES = (".preinst", ".postinst")


def is_list_file(name: str) -> bool:
    """Whether a share/{profiles,modules} entry is a package list, as opposed
    to a maintainer script or an editor/vcs leftover."""
    return not name.startswith(".") and not name.endswith(MAINT_SUFFIXES)


@dataclass
class AuditTarget:
    """One selection to audit.

    name    - what to call it in the report (a chroot or a profile name)
    base    - chroot whose bootstrapped apt state it is resolved against
    profile - the merged FllProfile
    locales - locales to detect locale packages for
    """

    name: str
    base: str
    profile: object
    locales: list


@dataclass
class AuditResult:
    """One target's verdict."""

    name: str
    packages: int = 0
    unknown: list = field(default_factory=list)
    diagnosis: list = field(default_factory=list)
    cascade: list = field(default_factory=list)
    debconf: list = field(default_factory=list)
    duplicates: dict = field(default_factory=dict)
    error: str = ""

    @property
    def ok(self) -> bool:
        """Duplicates are informational (a package named in two modules still
        installs), so they don't fail a target."""
        return not (
            self.unknown
            or self.diagnosis
            or self.cascade
            or self.debconf
            or self.error
        )


class AuditMixin:
    """Mixin providing the resolvability audit: check package lists against
    real apt indexes without building an image."""

    def audit(self) -> None:
        """Audit package lists for apt resolvability.

        Each target's selection is resolved with 'apt-get install --simulate'
        in an overlay over one bootstrapped chroot per (distro, codename, arch,
        repos) signature. A simulate changes nothing, so a single bootstrap
        serves every target sharing that signature; the overlay is what lets a
        profile's preinst scripts run for real without dirtying the base for
        the next target.

        Catches what dependency resolution catches: packages removed or renamed
        in the archive, typos, unmet dependencies, conflicts, and whitelisted
        recommends that drag in something uninstallable. It cannot catch what
        needs a real unpack - dpkg file conflicts between packages, maintainer
        script or debconf failures at configure time, postinst scripts,
        initramfs generation or image assembly.
        """
        targets = self._audit_targets()

        groups = {}
        for target in targets:
            groups.setdefault(self._audit_group_key(target.base), []).append(target)
        self.log.info(
            f"auditing {len(targets)} target(s) over "
            f"{len(groups)} bootstrapped chroot(s)"
        )

        results = []
        for group in groups.values():
            base = group[0].base
            self._audit_bootstrap(base)
            self._audit_recommends_whitelist(base)
            for target in group:
                results.append(self._audit_one(target, base))
            self.nuke_chroot(base)

        self._audit_report(results)

    def _audit_targets(self) -> list:
        """Return the AuditTargets for this run.

        By default each configured chroot is audited exactly as it would be
        built. With --profiles, each named profile from share/profiles is
        audited on its own against a single chroot definition, which casts a
        wider net over the package lists than the handful of chroots currently
        enabled in the config file."""
        if not self.opts.profiles:
            return [
                AuditTarget(c, c, self.profiles[c], self._chroot_locales(c))
                for c in self.chroots
            ]

        base = self.chroots[0]
        profile_dir = os.path.join(self.opts.share, "profiles")
        modules_dir = os.path.join(self.opts.share, "modules")

        names = self.opts.profiles
        if names == ["all"]:
            names = sorted(p for p in os.listdir(profile_dir) if is_list_file(p))

        self.log.info(
            f"auditing profiles against the '{base}' chroot definition "
            f"(its distro, codename, arch, repos, modules and browser)"
        )

        locales = self._chroot_locales(base)
        targets = []
        for name in names:
            path = os.path.join(profile_dir, name)
            if not os.path.isfile(path):
                self.log.critical(f"no such package profile: {path}")
                raise FllError
            targets.append(
                AuditTarget(
                    name,
                    base,
                    self.expand_pkg_profile(base, path, modules_dir),
                    locales,
                )
            )
        return targets

    def _audit_group_key(self, chroot: str) -> tuple:
        """Chroots agreeing on distro, codename, arch and repos share a
        bootstrapped chroot: their apt state is identical, so only the package
        selection differs. Kernel flavour and locales vary freely within a
        group - they change the selection, not the state."""
        pkgs = self.conf["chroots"][chroot]["packages"]
        repos = self.conf["chroots"][chroot]["repos"]
        return (
            pkgs["distro"],
            pkgs["codename"],
            pkgs["arch"],
            tuple(
                (name, tuple(sorted(dict(repos[name]).items())))
                for name in sorted(repos)
            ),
        )

    def _audit_bootstrap(self, chroot: str) -> None:
        """Bootstrap and prime the chroot a group of targets resolves against.
        Only the apt state matters, so this stops after prime_apt's update and
        dist-upgrade - no package installation, initramfs or image work."""
        self.chroot_bootstrap(chroot)
        self.dpkg_divert(chroot)
        self.prime_apt(chroot)

    @contextlib.contextmanager
    def _audit_overlay(self, base: str, name: str):
        """Mount an overlay over the *base* chroot at self.temp/*name* and
        yield *name* for use as a chroot, so every existing chroot helper works
        against it unmodified. Writes land in a throwaway upper dir: whatever
        the audit does - notably running a profile's preinst scripts - is
        discarded, and the next target still sees a pristine base."""
        merged = os.path.join(self.temp, name)
        upper = os.path.join(self.temp, f".{name}.upper")
        work = os.path.join(self.temp, f".{name}.work")
        for dirname in (merged, upper, work):
            os.makedirs(dirname, 0o755, exist_ok=True)

        self.log.debug(f"mounting audit overlay: {merged}")
        self.exec_cmd([
            "mount", "-t", "overlay", f"overlay-{name}",
            "-o",
            f"lowerdir={os.path.join(self.temp, base)},"
            f"upperdir={upper},workdir={work}",
            merged,
        ])
        try:
            yield name
        finally:
            mounted = True
            for cmd in (["umount", merged], ["umount", "-l", merged]):
                try:
                    self.exec_cmd(cmd)
                except FllError:
                    continue
                mounted = False
                break
            if mounted:
                # Never rmtree through a live mount; the leak is confined to
                # the build dir and is visible in the log.
                self.log.error(f"audit overlay still mounted: {merged}")
            else:
                for dirname in (merged, upper, work):
                    self.nuke_directory(dirname)

    def _audit_one(self, target: AuditTarget, base: str) -> AuditResult:
        """Audit one target in a fresh overlay over *base*."""
        self.log.info(f"{target.name} - auditing package selection...")
        with self._audit_overlay(base, f"{target.name}.audit") as state:
            # pre_installation and diagnose_install_failure read the profile
            # out of self.profiles, keyed by chroot name; the overlay is named
            # after the target so both see this target's own lists.
            self.profiles[state] = target.profile
            return self._audit_target(target, state)

    def _audit_target(self, target: AuditTarget, state: str) -> AuditResult:
        """Resolve one target against *state*'s apt indexes and report what apt
        cannot satisfy. Never raises: an audit collects every target's verdict
        rather than stopping at the first failure."""
        result = AuditResult(target.name)
        profile = target.profile

        # Before resolution, as in a build: a preinst script can enable an
        # architecture or a repository the selection then depends on.
        if profile.preinst:
            try:
                self.pre_installation(state)
            except FllError:
                result.error = "preinst script failed"
                return result

        try:
            wanted, installed = self.resolve_wanted_packages(
                state, profile, locales=target.locales
            )
        except FllError:
            result.error = "package selection failed"
            return result

        result.duplicates = {
            pkg: sorted(files)
            for pkg, files in profile.sources.items()
            if len(files) > 1
        }
        for pkg, files in sorted(result.duplicates.items()):
            self.log.debug(f"{target.name} - {pkg} declared in {', '.join(files)}")

        result.debconf = self._audit_debconf(state, profile)
        for line in result.debconf:
            self.log.error(f"{target.name} - debconf: {line}")

        available = self._available_package_names(state)
        additions = sorted(set(wanted) - installed)
        result.unknown = [
            pkg for pkg in additions if apt_spec_name(pkg, available) is None
        ]
        # Only entries naming a package that exists as written are installs; a
        # '<pkg>-' deselection resolves to the stripped name and removes.
        result.packages = sum(
            1 for pkg in additions if apt_spec_name(pkg, available) == pkg
        )

        solvable = [
            pkg for pkg in wanted if apt_spec_name(pkg, available) is not None
        ]
        returncode, output = self._apt_simulate(state, solvable)
        if returncode:
            result.diagnosis, result.cascade = self._parse_apt_problems(output)

        # Hand the package findings to the build's own analysis, which names the
        # unknown packages and traces each conflict back to the profile or
        # module file that asked for it.
        if result.unknown or result.diagnosis or result.cascade:
            self.diagnose_install_failure(state, wanted, installed)

        return result

    def _audit_debconf(self, chroot: str, profile) -> list:
        """Syntax-check a profile's debconf pre-seed lines with
        debconf-set-selections --checkonly. Catches malformed lines that would
        otherwise fail mid-build; it cannot check that a template exists, as
        the packages owning them are not installed."""
        if not profile.debconf:
            return []

        selections = os.path.join(self.temp, chroot, "fll", "fll_debconf_selections")
        with open(selections, "w") as fh:
            fh.writelines([f"{line}\n" for line in sorted(profile.debconf)])

        cmd = ["debconf-set-selections", "--checkonly", "/fll/fll_debconf_selections"]
        result = subprocess.run(
            self._nspawn_cmd(chroot, cmd),
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if not result.returncode:
            return []
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _audit_recommends_whitelist(self, chroot: str) -> list:
        """Report recommends whitelist entries that exist in no configured
        repository. The whitelist ages exactly as a package list does, but a
        stale entry there is silent: it simply stops matching anything."""
        whitelist = ConfigObj(os.path.join(self.opts.share, RECOMMENDS_WHITELIST))
        entries = multiline_to_list(whitelist.get("packages", ""))
        available = self._available_package_names(chroot)
        stale = sorted(pkg for pkg in entries if pkg not in available)
        if stale:
            self.log.warning(
                f"{len(stale)} {RECOMMENDS_WHITELIST} entry(s) exist in no "
                f"configured repository: {' '.join(stale)}"
            )
        return stale

    def _audit_report(self, results: list) -> None:
        """Log a one-line verdict per target and fail the run if any target did
        not resolve, so --audit is usable as a gate."""
        failed = [r for r in results if not r.ok]

        clean = len(results) - len(failed)
        self.log.info(f"audit summary - {clean}/{len(results)} clean:")
        for result in results:
            duplicates = (
                f", {len(result.duplicates)} duplicate declaration(s)"
                if result.duplicates
                else ""
            )
            if result.ok:
                self.log.info(
                    f"  ok   {result.name}: {result.packages} package(s) to "
                    f"install{duplicates}"
                )
                continue
            problems = []
            if result.error:
                problems.append(result.error)
            if result.unknown:
                problems.append(f"{len(result.unknown)} package(s) not in any repo")
            if result.diagnosis or result.cascade:
                problems.append("unsatisfiable dependencies")
            if result.debconf:
                problems.append("malformed debconf pre-seed")
            self.log.error(f"  FAIL {result.name}: {'; '.join(problems)}{duplicates}")

        if failed:
            self.log.critical(f"{len(failed)} of {len(results)} target(s) failed audit")
            raise FllError
