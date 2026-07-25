# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import contextlib
import os
import subprocess
import sys
from dataclasses import dataclass, field

from pyfll.apt import apt_spec_name, count_apt_actions
from pyfll.exceptions import FllError
from pyfll.profile import RECOMMENDS_WHITELIST, FllProfile
from pyfll.util import multiline_to_list

# Entries in share/{profiles,modules} that are maintainer scripts, not lists.
MAINT_SUFFIXES = (".preinst", ".postinst")

# Shells whose -n flag parses a script without running it.
SHELLS = ("sh", "bash", "dash", "ksh", "mksh", "zsh")

# Python has no -n; compile the source instead. Deliberately not py_compile,
# which would drop a __pycache__ into share/profiles.
PY_COMPILE = "import sys; compile(open(sys.argv[1]).read(), sys.argv[1], 'exec')"


def shebang_interpreter(first_line: str) -> str:
    """Return the interpreter basename from a shebang line, or '' if there is
    none. '#!/usr/bin/env python3' resolves to python3 rather than env."""
    if not first_line.startswith("#!"):
        return ""
    argv = first_line[2:].split()
    if not argv:
        return ""
    interpreter = os.path.basename(argv[0])
    if interpreter != "env":
        return interpreter
    # Skip env's own options, e.g. '#!/usr/bin/env -S python3 -u'.
    for arg in argv[1:]:
        if not arg.startswith("-"):
            return os.path.basename(arg)
    return ""


def syntax_check_cmd(interpreter: str, path: str) -> list | None:
    """The argv that syntax-checks *path*, or None if we cannot check this
    interpreter - in which case the caller warns rather than claiming the
    script is fine."""
    if interpreter in SHELLS:
        return [interpreter, "-n", path]
    if interpreter.startswith("python"):
        return [sys.executable, "-c", PY_COMPILE, path]
    return None


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

    @property
    def slug(self) -> str:
        """Filesystem-safe form of the name, for the overlay mountpoint."""
        return self.name.replace(":", "-").replace("/", "-")


@dataclass
class AuditResult:
    """One target's verdict.

    selected - names the audit asked apt for that were not already installed
    install  - packages apt would install, dependencies included
    remove   - packages apt would remove (a '<pkg>-' entry taking effect)
    """

    name: str
    selected: int = 0
    install: int = 0
    remove: int = 0
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
        self._audit_preflight()
        if self.opts.complete:
            self._audit_completeness()

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

    def _reference_graph(self) -> tuple:
        """Walk the reference graph rooted at the config's chroots, returning
        (built, named_by, by_profile).

        built      - profile names some chroot builds
        named_by   - module name -> chroots naming it directly
        by_profile - module name -> profiles naming it, over every profile on
                     disk, whether or not a chroot builds that profile

        Two levels is the whole graph: a chroot names profiles and modules, a
        profile names modules, and fll.module.spec has no `modules` key, so a
        module cannot pull in another."""
        built = set()
        named_by = {}
        for chroot in self.conf["chroots"]:
            pkgs = self.conf["chroots"][chroot]["packages"]
            built.update(pkgs["profile"])
            for module in pkgs["modules"]:
                named_by.setdefault(module, set()).add(f"chroot {chroot}")

        profile_dir = os.path.join(self.opts.share, "profiles")
        by_profile = {}
        for name in sorted(p for p in os.listdir(profile_dir) if is_list_file(p)):
            conf = self._read_configobj(os.path.join(profile_dir, name))
            for module in multiline_to_list(conf.get("modules", "")):
                by_profile.setdefault(module, set()).add(name)

        return built, named_by, by_profile

    def _audit_preflight(self) -> None:
        """Run the static checks that need no chroot, and abort if any failed.

        Both checks run before anything is reported so a single pass surfaces
        every static problem: fixing a broken reference should not then reveal a
        broken script on the next run."""
        problems = self._audit_references() + self._audit_maint_scripts()
        if problems:
            self.log.critical(
                f"{len(problems)} problem(s) to fix before the package lists "
                f"can be audited"
            )
            raise FllError

    def _audit_references(self) -> list:
        """Report, and return, every reference to a profile or module file that
        does not exist.

        Covers every profile on disk rather than only the ones being audited -
        more than expand_pkg_profile's per-profile check reaches."""
        profile_dir = os.path.join(self.opts.share, "profiles")
        modules_dir = os.path.join(self.opts.share, "modules")
        built, named_by, by_profile = self._reference_graph()
        config_name = os.path.basename(self.opts.config)

        missing = []
        for module in sorted(set(named_by) | set(by_profile)):
            if os.path.isfile(os.path.join(modules_dir, module)):
                continue
            origins = named_by.get(module, set()) | {
                f"profiles/{p}" for p in by_profile.get(module, set())
            }
            missing.append(f"module {module} (from {', '.join(sorted(origins))})")
        for profile in sorted(built):
            if not os.path.isfile(os.path.join(profile_dir, profile)):
                missing.append(f"profile {profile} (from {config_name})")
        if missing:
            self.log.critical(
                f"{len(missing)} reference(s) name a file that does not exist:"
            )
            for item in missing:
                self.log.critical(f"    {item}")
        return missing

    def _audit_maint_scripts(self) -> list:
        """Syntax-check every preinst/postinst script, reporting and returning
        the ones that do not parse.

        Checks every script on disk, not just those a target registers: a syntax
        error in an unbuilt profile's script is a build waiting to fail, and
        parsing is free. The interpreter comes from each script's shebang -
        share/profiles/waydroid-kiosk.postinst is Python, so judging everything
        by dash's grammar would invent errors that are not there."""
        problems = []
        for dirname in ("profiles", "modules"):
            directory = os.path.join(self.opts.share, dirname)
            for name in sorted(os.listdir(directory)):
                if not name.endswith(MAINT_SUFFIXES):
                    continue
                relpath = os.path.join(dirname, name)
                path = os.path.join(directory, name)

                with open(path) as fh:
                    interpreter = shebang_interpreter(fh.readline())
                cmd = syntax_check_cmd(interpreter, path)
                if cmd is None:
                    self.log.warning(
                        f"cannot syntax-check {relpath}: unknown interpreter "
                        f"{interpreter or '(no shebang)'!r}"
                    )
                    continue

                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                if result.returncode == 0:
                    continue
                self.log.critical(f"{interpreter} syntax error in {relpath}:")
                for line in result.stdout.splitlines():
                    if line.strip():
                        self.log.critical(f"    {line.strip()}")
                problems.append(relpath)
        return problems

    def _audit_completeness(self) -> None:
        """Report how completely the config exercises share/{profiles,modules}.

        Reachability starts at the config's chroots, not at "some file mentions
        this name": a module reached only through a profile that no chroot
        builds is not exercised by any build either, so the graph is walked.

        Warnings only, and opt-in via --complete. A personal config that
        builds one chroot leaves almost every profile unbuilt, which is true but
        useless to report; it is the shipped example config, meant to showcase
        every build we are capable of, whose numbers should trend to zero."""
        profile_dir = os.path.join(self.opts.share, "profiles")
        modules_dir = os.path.join(self.opts.share, "modules")
        profiles_on_disk = sorted(
            p for p in os.listdir(profile_dir) if is_list_file(p)
        )
        modules_on_disk = sorted(m for m in os.listdir(modules_dir) if is_list_file(m))

        built, named_by, by_profile = self._reference_graph()
        config_name = os.path.basename(self.opts.config)

        unbuilt = [p for p in profiles_on_disk if p not in built]
        if unbuilt:
            self.log.warning(
                f"{len(unbuilt)} profile(s) no chroot in {config_name} builds: "
                f"{' '.join(unbuilt)}"
            )

        reachable = set(named_by)
        for module, profiles in by_profile.items():
            if profiles & built:
                reachable.add(module)

        # The whitelist is read directly by the resolver, not listed as a module.
        whitelist = os.path.basename(RECOMMENDS_WHITELIST)
        unreachable = [
            m for m in modules_on_disk if m not in reachable and m != whitelist
        ]

        # Split by what the fix is: a module held up only by an unbuilt profile
        # becomes reachable the moment a chroot builds that profile, so it is
        # the config's gap. One referenced nowhere at all is the module's own.
        via_unbuilt = {}
        orphaned = []
        for module in unreachable:
            profiles = sorted(by_profile.get(module, set()) & set(unbuilt))
            if profiles:
                via_unbuilt[module] = profiles
            else:
                orphaned.append(module)

        if via_unbuilt:
            self.log.warning(
                f"{len(via_unbuilt)} module(s) reachable only through a profile "
                f"no chroot builds:"
            )
            for module, profiles in sorted(via_unbuilt.items()):
                self.log.warning(f"    {module} (via {', '.join(profiles)})")
        if orphaned:
            self.log.warning(
                f"{len(orphaned)} module(s) no chroot or profile references at "
                f"all: {' '.join(orphaned)}"
            )

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
            f"(its distro, codename, arch, repos and modules)"
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
                    self.expand_pkg_profile(base, path, modules_dir, browser=False),
                    locales,
                )
            )
        return targets + self._browser_targets(base, locales)

    def _browser_targets(self, base: str, locales: list) -> list:
        """Audit each browser the config names as a target of its own.

        A browser is orthogonal to a profile - any profile can be built with
        any of them - so auditing the cross product would be waste, and bolting
        one browser onto every profile would report its breakage once per
        profile while never testing the others at all. Resolving each browser
        once against the bare bootstrapped chroot catches what actually goes
        wrong: a browser's dependencies breaking in sid.

        The browsers come from every chroot the config defines, so a browser
        named only in a commented-out chroot is invisible here."""
        browsers = set()
        for chroot in self.conf["chroots"]:
            browsers.update(self.conf["chroots"][chroot]["packages"]["browser"])

        if not browsers:
            self.log.warning("no browser is configured by any chroot; none audited")
            return []

        self.log.info(f"auditing browser(s): {' '.join(sorted(browsers))}")

        origin = f"{os.path.basename(self.opts.config)} browser="
        targets = []
        for browser in sorted(browsers):
            profile = FllProfile()
            profile.add_package(browser, origin)
            targets.append(AuditTarget(f"browser:{browser}", base, profile, locales))
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
        with self._audit_overlay(base, f"{target.slug}.audit") as state:
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
        # Only entries naming a package that exists as written are selections;
        # a '<pkg>-' deselection resolves to the stripped name and removes.
        result.selected = sum(
            1 for pkg in additions if apt_spec_name(pkg, available) == pkg
        )

        solvable = [
            pkg for pkg in wanted if apt_spec_name(pkg, available) is not None
        ]
        returncode, output = self._apt_simulate(state, solvable)
        if returncode:
            result.diagnosis, result.cascade = self._parse_apt_problems(output)
        else:
            # Only meaningful once apt has produced a plan; a failed solve
            # leaves these at zero.
            result.install, result.remove = count_apt_actions(output)

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
        whitelist = self._read_configobj(
            os.path.join(self.opts.share, RECOMMENDS_WHITELIST)
        )
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
                # Lead with what apt would really do; the selection size is
                # context, not the package count.
                removals = f", {result.remove} to remove" if result.remove else ""
                self.log.info(
                    f"  ok   {result.name}: {result.install} package(s) to "
                    f"install ({result.selected} selected){removals}{duplicates}"
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
