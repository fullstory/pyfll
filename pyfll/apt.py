# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import os
import shutil
import subprocess
from urllib.parse import urlsplit

from pyfll.exceptions import FllError
from pyfll.profile import RECOMMENDS_WHITELIST


def proxy_uri(proxy: str, uri: str) -> str:
    """Rewrite *uri* to go through an apt-cacher-ng-style *proxy* base URL:
    proxy + '/' + netloc + path. URIs with no netloc (e.g. file:/path) can't
    be proxied this way, so they're returned unchanged."""
    parts = urlsplit(uri)
    if not parts.netloc:
        return uri
    return f"{proxy}/{parts.netloc}{parts.path}"


class AptMixin:
    """Mixin providing apt/dpkg operations, chroot bootstrap, and package installation."""

    def apt_get(
        self,
        chroot: str,
        command: str,
        args: list | None = None,
        insecure: bool = False,
        quiet: bool = False,
    ) -> None:
        """An apt-get install wrapper. Automatic installation of recommended
        packages defaults to disabled."""
        aptget = ["apt-get", "--yes"]
        if insecure:
            aptget.append("--allow-unauthenticated")
            aptget.extend(["-o", "Acquire::AllowInsecureRepositories=1"])
        aptget.extend(["-o", "Acquire::Languages=none"])
        aptget.extend(["-o", "Dpkg::Use-Pty=0"])
        aptget.extend(["-o", "Dpkg::Progress-Fancy=0"])
        aptget.extend(["-o", "APT::Color=0"])

        apt_recommends = self.conf["options"].get("apt_recommends", "no")
        if apt_recommends == "no":
            aptget.extend(["-o", "APT::Install-Recommends=0"])

        if self.opts.debug:
            aptget.extend(["-o", "APT::Get::Show-Versions=1"])
        if self.opts.verbose:
            aptget.append("-q")
        else:
            aptget.append("-qq")

        aptget.append(command)
        if args:
            aptget.extend(args)

        self.chroot_exec(chroot, aptget, quiet=quiet)

    def debbootstrap(
        self, chroot: str, arch: str, target: str, mirror: str, codename: str
    ) -> None:
        """Bootstrap a distro root filesystem with debootstrap."""
        bootstrapper = self.conf["options"].get("bootstrapper")
        bootstrap_includes = "apt-utils,ca-certificates,gnupg,xz-utils,zstd"
        if bootstrapper == "mmdebstrap":
            cmd = [
                "mmdebstrap",
                f"--architectures={arch}",
                f"--include={bootstrap_includes}",
                "--variant=minbase",
                "--mode=root",
                "--format=directory",
                "--hook-dir=/usr/share/mmdebstrap/hooks/merged-usr",
            ]
        elif bootstrapper == "debootstrap":
            cmd = [
                "debootstrap",
                f"--arch={arch}",
                f"--include={bootstrap_includes}",
                "--variant=minbase",
                "--merged-usr",
            ]
        else:
            cmd = [
                "cdebootstrap",
                f"--arch={arch}",
                f"--include={bootstrap_includes}",
                "--flavour=minimal",
            ]

        cmd.extend([codename, target, mirror])

        if self.opts.debug or self.opts.verbose:
            cmd.insert(1, "--verbose")

        self.exec_cmd(cmd)

        if bootstrapper == "cdebootstrap":
            self.chroot_exec(chroot, ["dpkg", "--purge", "cdebootstrap-helper-rc.d"])

    def _detect_apt_proxy(self) -> str | None:
        """Return the apt proxy base URL from auto-apt-proxy, or None.

        Never fatal: a missing tool, a non-zero exit, or empty output all just
        mean "no proxy", so the caller falls back to the direct mirror URI.
        """
        auto_apt_proxy = shutil.which("auto-apt-proxy")
        if not auto_apt_proxy:
            return None
        try:
            result = subprocess.run(
                [auto_apt_proxy], stdout=subprocess.PIPE, check=True
            )
        except (OSError, subprocess.CalledProcessError):
            self.log.warning("auto-apt-proxy failed; continuing without apt proxy")
            return None
        proxy = result.stdout.decode("utf-8").strip()
        return proxy or None

    def chroot_bootstrap(self, chroot: str) -> None:
        """Bootstrap a distro root filesystem with the configured bootstrapper."""
        distro = self.conf["chroots"][chroot]["packages"]["distro"]
        codename = self.conf["chroots"][chroot]["packages"]["codename"]
        arch = self.conf["chroots"][chroot]["packages"]["arch"]

        dist_repo = self.conf["chroots"][chroot]["repos"][distro]
        if dist_repo.get("cached"):
            mirror = dist_repo["cached"]
        else:
            mirror = dist_repo["uri"]
            apt_proxy = self._detect_apt_proxy()
            if apt_proxy:
                mirror = proxy_uri(apt_proxy, mirror)

        target = os.path.join(self.temp, chroot)

        self.log.info(f"{chroot} - bootstrapping {distro} {codename} {arch}...")
        self.debbootstrap(chroot, arch, target, mirror, codename)
        self.write_file(chroot, "/etc/hosts")
        os.mkdir(os.path.join(target, "disks"), 0o755)
        os.mkdir(os.path.join(target, "fll"), 0o755)

    def write_apt_lists(
        self, chroot: str, cached: bool = False, src_uri: bool = False
    ) -> None:
        """Write apt source lists to /etc/apt/sources.list.d/*."""
        distro = self.conf["chroots"][chroot]["packages"]["distro"]
        chroot_dir = os.path.join(self.temp, chroot)
        apt_proxy = self._detect_apt_proxy()
        for dist_repo in self.conf["chroots"][chroot]["repos"].keys():
            repo = self.conf["chroots"][chroot]["repos"][dist_repo]
            repo_uri = repo.get("uri")
            cached_uri = repo.get("cached")
            if not cached_uri and apt_proxy and repo_uri:
                cached_uri = proxy_uri(apt_proxy, repo_uri)
            sources_uri = repo.get("sources_uri")
            if sources_uri:
                cmd = ["wget", "--quiet", sources_uri, "-O"]
                cmd.append(
                    os.path.join(
                        chroot_dir,
                        "etc/apt/sources.list.d",
                        os.path.basename(sources_uri),
                    )
                )
                self.exec_cmd(cmd)

                if cached and cached_uri:
                    wget_sources_file = os.path.join(
                        chroot_dir,
                        "etc/apt/sources.list.d",
                        os.path.basename(sources_uri),
                    )
                    try:
                        with open(wget_sources_file) as sources_file_fh:
                            lines = sources_file_fh.readlines()
                        with open(wget_sources_file, "w") as sources_file_fh:
                            for line in lines:
                                if line.startswith("URIs:"):
                                    sources_file_fh.write(f"URIs: {cached_uri}\n")
                                else:
                                    sources_file_fh.write(line)
                    except OSError:
                        self.log.exception(f"failed to rewrite {wget_sources_file}")
                        raise FllError
                continue

            sources_file = os.path.join(
                chroot_dir, "etc/apt/sources.list.d", dist_repo + ".sources"
            )

            self.log.debug(f"creating {sources_file}")
            try:
                with open(sources_file, "w") as sources_file_fh:
                    if src_uri:
                        sources_file_fh.write("Types: deb deb-src\n")
                    else:
                        sources_file_fh.write("Types: deb\n")
                    if cached and cached_uri:
                        sources_file_fh.write(f"URIs: {cached_uri}\n")
                    else:
                        sources_file_fh.write(f"URIs: {repo_uri}\n")
                    sources_file_fh.write(f"Suites: {repo['suite']}\n")
                    sources_file_fh.write(f"Components: {repo['components']}\n")
                    if repo.get("keyring"):
                        sources_file_fh.write(
                            f"Signed-by: /usr/share/keyrings/{repo['keyring']}.gpg\n"
                        )
                    else:
                        sources_file_fh.write(
                            f"Signed-by: /usr/share/keyrings/{distro}-archive-keyring.gpg\n"
                        )
            except OSError:
                self.log.exception(f"failed to open {sources_file}")
                raise FllError

    def prime_apt(self, chroot: str) -> None:
        """Prepare apt for work in each build chroot. Fetch all required gpg
        keys and initialize apt_pkg config."""
        self.log.info(f"{chroot} - preparing apt...")
        chroot_dir = os.path.join(self.temp, chroot)

        apt_preferences = self.conf["options"].get("apt_preferences")
        if apt_preferences:
            self.log.info(
                f"{chroot} - importing apt preferences file: {apt_preferences}"
            )
            try:
                shutil.copy(apt_preferences, os.path.join(chroot_dir, "etc/apt/"))
            except OSError:
                self.log.error(f"failed to import apt preferences: {apt_preferences}")
                raise FllError

        sources_list = os.path.join(chroot_dir, "etc/apt/sources.list")
        if os.path.isfile(sources_list):
            os.unlink(sources_list)

        src_uri = not self.opts.binary
        self.write_apt_lists(chroot, cached=True, src_uri=src_uri)

        keyrings = list()
        for dist_repo in self.conf["chroots"][chroot]["repos"].keys():
            repo = self.conf["chroots"][chroot]["repos"][dist_repo]
            keyring = repo.get("keyring")
            if keyring:
                keyrings.append(keyring)

        if keyrings:
            self.apt_get(chroot, "update", insecure=True)
            self.apt_get(chroot, "install", args=keyrings, insecure=True)

        self.apt_get(chroot, "update")
        self.apt_get(chroot, "dist-upgrade")

    def dpkg_divert(self, chroot: str) -> None:
        """Divert some facilities and replace temporaily with /bin/true (or
        some other more appropiate facility."""
        chroot_dir = os.path.join(self.temp, chroot)
        for divert in self.diverts:
            self.log.debug(f"diverting {divert}")
            self.chroot_exec(chroot, [
                "dpkg-divert", "--add", "--local",
                "--divert", f"{divert}.REAL", "--rename", divert,
            ])

            if divert == "/usr/sbin/policy-rc.d":
                self.write_file(chroot, divert)
                os.chmod(os.path.join(chroot_dir, divert.lstrip("/")), 0o755)
            else:
                os.symlink("/bin/true", os.path.join(chroot_dir, divert.lstrip("/")))

    def dpkg_undo_divert(self, chroot: str) -> None:
        """Undivert facilities diverted by self.dpkg_divert()."""
        chroot_dir = os.path.join(self.temp, chroot)
        for divert in self.diverts:
            self.log.debug(f"undoing diversion: {divert}")
            os.unlink(os.path.join(chroot_dir, divert.lstrip("/")))
            self.chroot_exec(chroot, ["dpkg-divert", "--remove", "--rename", divert])

    def preseed_debconf(self, chroot: str) -> None:
        """Preseed debconf with values read from package lists."""
        chroot_dir = os.path.join(self.temp, chroot)
        debconf_list = self.profiles[chroot].debconf

        if not debconf_list:
            return

        self.log.debug(f"{chroot} - preseeding debconf...")
        debconf_filename = os.path.join(chroot_dir, "fll", "fll_debconf_selections")
        with open(debconf_filename, "w") as debconf_fh:
            debconf_fh.writelines([f"{d}\n" for d in debconf_list])

        cmd = ["debconf-set-selections"]
        if self.opts.verbose:
            cmd.append("--verbose")
        cmd.append("/fll/fll_debconf_selections")
        self.chroot_exec(chroot, cmd)

    def install_packages(self, chroot: str) -> None:
        """Install packages."""
        from pyfll.util import deduplicate_list

        available = self._read_apt_packages(chroot)
        installed = set(self._read_dpkg_status(chroot).keys())

        pkgs_base = list(installed)
        pkgs_want = deduplicate_list(pkgs_base + list(self.profiles[chroot].packages))
        pkgs_dict = dict([(pkg, True) for pkg in pkgs_want])
        rec_pkgs = self.detect_recommended_packages(
            pkgs_dict, available, installed,
            recommended_by=self.profiles[chroot].recommended_by,
        )
        pkgs_want = deduplicate_list(list(pkgs_dict.keys()) + rec_pkgs)
        pkgs_dict = dict([(pkg, True) for pkg in pkgs_want])
        loc_list = (
            [loc for loc in self.conf["chroots"][chroot]["packages"]["locales"]]
            if self.conf["chroots"][chroot]["packages"].get("locales")
            else self.opts.locales
        )
        loc_pkgs = self.detect_locale_packages(loc_list, pkgs_dict, available)
        pkgs_want = deduplicate_list(list(pkgs_dict.keys()) + loc_pkgs)

        self.log.info(f"{chroot} - installing packages...")
        try:
            self.apt_get(chroot, "install", args=pkgs_want, quiet=True)
        except FllError:
            # Skip analysis when a sibling chroot's failure aborted us.
            if not self._abort.is_set():
                self.diagnose_install_failure(chroot, pkgs_want, installed)
            raise

    def diagnose_install_failure(
        self, chroot: str, wanted: list, installed: set
    ) -> None:
        """Explain a failed 'apt-get install' in human terms.

        The real install runs with -qq and streams apt's output at debug level,
        so a resolution failure surfaces only as a generic non-zero exit. Here
        we work out which of the requested packages is to blame: first the names
        that exist in no configured repository, then - by re-running the
        selection under --simulate, which reproduces a resolution failure
        without downloading - apt's own unmet-dependency diagnosis.

        Best-effort and never raises: analysis must not mask the original error.
        """
        try:
            self.log.error(f"{chroot} - analysing package installation failure...")

            # Only packages apt was asked to bring in can be at fault; the rest
            # are already installed.
            additions = sorted(set(wanted) - installed)
            available = self._available_package_names(chroot)

            unknown = [p for p in additions if p not in available]
            if unknown:
                self.log.error(
                    f"{chroot} - {len(unknown)} requested package(s) not found in "
                    f"any configured repository (typo, rename, or a missing "
                    f"component/suite?):"
                )
                for pkg in unknown:
                    self.log.error(f"{chroot} -     {pkg}")

            # Drop the unknown names so apt gets past "unable to locate" and can
            # report deeper conflicts among packages that do exist.
            solvable = [p for p in wanted if p in available]
            rc, output = self._apt_simulate(chroot, solvable)
            if rc == 0:
                if not unknown:
                    self.log.error(
                        f"{chroot} - dependencies resolve cleanly; the failure was "
                        f"during download, unpacking or configuration - see the "
                        f"chroot log above for the failing package."
                    )
                return

            diagnosis, cascade = self._parse_apt_problems(output)
            if diagnosis:
                self.log.error(f"{chroot} - apt could not satisfy the selection:")
                for line in diagnosis:
                    self.log.error(f"{chroot} -     {line}")
                # The conflict is over a package the resolver picked, usually a
                # library rather than an authored name. Trace it back to the
                # profile/module package list, the only thing the user actually
                # controls, naming the file each culprit is in. A whitelisted
                # recommend is the most common cause and we already know which
                # package pulled it in, so check that first.
                profile = self.profiles[chroot]
                authored = set(profile.packages)
                for pkg in self._conflict_subjects(diagnosis):
                    recommenders = profile.recommended_by.get(pkg)
                    if recommenders:
                        self.log.error(
                            f"{chroot} - {pkg} was added as a Recommends of "
                            f"{self._pkg_origins(profile, recommenders)}, "
                            f"whitelisted in {RECOMMENDS_WHITELIST}"
                        )
                    elif pkg in authored:
                        src = profile.sources.get(pkg)
                        where = ", ".join(sorted(src)) if src else "the build config"
                        self.log.error(
                            f"{chroot} - {pkg} is named directly in {where}"
                        )
                    elif pullers := self._selected_rdepends(chroot, pkg, authored):
                        self.log.error(
                            f"{chroot} - {pkg} was pulled in by "
                            f"{self._pkg_origins(profile, pullers)}"
                        )
                    else:
                        self.log.error(
                            f"{chroot} - {pkg} could not be traced to a "
                            f"profile/module package (installed as a dependency)"
                        )

            # The solver names its conflicting packages in the indented lines
            # after 'E:'. When it did, the cascade of downstream "not going to
            # be installed" lines is noise: demote it to debug (still in the
            # full log file) and lead with the diagnosis above. Otherwise the
            # cascade is all we have, so show it and point at the culprits.
            detailed = any(not line.startswith("E:") for line in diagnosis)
            if cascade and detailed:
                for line in cascade:
                    self.log.debug(f"{chroot} -     {line}")
                self.log.error(
                    f"{chroot} - ({len(cascade)} downstream unmet-dependency "
                    f"line(s) suppressed; see debug log for the full cascade)"
                )
            elif cascade:
                if not diagnosis:
                    self.log.error(
                        f"{chroot} - apt could not satisfy the selection:"
                    )
                for line in cascade:
                    self.log.error(f"{chroot} -     {line}")
                culprits = sorted(
                    p for p in additions
                    if any(r.split(" :", 1)[0] == p for r in cascade)
                )
                if culprits:
                    self.log.error(
                        f"{chroot} - selected package(s) directly implicated: "
                        f"{' '.join(culprits)}"
                    )
        except Exception:
            self.log.debug(
                f"{chroot} - package failure analysis failed", exc_info=True
            )

    def _available_package_names(self, chroot: str) -> set:
        """Return every installable name (real packages plus Provides) from the
        apt indexes, for spotting requested names that exist nowhere."""
        names = set()
        lists_dir = os.path.join(self.temp, chroot, "var/lib/apt/lists")
        if not os.path.isdir(lists_dir):
            return names
        for fname in os.listdir(lists_dir):
            if not fname.endswith("_Packages"):
                continue
            with open(os.path.join(lists_dir, fname)) as f:
                for line in f:
                    if line.startswith("Package: "):
                        names.add(line[9:].strip())
                    elif line.startswith("Provides: "):
                        for prov in line[10:].split(","):
                            prov = prov.strip().split(" ")[0]
                            if prov:
                                names.add(prov)
        return names

    def _apt_simulate(self, chroot: str, packages: list) -> tuple:
        """Run 'apt-get install --simulate' for *packages*, returning
        (returncode, combined_output). Mirrors the recommends policy of the real
        install so the resolver behaves identically."""
        aptget = [
            "apt-get", "install", "--simulate",
            "-o", "Acquire::Languages=none",
            "-o", "APT::Color=0",
        ]
        if self.conf["options"].get("apt_recommends", "no") == "no":
            aptget.extend(["-o", "APT::Install-Recommends=0"])
        aptget.extend(packages)
        result = subprocess.run(
            self._nspawn_cmd(chroot, aptget),
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return result.returncode, result.stdout

    def _parse_apt_problems(self, output: str) -> tuple:
        """Split apt's simulate output into (diagnosis, cascade).

        diagnosis: the 'E:' error line(s) and the indented lines the solver
            prints after them - its conflicting assignments, i.e. the actual
            reason the selection is unsatisfiable.
        cascade: the '<pkg> : Depends: ...' entries under "unmet
            dependencies:", which are mostly downstream fallout once the root
            conflict is known.
        """
        diagnosis = []
        cascade = []
        target = None
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                target = None
            elif "have unmet dependencies:" in stripped:
                target = cascade
            elif line.startswith("E:"):
                target = diagnosis
                diagnosis.append(stripped)
            elif target is not None and line[:1].isspace():
                target.append(stripped)
            else:
                target = None
        return diagnosis, cascade

    def _conflict_subjects(self, diagnosis: list) -> list:
        """Extract the package names from the solver's numbered conflicting-
        assignment lines ('1. <name>:<arch>=<ver> is selected for install'),
        stripping the :architecture and =version suffixes."""
        subjects = []
        for line in diagnosis:
            head, sep, rest = line.partition(".")
            if not (sep and head.strip().isdigit() and rest.strip()):
                continue
            token = rest.strip().split()[0]
            name = token.split("=", 1)[0].split(":", 1)[0]
            if name and name not in subjects:
                subjects.append(name)
        return subjects

    def _pkg_origins(self, profile, pkgs: list) -> str:
        """Render *pkgs* with the profile/module file each was declared in, e.g.
        'mpv (modules/hyprland-extra)'. Packages with no recorded source (added
        from build config rather than a file) are shown bare."""
        parts = []
        for pkg in sorted(pkgs):
            sources = profile.sources.get(pkg)
            if sources:
                parts.append(f"{pkg} ({', '.join(sorted(sources))})")
            else:
                parts.append(pkg)
        return ", ".join(parts)

    def _selected_rdepends(self, chroot: str, pkg: str, selected: set) -> list:
        """Return the members of *selected* that reverse-depend on *pkg*,
        directly or transitively, per apt-cache. Identifies which profile/module
        package dragged an otherwise-uninstallable package into the resolution."""
        aptcache = [
            "apt-cache", "rdepends", "--recurse",
            "--no-suggests", "--no-conflicts", "--no-breaks",
            "--no-replaces", "--no-enhances",
        ]
        # Mirror the install's recommends policy so the trace only follows
        # edges the resolver actually would have.
        if self.conf["options"].get("apt_recommends", "no") == "no":
            aptcache.append("--no-recommends")
        aptcache.append(pkg)
        result = subprocess.run(
            self._nspawn_cmd(chroot, aptcache),
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        names = set()
        for line in result.stdout.splitlines():
            # Dependents are indented; alternatives carry a leading '|'.
            if not line[:1].isspace():
                continue
            name = line.strip().lstrip("|").strip().split(" ")[0].split(":", 1)[0]
            if name:
                names.add(name)
        return sorted((names & selected) - {pkg})

    def install_flatpaks(self, chroot: str) -> None:
        """Install flatpaks"""
        if not any(
            [self.profiles[chroot].flatpaks, self.profiles[chroot].flatpaks_beta]
        ):
            return
        self.log.info(
            f"{chroot} - configuring flatpak remotes and installing flatpaks..."
        )
        flatpak_base = ["flatpak"]
        if self.opts.verbose:
            flatpak_base.append("--verbose")
        elif self.opts.debug:
            flatpak_base.append("-vv")
        flatpaks = self.profiles[chroot].flatpaks
        if "flatpak" in self.profiles[chroot].packages:
            self.chroot_exec(chroot, [
                *flatpak_base, "remote-add", "--if-not-exists",
                "flathub", "https://flathub.org/repo/flathub.flatpakrepo",
            ], capability="all")
            for flatpak in flatpaks:
                self.chroot_exec(chroot, [
                    *flatpak_base, "install", "--noninteractive", "--assumeyes",
                    "flathub", flatpak,
                ], capability="all")

        flatpaks_beta = self.profiles[chroot].flatpaks_beta
        if len(flatpaks_beta) > 0:
            self.chroot_exec(chroot, [
                *flatpak_base, "remote-add", "--if-not-exists",
                "flathub-beta", "https://flathub.org/beta-repo/flathub-beta.flatpakrepo",
            ], capability="all")
            for flatpak in flatpaks_beta:
                self.chroot_exec(chroot, [
                    *flatpak_base, "install", "--noninteractive", "--assumeyes",
                    "flathub-beta", flatpak,
                ], capability="all")

    def pre_installation(self, chroot: str) -> None:
        """Run package module preinst scripts in a chroot."""
        chroot_dir = os.path.join(self.temp, chroot)

        self.log.info(f"{chroot} - executing preinst scripts...")

        for script in self.profiles[chroot].preinst:
            sname = os.path.basename(script)
            try:
                shutil.copy(script, os.path.join(chroot_dir, "fll"))
                os.chmod(os.path.join(chroot_dir, "fll", sname), 0o755)
            except OSError:
                self.log.exception(f"error preparing preinst script: {sname}")
                raise FllError

            self.chroot_exec(chroot, [f"/fll/{sname}", "preinst"])
            os.unlink(os.path.join(chroot_dir, "fll", sname))

    def post_installation(self, chroot: str) -> None:
        """Run package module postinst scripts in a chroot."""
        chroot_dir = os.path.join(self.temp, chroot)

        self.log.info(f"{chroot} - executing postinst scripts...")

        for script in self.profiles[chroot].postinst:
            sname = os.path.basename(script)
            try:
                shutil.copy(script, os.path.join(chroot_dir, "fll"))
                os.chmod(os.path.join(chroot_dir, "fll", sname), 0o755)
            except OSError:
                self.log.exception(f"error preparing postinst script: {sname}")
                raise FllError

            self.chroot_exec(chroot, [f"/fll/{sname}", "postinst"])
            os.unlink(os.path.join(chroot_dir, "fll", sname))

    def create_initramfs(self, chroot: str) -> None:
        """Create an initramfs"""
        initramfs_tool = self.conf["options"].get("initramfs_tool")
        initramfs_comp = self.conf["options"].get("initramfs_comp")
        kvers = self.detect_linux_version(chroot)
        for kernel in kvers:
            cmd = None
            if initramfs_tool == "initramfs-tools":
                cmd = ["update-initramfs", "-c", "-k", kernel]
                if self.opts.verbose or self.opts.debug:
                    cmd.append("-v")
            elif initramfs_tool == "dracut":
                cmd = [
                    "dracut",
                    "--no-hostonly",
                    "--no-hostonly-i18n",
                    "--no-hostonly-cmdline",
                    "--no-hostonly-default-device",
                    "--force-add", "fll",
                    "--kver", kernel,
                ]
                if initramfs_comp:
                    cmd.append(f"--{initramfs_comp}")
                if self.opts.verbose or self.opts.debug:
                    cmd.append("--verbose")
                elif self.opts.quiet:
                    cmd.append("--quiet")
            if cmd is None:
                self.log.critical(f"unknown initramfs_tool: {initramfs_tool!r}")
                raise FllError
            self.chroot_exec(chroot, cmd)

    def hold_kernel_packages(self, chroot: str) -> None:
        """Hold kernel and header packages in the live image.

        The live-boot artifacts (vmlinuz and the initrd) live on read-only or
        FAT media that an apt transaction cannot safely rewrite, so the kernel
        is a property of the image and is refreshed only as a unit via a
        whole-image ``--upgrade <iso>``.  Hold both the metapackages and the
        installed versioned packages so apt can neither bump the versioned
        kernel directly nor pull a newer sibling transitively through the meta.
        On a dracut-only system this also freezes the initrd, as dracut rebuilds
        it on kernel events only.  Calamares releases the hold on install.

        Requires a populated manifest (write_manifest), so call after it.
        """
        flavour = self.conf["chroots"][chroot]["packages"]["linux"]
        manifest = self.profiles[chroot].manifest

        # Explicit whitelist: the image/headers metapackages, plus for every
        # installed kernel version the versioned image and headers packages and
        # the shared headers "common" package (which drops the flavour suffix).
        candidates = {f"linux-image-{flavour}", f"linux-headers-{flavour}"}
        for kver in self.detect_linux_version(chroot):
            candidates.add(f"linux-image-{kver}")
            candidates.add(f"linux-headers-{kver}")
            suffix = f"-{flavour}"
            abi = kver[: -len(suffix)] if kver.endswith(suffix) else kver
            candidates.add(f"linux-headers-{abi}-common")

        # Intersect with the manifest so we hold only packages actually
        # installed: apt-mark errors on unknown names, and this drops any
        # derived name (e.g. -common) that a given kernel does not ship.
        packages = sorted(p for p in candidates if p in manifest)
        if not packages:
            self.log.warning(f"{chroot} - no kernel packages found to hold")
            return

        log_it = self.log.info if self.opts.verbose else self.log.debug
        log_it(f"{chroot} - holding kernel packages: {' '.join(packages)}")
        self.chroot_exec(chroot, ["apt-mark", "hold"] + packages)

    def zero_logs(self, chroot: str, dirname: str, filenames: list) -> None:
        """Truncate all log files."""
        chrootdir = os.path.relpath(dirname, os.path.join(self.temp, chroot))

        for f in filenames:
            if not os.path.isfile(os.path.join(dirname, f)):
                continue
            self.write_file(chroot, os.path.join(chrootdir, f))

    def clean_chroot(self, chroot: str) -> None:
        """Remove unwanted content from a chroot."""
        self.log.debug(f"{chroot} - purging unwanted content...")

        self.chroot_exec(chroot, ["dpkg", "--purge", "fll-live-initramfs"])
        self.chroot_exec(chroot, ["apt-get", "clean"])
        self.chroot_exec(chroot, ["dpkg", "--clear-avail"])

        chroot_dir = os.path.join(self.temp, chroot)
        for dirpath, dirnames, files in os.walk(os.path.join(chroot_dir, "var/log")):
            self.zero_logs(chroot, dirpath, files)

    def configure_locales(self, chroot: str) -> None:
        """Generate locales."""
        chroot_dir = os.path.join(self.temp, chroot)
        locales_list = (
            [loc for loc in self.conf["chroots"][chroot]["packages"]["locales"]]
            if self.conf["chroots"][chroot]["packages"].get("locales")
            else self.opts.locales
        )
        default_locale = f"{locales_list[0]}.UTF-8"
        with open(os.path.join(chroot_dir, "etc", "locale.gen"), "a") as locale_gen:
            locale_gen.write("\n# Locales enabled by fll\n")
            for locale in locales_list:
                self.log.debug(f"enabling locale: {locale}.UTF-8 UTF-8")
                locale_gen.write(f"{locale}.UTF-8 UTF-8\n")
        self.chroot_exec(chroot, ["locale-gen"])
        self.chroot_exec(chroot, ["update-locale", f"LANG={default_locale}"])
