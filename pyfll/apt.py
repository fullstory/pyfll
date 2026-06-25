# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import os
import shutil
import subprocess

from pyfll.exceptions import FllError


class AptMixin:
    """Mixin providing apt/dpkg operations, chroot bootstrap, and package installation."""

    def apt_get(
        self, chroot: str, command: str, args: list | None = None, insecure: bool = False
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

        self.chroot_exec(chroot, aptget)

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
                mirror = apt_proxy + "/" + mirror.split("//")[1]

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
                cached_uri = apt_proxy + "/" + repo_uri.split("//")[1]
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
                    cmd = ["sed", "-i", f"s#^URIs: .*#URIs: {cached_uri}#"]
                    cmd.append(
                        os.path.join(
                            chroot_dir,
                            "etc/apt/sources.list.d",
                            os.path.basename(sources_uri),
                        )
                    )
                    self.exec_cmd(cmd)
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
        rec_pkgs = self.detect_recommended_packages(pkgs_dict, available, installed)
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
        self.apt_get(chroot, "install", args=pkgs_want)

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
            ])
            for flatpak in flatpaks:
                self.chroot_exec(chroot, [
                    *flatpak_base, "install", "--noninteractive", "--assumeyes",
                    "flathub", flatpak,
                ])

        flatpaks_beta = self.profiles[chroot].flatpaks_beta
        if len(flatpaks_beta) > 0:
            self.chroot_exec(chroot, [
                *flatpak_base, "remote-add", "--if-not-exists",
                "flathub-beta", "https://flathub.org/beta-repo/flathub-beta.flatpakrepo",
            ])
            for flatpak in flatpaks_beta:
                self.chroot_exec(chroot, [
                    *flatpak_base, "install", "--noninteractive", "--assumeyes",
                    "flathub-beta", flatpak,
                ])

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
            cmd = ""
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
            self.chroot_exec(chroot, cmd)

    def zero_logs(self, chroot: str, dirname: str, filenames: list) -> None:
        """Truncate all log files."""
        chrootdir = dirname.partition(chroot)[2]

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
