# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import os
from dataclasses import dataclass, field

from configobj import ConfigObj
from debian.debian_support import Version

from pyfll.exceptions import FllError, FllLocalesError
from pyfll.locales import FllLocales
from pyfll.util import deduplicate_list, multiline_to_list

# Path, relative to --share, of the whitelist controlling which packages'
# Recommends get pulled in. Also used as the label surfaced in failure analysis.
RECOMMENDS_WHITELIST = os.path.join("modules", "recommends")


def source_pkg_specs(status: dict, packages: list) -> list:
    """Build deduplicated apt-get source specs ('<source>=<source_version>')
    from parsed dpkg status data, skipping cdebootstrap-helper packages."""
    seen = set()
    specs = []
    for pkg in packages:
        if pkg.startswith("cdebootstrap-helper"):
            continue
        srcpkg = status[pkg]["source"]
        srcver = status[pkg]["source_version"]
        if (srcpkg, srcver) not in seen:
            seen.add((srcpkg, srcver))
            specs.append(f"{srcpkg}={srcver}")
    return specs


def parse_dependency_groups(dep_str: str) -> list:
    """Parse a Depends/Recommends string into a list of OR groups.
    Each group is a list of package names (version constraints stripped)."""
    groups = []
    for group in dep_str.split(","):
        alts = []
        for alt in group.split("|"):
            alt = alt.strip()
            if alt:
                alts.append(alt.split()[0])
        if alts:
            groups.append(alts)
    return groups


@dataclass
class FllProfile:
    """
    Holds the package-related data collected from a single profile file and
    all modules it references.

    Attributes:
        debconf       - debconf pre-seed lines loaded pre-installation
        packages      - Debian package names
        sources       - package name -> set of profile/module files declaring it
        recommended_by - recommended package -> set of packages that recommend it
        flatpaks      - flatpak app IDs from flathub
        flatpaks_beta - flatpak app IDs from flathub-beta
        desktops      - X11/wayland session .desktop file names
        groups        - groups to add live user into
        preinst       - paths to preinst scripts to run pre-installation
        postinst      - paths to postinst scripts to run post-installation
        manifest      - package manifest data
    """

    debconf: set = field(default_factory=set)
    packages: set = field(default_factory=set)
    sources: dict = field(default_factory=dict)
    recommended_by: dict = field(default_factory=dict)
    flatpaks: set = field(default_factory=set)
    flatpaks_beta: set = field(default_factory=set)
    desktops: set = field(default_factory=set)
    groups: set = field(default_factory=set)
    preinst: set = field(default_factory=set)
    postinst: set = field(default_factory=set)
    manifest: dict = field(default_factory=dict)

    def add_package(self, name, source=None):
        """Add a package, optionally recording the file it was declared in
        (used to trace an install failure back to a profile or module)."""
        self.packages.add(name)
        if source:
            self.sources.setdefault(name, set()).add(source)

    def merge(self, other):
        """Add all items from another FllProfile into this one."""
        self.debconf.update(other.debconf)
        self.packages.update(other.packages)
        for name, origins in other.sources.items():
            self.sources.setdefault(name, set()).update(origins)
        self.flatpaks.update(other.flatpaks)
        self.flatpaks_beta.update(other.flatpaks_beta)
        self.desktops.update(other.desktops)
        self.groups.update(other.groups)
        self.preinst.update(other.preinst)
        self.postinst.update(other.postinst)


class PackageProfileMixin:
    """Mixin providing package profile parsing, dependency resolution, and manifest writing."""

    def expand_pkg_profile(
        self, chroot: str, profile: str, modules_dir: str
    ) -> FllProfile:
        """Return a FllProfile for a given chroot and profile."""
        pkg_profile = FllProfile()
        for package in self.conf["chroots"][chroot]["packages"].get("packages"):
            pkg_profile.packages.add(package)
        arch = self.conf["chroots"][chroot]["packages"]["arch"]
        linux = self.conf["chroots"][chroot]["packages"]["linux"]
        browsers = self.conf["chroots"][chroot]["packages"]["browser"]
        for browser in browsers:
            pkg_profile.packages.add(browser)

        ro_fs = self.conf["options"]["readonly_filesystem"]
        if ro_fs == "squashfs":
            pkg_profile.packages.add("squashfs-tools")
        elif ro_fs == "erofs":
            pkg_profile.packages.add("erofs-utils")

        initramfs_tool = self.conf["options"]["initramfs_tool"]
        pkg_profile.packages.add(initramfs_tool)

        bootloader = self.conf["options"]["bootloader"]
        if bootloader == "grub" or bootloader == "grub-efi":
            if arch in ("amd64", "i386") and bootloader == "grub":
                pkg_profile.packages.add("grub-pc")
            if arch == "amd64":
                pkg_profile.packages.add("grub-efi-amd64-bin")
            elif arch == "i386":
                pkg_profile.packages.add("grub-efi-ia32-bin")
            elif arch == "arm64":
                pkg_profile.packages.add("grub-efi-arm64-bin")
        elif bootloader == "systemd-boot":
            pkg_profile.packages.update(["systemd-boot", "systemd-boot-efi"])
        elif bootloader == "refind":
            pkg_profile.packages.add("refind")
            pkg_profile.debconf.add("refind refind/install_to_esp boolean false")

        if self.conf["options"].get("homed"):
            pkg_profile.packages.add("systemd-homed")

        linux_meta = ["linux-image", "linux-headers"]
        pkg_profile.packages.update(
            ["-".join([prefix, linux]) for prefix in linux_meta]
        )

        pkg_profile.flatpaks = set(
            self.conf["chroots"][chroot]["flatpak"]["flathub"]["flatpaks"]
        )
        pkg_profile.flatpaks_beta = set(
            self.conf["chroots"][chroot]["flatpak"]["flathub-beta"]["flatpaks"]
        )

        fll_profile_spec = os.path.join(self.opts.share, "fll.profile.spec")
        profile_conf = ConfigObj(profile, configspec=fll_profile_spec)
        self.validate_configobj(profile_conf)
        profile_origin = os.path.relpath(profile, self.opts.share)

        if "desc" in profile_conf:
            for line in multiline_to_list(profile_conf["desc"]):
                self.log.debug(f"  {line}")

        if "debconf" in profile_conf:
            self.log.debug("debconf:")
            for line in multiline_to_list(profile_conf["debconf"]):
                pkg_profile.debconf.add(line)
                self.log.debug(f"  {line}")

        if "packages" in profile_conf:
            self.log.debug("packages:")
            for line in multiline_to_list(profile_conf["packages"]):
                pkg_profile.add_package(line, profile_origin)
                self.log.debug(f"  {line}")

        packages_arch = f"packages_{arch}"
        if packages_arch in profile_conf:
            self.log.debug(f"packages_{arch}:")
            for line in multiline_to_list(profile_conf[packages_arch]):
                pkg_profile.add_package(line, profile_origin)
                self.log.debug(f"  {line}")

        if "flatpaks" in profile_conf:
            self.log.debug("flatpaks:")
            for line in multiline_to_list(profile_conf["flatpaks"]):
                pkg_profile.flatpaks.add(line)
                self.log.debug(f"  {line}")

        if "flatpaks_beta" in profile_conf:
            self.log.debug("flatpaks_beta:")
            for line in multiline_to_list(profile_conf["flatpaks_beta"]):
                pkg_profile.flatpaks_beta.add(line)
                self.log.debug(f"  {line}")

        if "desktops" in profile_conf:
            self.log.debug("desktops:")
            for line in multiline_to_list(profile_conf["desktops"]):
                pkg_profile.desktops.add(line)
                self.log.debug(f"  {line}")

        if "groups" in profile_conf:
            self.log.debug("groups:")
            for line in multiline_to_list(profile_conf["groups"]):
                pkg_profile.groups.add(line)
                self.log.debug(f"  {line}")

        modules = set()
        if "modules" in profile_conf:
            self.log.debug("modules:")
            for module in multiline_to_list(profile_conf["modules"]):
                modules.add(module)
                self.log.debug(f"  {module}")

        if "modules" in self.conf["chroots"][chroot]["packages"]:
            self.log.debug("modules (config):")
            for module in self.conf["chroots"][chroot]["packages"]["modules"]:
                modules.add(module)
                self.log.debug(f"  {module}")

        if os.path.isfile(profile + ".preinst"):
            self.log.debug(f"registering preinst script: {profile}.preinst")
            pkg_profile.preinst.add(profile + ".preinst")

        if os.path.isfile(profile + ".postinst"):
            self.log.debug(f"registering postinst script: {profile}.postinst")
            pkg_profile.postinst.add(profile + ".postinst")

        self.log.debug("---")
        fll_module_spec = os.path.join(self.opts.share, "fll.module.spec")
        for module in modules:
            module_file = os.path.join(modules_dir, module)

            if not os.path.isfile(module_file):
                self.log.critical(f"no such module file: {module_file}")
                raise FllError

            module_conf = ConfigObj(module_file, configspec=fll_module_spec)
            self.validate_configobj(module_conf)
            module_origin = os.path.relpath(module_file, self.opts.share)

            if "desc" in module_conf:
                for line in multiline_to_list(module_conf["desc"]):
                    self.log.debug(f"  {line}")

            if "debconf" in module_conf:
                self.log.debug("debconf:")
                for line in multiline_to_list(module_conf["debconf"]):
                    pkg_profile.debconf.add(line)
                    self.log.debug(f"  {line}")

            if "packages" in module_conf:
                self.log.debug("packages:")
                for line in multiline_to_list(module_conf["packages"]):
                    pkg_profile.add_package(line, module_origin)
                    self.log.debug(f"  {line}")

            packages_arch = f"packages_{arch}"
            if packages_arch in module_conf:
                self.log.debug(f"packages_{arch}:")
                for line in multiline_to_list(module_conf[packages_arch]):
                    pkg_profile.add_package(line, module_origin)
                    self.log.debug(f"  {line}")

            if "flatpaks" in module_conf:
                self.log.debug("flatpaks:")
                for line in multiline_to_list(module_conf["flatpaks"]):
                    pkg_profile.flatpaks.add(line)
                    self.log.debug(f"  {line}")

            if "flatpaks_beta" in module_conf:
                self.log.debug("flatpaks_beta:")
                for line in multiline_to_list(module_conf["flatpaks_beta"]):
                    pkg_profile.flatpaks_beta.add(line)
                    self.log.debug(f"  {line}")

            if "desktops" in module_conf:
                self.log.debug("desktops:")
                for line in multiline_to_list(module_conf["desktops"]):
                    pkg_profile.desktops.add(line)
                    self.log.debug(f"  {line}")

            if "groups" in module_conf:
                self.log.debug("groups:")
                for line in multiline_to_list(module_conf["groups"]):
                    pkg_profile.groups.add(line)
                    self.log.debug(f"  {line}")

            if os.path.isfile(module_file + ".preinst"):
                self.log.debug(f"registering preinst script: {module_file}.preinst")
                pkg_profile.preinst.add(module_file + ".preinst")

            if os.path.isfile(module_file + ".postinst"):
                self.log.debug(f"registering postinst script: {module_file}.postinst")
                pkg_profile.postinst.add(module_file + ".postinst")

            self.log.debug("---")

        if any([pkg_profile.flatpaks, pkg_profile.flatpaks_beta]):
            pkg_profile.packages.add("flatpak")

        return pkg_profile

    def parse_package_profile(self, chroot: str) -> FllProfile:
        """Parse packages profile for each chroot."""
        profiles = self.conf["chroots"][chroot]["packages"]["profile"]
        profile_dir = os.path.join(self.opts.share, "profiles")
        modules_dir = os.path.join(self.opts.share, "modules")

        chroot_profile = FllProfile()
        for profile_name in profiles:
            self.log.info(f"{chroot} - processing package profile: {profile_name}")
            profile_path = os.path.join(profile_dir, profile_name)
            if not os.path.isfile(profile_path):
                self.log.critical(f"no such package profile: {profile_path}")
                raise FllError
            chroot_profile.merge(
                self.expand_pkg_profile(chroot, profile_path, modules_dir)
            )

        self.log.debug(f"debconf summary for {chroot}:")
        for item in sorted(chroot_profile.debconf):
            self.log.debug(f"  {item}")

        self.log.debug(f"desktops summary for {chroot}:")
        for item in sorted(chroot_profile.desktops):
            self.log.debug(f"  {item}")

        self.log.debug(f"package summary for {chroot}:")
        for item in sorted(chroot_profile.packages):
            self.log.debug(f"  {item}")

        self.log.debug(f"flatpaks summary for {chroot}:")
        for item in sorted(chroot_profile.flatpaks):
            self.log.debug(f"  {item}")

        self.log.debug(f"flatpaks_beta summary for {chroot}:")
        for item in sorted(chroot_profile.flatpaks_beta):
            self.log.debug(f"  {item}")

        self.log.debug(f"groups summary for {chroot}:")
        for item in sorted(chroot_profile.groups):
            self.log.debug(f"  {item}")

        self.log.debug(f"preinst summary for {chroot}:")
        for item in sorted(chroot_profile.preinst):
            self.log.debug(f"  {item}")

        self.log.debug(f"postinst summary for {chroot}:")
        for item in sorted(chroot_profile.postinst):
            self.log.debug(f"  {item}")

        return chroot_profile

    def detect_linux_version(self, chroot: str) -> list:
        """Return a list of installed linux-image version strings, newest first."""
        linux = self.conf["chroots"][chroot]["packages"]["linux"]
        linux_meta = f"linux-image-{linux}"
        linux_images = [
            f[len("linux-image-"):]
            for f in self.profiles[chroot].manifest
            if f.startswith("linux-image-") and not f == linux_meta
        ]

        if len(linux_images) > 0:
            linux_images.sort(key=Version, reverse=True)
            return linux_images

        self.log.critical(f"{chroot} - failed to detect linux version")
        raise FllError

    def detect_locale_packages(
        self, locales: list, wanted: list, available: dict
    ) -> list:
        """Provide automated detection for extra locales packages."""
        self.log.debug(f"detecting packages for locales: {' '.join(locales)}")

        locales_pkg_map_file = os.path.join(self.opts.share, "data", "locales-pkg-map")
        locales_pkg_map = ConfigObj(locales_pkg_map_file)
        self.log.debug("locales_pkg_map:")
        self.log.debug(locales_pkg_map)

        fll_locales = FllLocales(available, wanted, locales_pkg_map)
        locales_list = []
        for locale in sorted(locales):
            try:
                loc_pkg_list = fll_locales.detect_locale_packages(locale)
            except FllLocalesError:
                self.log.exception(f"Failed to parse locale string: {locale}")
                raise FllError
            else:
                locales_list.extend(loc_pkg_list)

        self.log.debug(f"locales_list: {' '.join(locales_list)}")
        return locales_list

    def detect_recommended_packages(
        self, wanted: dict, available: dict, installed: set, recommended_by: dict = None
    ) -> list:
        """Provide automated detection for packages in recommends whitelist.

        When *recommended_by* is given, records each detected package ->
        the package that recommended it, so an install failure can be traced
        back to its origin."""
        apt_recommends = self.conf["options"].get("apt_recommends")
        if apt_recommends == "yes":
            return []

        self.log.debug("detecting whitelisted recommended packages...")
        rec_module = ConfigObj(os.path.join(self.opts.share, RECOMMENDS_WHITELIST))
        try:
            rec_dict = dict(
                [(p, True) for p in multiline_to_list(rec_module["packages"])]
            )
        except KeyError:
            return []

        self.log.debug(f"rec_dict: {rec_dict}")

        rec_list = []
        for p in wanted.keys():
            if p not in rec_dict:
                continue
            pkg_data = available.get(p)
            if not pkg_data:
                continue
            recommends_str = pkg_data.get("recommends", "")
            if not recommends_str:
                continue
            for group in parse_dependency_groups(recommends_str):
                if any(alt in wanted for alt in group):
                    continue
                first = group[0]
                if first not in installed:
                    self.log.debug(f"recommended package detected: {first} (via {p})")
                    rec_list.append(first)
                    if recommended_by is not None:
                        recommended_by.setdefault(first, set()).add(p)
        return rec_list

    def _read_dpkg_status(self, chroot: str) -> dict:
        """Parse /var/lib/dpkg/status; return {name: {version, source, source_version}}
        for each installed package."""
        status_file = os.path.join(self.temp, chroot, "var/lib/dpkg/status")
        packages = {}
        with open(status_file) as f:
            for stanza_text in f.read().split("\n\n"):
                stanza = {}
                for line in stanza_text.splitlines():
                    if line and not line.startswith(" "):
                        key, _, val = line.partition(": ")
                        stanza[key] = val
                if "installed" not in stanza.get("Status", ""):
                    continue
                name = stanza.get("Package")
                ver = stanza.get("Version")
                if not name or not ver:
                    continue
                src = stanza.get("Source", name)
                if "(" in src:
                    srcver = src[src.index("(") + 1: src.index(")")]
                    src = src[: src.index(" (")]
                else:
                    srcver = ver
                packages[name] = {
                    "version": ver,
                    "source": src,
                    "source_version": srcver,
                }
        return packages

    def _read_apt_packages(self, chroot: str) -> dict:
        """Parse apt Packages files; return {name: {version, recommends}}
        for all available packages, keeping the highest version when a package
        appears in multiple index files."""
        packages = {}
        lists_dir = os.path.join(self.temp, chroot, "var/lib/apt/lists")
        if not os.path.isdir(lists_dir):
            return packages
        for fname in sorted(os.listdir(lists_dir)):
            if not fname.endswith("_Packages"):
                continue
            with open(os.path.join(lists_dir, fname)) as f:
                for stanza_text in f.read().split("\n\n"):
                    stanza = {}
                    for line in stanza_text.splitlines():
                        if line and not line.startswith(" "):
                            key, _, val = line.partition(": ")
                            stanza[key] = val
                    name = stanza.get("Package")
                    ver = stanza.get("Version")
                    if not name or not ver:
                        continue
                    if name in packages:
                        if Version(ver) <= Version(packages[name]["version"]):
                            continue
                    packages[name] = {
                        "version": ver,
                        "recommends": stanza.get("Recommends", ""),
                    }
        return packages

    def _resolve_source_uris(self, chroot: str, srcpkg_specs: list) -> str:
        """Retrieve 'apt-get source --print-uris' output for srcpkg_specs.

        A single unresolvable spec (a repo with no deb-src, a source renamed
        or superseded in the pool since the chroot was populated, etc.) fails
        the whole batch, so on failure retry package-by-package and skip+warn
        on individual misses instead of aborting manifest generation."""
        try:
            return self.chroot_output(
                chroot, ["apt-get", "source", "--print-uris"] + srcpkg_specs
            )
        except FllError:
            self.log.warning(
                f"{chroot} - bulk source URI resolution failed; "
                "retrying package-by-package"
            )

        output = ""
        for spec in srcpkg_specs:
            try:
                output += self.chroot_output(
                    chroot, ["apt-get", "source", "--print-uris", spec], quiet=True
                )
            except FllError:
                self.log.warning(f"{chroot} - could not resolve source package: {spec}")
        return output

    def write_manifest(self, chroot: str) -> None:
        """Collect package and source package URI information from each chroot."""
        self.log.info(f"{chroot} - writing package manifest...")

        status = self._read_dpkg_status(chroot)
        manifest = {
            name: data["version"]
            for name, data in status.items()
            if not name.startswith("cdebootstrap-helper")
        }
        self.profiles[chroot].manifest = manifest

        packages = list(manifest.keys())
        if not packages:
            self.log.critical(f"{chroot} - no installed packages found in dpkg status")
            raise FllError
        pkg_maxlen = max(len(pkg) for pkg in packages)
        packages.sort()

        distro_name = self.conf["distro"]["FLL_DISTRO_NAME"]
        manifest_name = f"{distro_name}-{self.timestamp}.{self.run_id}.manifest.{chroot}"
        manifest_file = os.path.join(self.opts.output_dir, manifest_name)

        try:
            with open(manifest_file, "w") as manifest_fh:
                manifest_fh.writelines(
                    [
                        f"{pkg.ljust(pkg_maxlen)} " + f"{manifest[pkg]}\n"
                        for pkg in packages
                    ]
                )
            os.chown(manifest_file, self.opts.uid, self.opts.gid)
        except OSError:
            self.log.exception(f"failed to write file: {manifest_file}")
            raise FllError

        if self.opts.binary:
            return

        self.log.info(f"{chroot} - writing source package URIs...")
        srcpkg_specs = source_pkg_specs(status, packages)
        output = self._resolve_source_uris(chroot, srcpkg_specs)
        uris = [
            line.split("'")[1]
            for line in output.splitlines()
            if line.startswith("'")
        ]
        uris.sort()

        sources_list = deduplicate_list(uris)

        sources_name = f"{distro_name}-{self.timestamp}.{self.run_id}.sources.{chroot}"
        sources_file = os.path.join(self.opts.output_dir, sources_name)

        try:
            with open(sources_file, "w") as sources_fh:
                sources_fh.writelines([f"{s}\n" for s in sources_list])
            os.chown(sources_file, self.opts.uid, self.opts.gid)
        except OSError:
            self.log.exception(f"failed to write filename: {sources_file}")
            raise FllError
