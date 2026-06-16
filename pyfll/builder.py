import argparse
import atexit
import concurrent.futures
import copy
import datetime
import glob
import hashlib
import logging
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

from configobj import ConfigObj, flatten_errors
from debian.debian_support import Version
from validate import Validator

from pyfll.bootloader import BootloaderMixin
from pyfll.exceptions import FllError, FllLocalesError
from pyfll.gpt import run_gpthybrid
from pyfll.isodd import write_iso
from pyfll.locales import FllLocales
from pyfll.profile import FllProfile, parse_dependency_groups
from pyfll.util import deduplicate_list, multiline_to_list, uuidgen


class FLLBuilder(BootloaderMixin):
    env = {
        "LANGUAGE": "C",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": "/root",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SHELL": "/bin/bash",
        "DEBIAN_FRONTEND": "noninteractive",
        "DEBIAN_PRIORITY": "critical",
        "DEBCONF_NOWARNINGS": "yes",
    }

    diverts = [
        "/usr/bin/dracut",
        "/usr/sbin/policy-rc.d",
        "/usr/sbin/modprobe",
        "/usr/sbin/update-grub",
        "/usr/sbin/update-initramfs",
    ]

    def __init__(self, options: dict) -> None:
        """Accept options dict, setup logging."""
        self.opts = options
        self.conf = dict()
        self.temp = str()
        self.chroots = list()
        self.profiles = dict()

        self.log = logging.getLogger("log")
        self.log.setLevel(logging.DEBUG)

        self.time = time.perf_counter()
        self.date = datetime.datetime.now(datetime.UTC)
        self.xorriso_uuid = self.date.strftime("%Y-%m-%d-%H-%M-%S-00")
        self.persist_uuid = uuidgen()
        self.timestamp = self.date.strftime("%Y%m%d%H%M")
        self.run_id = uuidgen()[:8]
        self.live_media = str()
        self._staging_lock = threading.Lock()
        self._bootstrap_sem = threading.Semaphore(2)

    def prep_dir(self, dirname: str) -> str:
        """Set up working directories."""
        if not os.path.isdir(dirname):
            try:
                os.makedirs(dirname)
                os.chown(dirname, self.opts.uid, self.opts.gid)
            except OSError:
                self.log.exception(f"failed to create directory: {dirname}")
                raise FllError

        return os.path.realpath(dirname)

    def init_logger(self, lvl: str) -> None:
        """Set up the logger."""
        fmt = logging.Formatter("%(asctime)s %(levelname)-5s - %(message)s")
        out = logging.StreamHandler()
        out.setFormatter(fmt)
        out.setLevel(lvl)
        self.log.addHandler(out)

    def init_logfile(self) -> None:
        """Set up a log file."""
        distro_name = self.conf["distro"]["FLL_DISTRO_NAME"]
        log_filename = os.path.join(
            self.opts.output_dir, f"{distro_name}-{self.timestamp}.{self.run_id}.log"
        )
        log_filename = os.path.realpath(log_filename)
        dirname = os.path.dirname(log_filename)
        self.prep_dir(dirname)
        fmt = logging.Formatter("%(asctime)s %(levelname)-5s " + "%(message)s")
        logfile = logging.FileHandler(filename=log_filename, mode="w")
        logfile.setFormatter(fmt)
        logfile.setLevel(logging.DEBUG)
        self.log.addHandler(logfile)
        self._logfile_handler = logfile
        os.chown(log_filename, self.opts.uid, self.opts.gid)
        self.log.debug(" ".join(sys.argv))

    def init_cli_options(self) -> None:
        """Check and provide default class options."""
        if os.path.isfile(self.opts.config):
            self.opts.config = os.path.realpath(self.opts.config)
        else:
            self.log.critical(f"configuration file does not exist: {self.opts.config}")
            raise FllError

        if not os.path.isdir(self.opts.share):
            self.log.critical(f"share directory not exist: {self.opts.share}")
            raise FllError

        if self.opts.build:
            self.opts.build = self.prep_dir(self.opts.build)

        if self.opts.output_dir:
            self.opts.output_dir = self.prep_dir(self.opts.output_dir)
        else:
            self.opts.output_dir = self.opts.build

        if self.opts.debug:
            self.init_logger("DEBUG")
            self.opts.jobs = 1
        elif self.opts.verbose:
            self.init_logger("INFO")
            self.opts.jobs = 1
        else:
            self.init_logger("INFO")

    def get_distro_imagefile(self, chroot: str) -> str:
        """Return image file that compressed chroot will be archived to."""
        image_file = self.conf["distro"]["FLL_IMAGE_FILE"]
        return f"{image_file}.{chroot}"

    def get_distro_stamp(self, chroot: str) -> str:
        """Return a string suitable for the distro stamp file."""
        profiles = " ".join(self.conf["chroots"][chroot]["packages"]["profile"])
        codename = self.conf["chroots"][chroot]["packages"]["codename"]
        defaults = self.conf["distro"]
        stamp = defaults["FLL_DISTRO_NAME"]
        if defaults.get("FLL_DISTRO_VERSION") == "snapshot":
            stamp += f" - {profiles}"
            try:
                stamp += f" {codename}"
            except KeyError:
                pass
        else:
            if defaults.get("FLL_DISTRO_CODENAME_REV"):
                stamp += f" - {defaults['FLL_DISTRO_CODENAME']}"
                stamp += f" {defaults['FLL_DISTRO_CODENAME_REV']}-"
            elif defaults.get("FLL_DISTRO_CODENAME"):
                stamp += f" - {defaults['FLL_DISTRO_CODENAME']}"

            stamp += f" {profiles}"

        stamp += f" - {self.timestamp}"

        self.log.debug("stamp: %s" % stamp)
        return stamp

    def init_configuration(self) -> None:
        """Parse build configuration file and return it in a dict."""
        self.log.info(f"reading configuration file: {self.opts.config}")
        fll_config_spec = os.path.join(self.opts.share, "fll.conf.spec")
        self.conf = ConfigObj(self.opts.config, configspec=fll_config_spec)
        self.validate_configobj(self.conf)

    def validate_configobj(self, obj: ConfigObj) -> None:
        self.log.debug(f"vaildating {obj.filename}")
        validator = Validator()
        result = obj.validate(validator, preserve_errors=True)
        fatal_error = False
        for entry in flatten_errors(self.conf, result):
            section_list, key, error = entry
            if key is not None:
                section_list.append(key)
            else:
                section_list.append("[missing section]")
            section_string = " => ".join(section_list)
            if not error:
                error = "missing value or section"
            self.log.critical(f"{error}: {section_string}")
            fatal_error = True
        else:
            if fatal_error:
                raise FllError

    def write_configuration(self) -> None:
        """Save build configuration with live media. Use only at end."""
        distro_name = self.conf["distro"]["FLL_DISTRO_NAME"]
        self.conf.filename = os.path.join(
            self.opts.output_dir,
            f"{distro_name}-{self.timestamp}.{self.run_id}.fll.conf",
        )
        self.conf.write()
        os.chown(self.conf.filename, self.opts.uid, self.opts.gid)

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
                pkg_profile.packages.add(line)
                self.log.debug(f"  {line}")

        packages_arch = f"packages_{arch}"
        if packages_arch in profile_conf:
            self.log.debug(f"packages_{arch}:")
            for line in multiline_to_list(profile_conf[packages_arch]):
                pkg_profile.packages.add(line)
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
                    pkg_profile.packages.add(line)
                    self.log.debug(f"  {line}")

            packages_arch = f"packages_{arch}"
            if packages_arch in module_conf:
                self.log.debug(f"packages_{arch}:")
                for line in multiline_to_list(module_conf[packages_arch]):
                    pkg_profile.packages.add(line)
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

        self.log.debug(f"postinst summary for {chroot}:")
        for item in sorted(chroot_profile.postinst):
            self.log.debug(f"  {item}")

        return chroot_profile

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

    def init_build_directory(self) -> None:
        """Prepare temporary directory for chroots and result staging area."""
        self.log.debug("preparing build area...")

        self.temp = tempfile.mkdtemp(prefix="fll_", dir=self.opts.build)
        os.chown(self.temp, self.opts.uid, self.opts.gid)

        atexit.register(self.cleanup)

        stage = os.path.join(self.temp, "staging")
        os.makedirs(
            os.path.join(stage, self.conf["distro"]["FLL_IMAGE_DIR"]),
            0o755,
            exist_ok=True,
        )

        media_include = self.conf["options"].get("media_include")
        if media_include and os.path.isdir(media_include):
            try:
                target_dirpath = os.path.join(stage, os.path.basename(media_include))
                shutil.copytree(
                    media_include,
                    target_dirpath,
                    dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git*"),
                )
            except IOError:
                self.log.exception(
                    f"problem copying media_include data to staging dir: {media_include}"
                )
                raise FllError

    def nuke_directory(self, dirname: str) -> None:
        """Nuke directory tree."""
        if os.path.isdir(dirname):
            self.log.debug(f"nuking directory: {dirname}")
            try:
                shutil.rmtree(dirname)
            except IOError:
                self.log.exception(f"unable to remove {dirname}")
                raise FllError
        else:
            self.log.debug(f"directory does not exist: {dirname}")

    def nuke_chroot(self, chroot: str) -> None:
        """Convenience function to nuke chroot given by chroot name."""
        if not self.opts.preserve:
            self.log.info(f"{chroot} - nuking chroot...")
            self.nuke_directory(os.path.join(self.temp, chroot))

    def cleanup(self) -> None:
        """Clean up the build area after taking care that all build chroots
        have been taken care of."""
        self.log.info("cleaning up...")
        chroots = (
            [chroot for chroot in self.opts.chroots]
            if self.opts.chroots
            else self.conf["chroots"].keys()
        )
        for chroot in chroots:
            dirname = os.path.join(self.temp, chroot)
            if os.path.isdir(dirname):
                self.log.debug(f"cleaning up chroot: {chroot}")
                if not self.opts.preserve:
                    self.nuke_directory(dirname)

        if not self.opts.preserve:
            self.nuke_directory(self.temp)

    def exec_cmd(self, cmd: list) -> None:
        """Execute subprocess, always writing stdout+stderr to the log."""
        self.log.debug(shlex.join(cmd))

        log_it = self.log.info if self.opts.verbose else self.log.debug

        try:
            proc = subprocess.Popen(
                cmd,
                env=self.env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            for line in iter(proc.stdout.readline, ""):
                log_it(line.rstrip())
            proc.stdout.close()
            return_code = proc.wait()
            if return_code:
                raise subprocess.CalledProcessError(return_code, shlex.join(cmd))
        except KeyboardInterrupt:
            raise FllError
        except subprocess.CalledProcessError:
            self.log.exception(f"problem executing command: {shlex.join(cmd)}")
            raise FllError

    def chroot_exec(self, chroot: str, args: list) -> None:
        """Run command in a chroot via systemd-nspawn."""
        chroot_dir = os.path.join(self.temp, chroot)
        cmd = [
            "systemd-nspawn",
            "--quiet",
            f"--directory={chroot_dir}",
            "--as-pid2",
            "--resolv-conf=bind-host",
            "--timezone=off",
            "--restrict-address-families=AF_INET AF_INET6 AF_UNIX",
        ]
        for key, value in self.env.items():
            cmd.append(f"--setenv={key}={value}")
        cmd.append("--")
        cmd.extend(args)
        self.exec_cmd(cmd)

    def chroot_output(self, chroot: str, args: list) -> str:
        """Run command in a chroot and return captured stdout."""
        chroot_dir = os.path.join(self.temp, chroot)
        cmd = [
            "systemd-nspawn",
            "--quiet",
            f"--directory={chroot_dir}",
            "--as-pid2",
            "--resolv-conf=bind-host",
            "--timezone=off",
            "--restrict-address-families=AF_INET AF_INET6 AF_UNIX",
        ]
        for key, value in self.env.items():
            cmd.append(f"--setenv={key}={value}")
        cmd.append("--")
        cmd.extend(args)
        self.log.debug(shlex.join(cmd))
        result = subprocess.run(cmd, env=self.env, capture_output=True, text=True)
        if result.returncode != 0:
            self.log.critical(result.stderr.strip())
            raise FllError
        return result.stdout

    def apt_get(
        self, chroot: str, command: str, args: list = [], insecure: bool = False
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

    def chroot_bootstrap(self, chroot: str) -> None:
        """Bootstrap a distro root filesystem with cdebootstrap."""
        distro = self.conf["chroots"][chroot]["packages"]["distro"]
        codename = self.conf["chroots"][chroot]["packages"]["codename"]
        arch = self.conf["chroots"][chroot]["packages"]["arch"]

        dist_repo = self.conf["chroots"][chroot]["repos"][distro]
        if dist_repo.get("cached"):
            mirror = dist_repo["cached"]
        else:
            mirror = dist_repo["uri"]
            auto_apt_proxy = shutil.which("auto-apt-proxy")
            if auto_apt_proxy:
                apt_proxy = subprocess.run(
                    [auto_apt_proxy], stdout=subprocess.PIPE
                ).stdout.decode("utf-8")
                if apt_proxy:
                    mirror = apt_proxy.rstrip() + "/" + mirror.split("//")[1]

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
        auto_apt_proxy = shutil.which("auto-apt-proxy")
        apt_proxy = None
        if auto_apt_proxy:
            apt_proxy = subprocess.run(
                [auto_apt_proxy], stdout=subprocess.PIPE
            ).stdout.decode("utf-8")
        for dist_repo in self.conf["chroots"][chroot]["repos"].keys():
            repo = self.conf["chroots"][chroot]["repos"][dist_repo]
            repo_uri = repo.get("uri")
            cached_uri = repo.get("cached")
            if not cached_uri and apt_proxy and repo_uri:
                cached_uri = apt_proxy.rstrip() + "/" + repo_uri.split("//")[1]
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

            self.log.debug("creating %s" % sources_file)
            sources_file_fh = None
            try:
                sources_file_fh = open(sources_file, "w")
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
            except IOError:
                self.log.exception("failed to open %s" % sources_file)
                raise FllError
            finally:
                if sources_file_fh:
                    sources_file_fh.close()

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
            except IOError:
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
            cmd = "dpkg-divert --add --local --divert " + divert + ".REAL --rename "
            cmd += divert
            self.chroot_exec(chroot, shlex.split(cmd))

            if divert == "/usr/sbin/policy-rc.d":
                self.write_file(chroot_dir, divert)
                os.chmod(os.path.join(chroot_dir, divert.lstrip("/")), 0o755)
            else:
                os.symlink("/bin/true", os.path.join(chroot_dir, divert.lstrip("/")))

    def dpkg_undo_divert(self, chroot: str) -> None:
        """Undivert facilities diverted by self.dpkg_divert()."""
        chroot_dir = os.path.join(self.temp, chroot)
        for divert in self.diverts:
            self.log.debug(f"undoing diversion: {divert}")
            os.unlink(os.path.join(chroot_dir, divert.lstrip("/")))
            cmd = "dpkg-divert --remove --rename " + divert
            self.chroot_exec(chroot, shlex.split(cmd))

    def write_file(self, chroot: str, filename: str, mode: int = 0o644) -> None:
        """Write a file in a chroot. Templates defined below."""
        new_file = True
        chroot_dir = os.path.join(self.temp, chroot)
        chroot_filename = os.path.join(chroot_dir, filename.lstrip("/"))
        if os.path.isfile(chroot_filename):
            new_file = False
        if not os.path.exists(os.path.dirname(chroot_filename)):
            os.makedirs(os.path.dirname(chroot_filename), 0o755, exist_ok=True)
        with open(chroot_filename, "w") as filehandle:
            self.log.debug(f"writing file: {filename}")
            if filename == "/etc/default/distro":
                distro_defaults = self.conf["distro"].keys()
                distro_defaults.sort()
                for key in distro_defaults:
                    if key.startswith("FLL_DISTRO_CODENAME"):
                        continue
                    elif key == "FLL_IMAGE_FILE":
                        image_file = self.get_distro_imagefile(chroot)
                        filehandle.write('%s="%s"\n' % (key, image_file))
                        filehandle.write(
                            'FLL_IMAGE_LOCATION="$FLL_IMAGE_DIR/$FLL_IMAGE_FILE"\n'
                        )
                    elif key == "FLL_LIVE_USER_GROUPS":
                        groups = " ".join(sorted(self.profiles[chroot].groups))
                        filehandle.write('%s="%s"\n' % (key, groups))
                    else:
                        filehandle.write('%s="%s"\n' % (key, self.conf["distro"][key]))
            elif filename == "/etc/fstab":
                filehandle.write("# /etc/fstab: static file system information\n")
            elif filename == "/etc/hostname":
                hostname = self.conf["distro"]["FLL_DISTRO_NAME"]
                filehandle.write(hostname + "\n")
            elif filename == "/etc/hosts":
                hostname = self.conf["distro"]["FLL_DISTRO_NAME"]
                filehandle.write("127.0.0.1\tlocalhost\n")
                filehandle.write("127.0.0.1\t" + hostname + "\n\n")
                filehandle.write("# Below lines are for IPv6 capable hosts\n")
                filehandle.write("::1     ip6-localhost ip6-loopback\n")
                filehandle.write("fe00::0 ip6-localnet\n")
                filehandle.write("ff00::0 ip6-mcastprefix\n")
                filehandle.write("ff02::1 ip6-allnodes\n")
                filehandle.write("ff02::2 ip6-allrouters\n")
                filehandle.write("ff02::3 ip6-allhosts\n")
            elif filename == "/usr/sbin/policy-rc.d":
                filehandle.write("#!/bin/sh\n")
                filehandle.write('echo "$0 denied action: $1 $2" >&2\n')
                filehandle.write("exit 101\n")
            elif filename == "/etc/plymouth/plymouthd.conf":
                boot_theme = self.conf["options"].get("boot_theme", "bgrt")
                self.log.debug(f"{chroot} - setting {boot_theme} plymouth theme")
                filehandle.write("[Daemon]\n")
                filehandle.write(f"Theme={boot_theme}\n")

        if new_file:
            os.chmod(chroot_filename, mode)

    def write_default_conffiles(self, chroot: str) -> None:
        """Initial creation of conffiles required in chroot."""
        self.write_file(chroot, "/etc/fstab")
        self.write_file(chroot, "/etc/hostname")

    def write_distro_defaults(self, chroot: str) -> None:
        """Write the /etc/default/distro file."""
        self.write_file(chroot, "/etc/default/distro")

    def write_final_conffiles(self, chroot: str) -> None:
        """Final editing of conffiles in chroot."""
        chroot_dir = os.path.join(self.temp, chroot)

        distro_version = "%s-version" % self.conf["distro"]["FLL_DISTRO_NAME"].lower()
        distro_version_filename = os.path.join(chroot_dir, "etc", distro_version)

        self.log.debug(f"stamping distro version: {distro_version}")
        with open(distro_version_filename, "w") as distro_version_filehandle:
            distro_version_filehandle.write(self.get_distro_stamp(chroot))
        os.chmod(distro_version_filename, 0o444)

        self.write_file(chroot, "/etc/motd.tail")
        self.write_file(chroot, "/etc/plymouth/plymouthd.conf")

        self.log.debug("writing final apt sources.list(s)")
        self.write_apt_lists(chroot, cached=self.opts.apt_cache)

        if (
            os.path.isfile(os.path.join(chroot_dir, "etc/resolv.conf"))
            and not os.path.islink(os.path.join(chroot_dir, "etc/resolv.conf"))
            and os.path.isfile(os.path.join(chroot_dir, "etc/systemd/resolved.conf"))
        ):
            try:
                os.unlink(os.path.join(chroot_dir, "etc/resolv.conf"))
                os.symlink(
                    "../run/systemd/resolve/stub-resolv.conf",
                    os.path.join(chroot_dir, "etc/resolv.conf"),
                )
                with open(
                    os.path.join(chroot_dir, "etc/systemd/resolved.conf"), "a"
                ) as resolvedconf:
                    resolvedconf.write("DNS=\n")
            except IOError:
                self.log.exception("failed to setup resolv.conf and resolved.conf")
                raise FllError

        homed_privkey = self.conf["options"].get("homed_privkey")
        homed_pubkey = self.conf["options"].get("homed_pubkey")
        if homed_privkey and homed_pubkey:
            self.log.info(f"{chroot} - copying systemd-homed keys to chroot...")
            try:
                os.makedirs(os.path.join(chroot_dir, "var/lib/systemd/home/"))
                shutil.copy(
                    homed_privkey, os.path.join(chroot_dir, "var/lib/systemd/home/")
                )
                shutil.copy(
                    homed_pubkey, os.path.join(chroot_dir, "var/lib/systemd/home/")
                )
            except FileNotFoundError:
                self.log.exception("homed configuration failed")
                raise FllError

    def create_initramfs(self, chroot: str) -> None:
        """Create an initramfs"""
        initramfs_tool = self.conf["options"].get("initramfs_tool")
        kvers = self.detect_linux_version(chroot)
        for kernel in kvers:
            cmd = ""
            if initramfs_tool == "initramfs-tools":
                cmd = f"update-initramfs -c -k {kernel}"
                if self.opts.verbose or self.opts.debug:
                    cmd += " -v"
            elif initramfs_tool == "dracut":
                cmd = "dracut --no-hostonly --no-hostonly-i18n "
                cmd += "--no-hostonly-cmdline --no-hostonly-default-device "
                cmd += f"--force-add fll --kver {kernel}"
                if self.opts.verbose or self.opts.debug:
                    cmd += " --verbose"
                elif self.opts.quiet:
                    cmd += " --quiet"
            self.chroot_exec(chroot, shlex.split(cmd))

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

        cmd = "debconf-set-selections "
        if self.opts.verbose:
            cmd += "--verbose "
        cmd += "/fll/fll_debconf_selections"
        self.chroot_exec(chroot, shlex.split(cmd))

    def detect_linux_version(self, chroot: str) -> list:
        """Return version string of a singularly installed linux-image."""
        linux = self.conf["chroots"][chroot]["packages"]["linux"]
        linux_meta = f"linux-image-{linux}"
        linux_images = [
            f[len("linux-image-") :]
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
        self, wanted: dict, available: dict, installed: set
    ) -> list:
        """Provide automated detection for packages in recommends whitelist."""
        apt_recommends = self.conf["options"].get("apt_recommends")
        if apt_recommends == "yes":
            return []

        self.log.debug("detecting whitelisted recommended packages...")
        rec_module = ConfigObj(os.path.join(self.opts.share, "modules", "recommends"))
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
                    srcver = src[src.index("(") + 1 : src.index(")")]
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

    def write_manifest(self, chroot: str) -> None:
        """Collect package and source package URI information from each
        chroot."""
        image_dir = os.path.join(
            self.temp, "staging", self.conf["distro"]["FLL_IMAGE_DIR"]
        )
        self.log.info(f"{chroot} - writing package manifest...")

        status = self._read_dpkg_status(chroot)
        manifest = {
            name: data["version"]
            for name, data in status.items()
            if not name.startswith("cdebootstrap-helper")
        }
        self.profiles[chroot].manifest = manifest

        packages = list(manifest.keys())
        packages.sort(key=len)
        pkg_maxlen = len(packages[-1])
        packages.sort()

        manifest_name = self.get_distro_imagefile(chroot) + ".manifest"
        manifest_file = os.path.join(image_dir, manifest_name)

        try:
            with open(manifest_file, "w") as manifest_fh:
                manifest_fh.writelines(
                    [
                        f"{pkg.ljust(pkg_maxlen)} " + f"{manifest[pkg]}\n"
                        for pkg in packages
                    ]
                )
        except IOError:
            self.log.exception(f"failed to write file: {manifest_file}")
            raise FllError
        finally:
            os.chown(manifest_file, self.opts.uid, self.opts.gid)

        if self.opts.binary:
            return

        self.log.info(f"{chroot} - writing source package URIs...")
        srcpkg_seen = dict()
        srcpkg_specs = []
        for pkg in packages:
            if pkg.startswith("cdebootstrap-helper"):
                continue
            srcpkg = status[pkg]["source"]
            pkgver = status[pkg]["version"]
            if srcpkg not in srcpkg_seen:
                srcpkg_seen[srcpkg] = True
                srcpkg_specs.append(f"{pkg}={pkgver}")

        try:
            output = self.chroot_output(
                chroot, ["apt-get", "source", "--print-uris"] + srcpkg_specs
            )
        except FllError:
            self.log.critical("failed to retrieve source URIs")
            raise
        uris = [
            line.split("'")[1]
            for line in output.splitlines()
            if line.startswith("'")
        ]
        uris.sort()

        sources_list = deduplicate_list(uris)

        sources_name = self.get_distro_imagefile(chroot) + ".sources"
        sources_file = os.path.join(image_dir, sources_name)

        try:
            with open(sources_file, "w") as sources_fh:
                sources_fh.writelines([f"{s}\n" for s in sources_list])
        except IOError:
            self.log.exception(f"failed to write filename: {sources_file}")
            raise FllError
        finally:
            os.chown(sources_file, self.opts.uid, self.opts.gid)

    def install_packages(self, chroot: str) -> None:
        """Install packages."""
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
        flatpak_cmd = "flatpak"
        if self.opts.verbose:
            flatpak_cmd += " --verbose"
        elif self.opts.debug:
            flatpak_cmd += " -vv"
        flatpaks = self.profiles[chroot].flatpaks
        if "flatpak" in self.profiles[chroot].packages:
            flathub_remote = "flathub https://flathub.org/repo/flathub.flatpakrepo"
            self.chroot_exec(
                chroot,
                shlex.split(
                    f"{flatpak_cmd} remote-add --if-not-exists {flathub_remote}"
                ),
            )
            for flatpak in flatpaks:
                self.chroot_exec(
                    chroot,
                    shlex.split(
                        f"{flatpak_cmd} install --noninteractive --assumeyes flathub {flatpak}"
                    ),
                )

        flatpaks_beta = self.profiles[chroot].flatpaks_beta
        if len(flatpaks_beta) > 0:
            flathub_beta_remote = (
                "flathub-beta https://flathub.org/beta-repo/flathub-beta.flatpakrepo"
            )
            self.chroot_exec(
                chroot,
                shlex.split(
                    f"{flatpak_cmd} remote-add --if-not-exists {flathub_beta_remote}"
                ),
            )
            for flatpak in flatpaks_beta:
                self.chroot_exec(
                    chroot,
                    shlex.split(
                        f"{flatpak_cmd} install --noninteractive --assumeyes flathub-beta {flatpak}"
                    ),
                )

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

            cmd = f"/fll/{sname} postinst"
            self.chroot_exec(chroot, shlex.split(cmd))
            os.unlink(os.path.join(chroot_dir, "fll", sname))

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
        chroot_dir = os.path.join(self.temp, chroot)

        self.chroot_exec(chroot, shlex.split("dpkg --purge fll-live-initramfs"))
        self.chroot_exec(chroot, shlex.split("apt-get clean"))
        self.chroot_exec(chroot, shlex.split("dpkg --clear-avail"))

        for dirpath, dirnames, files in os.walk(os.path.join(chroot_dir, "var/log")):
            self.zero_logs(chroot, dirpath, files)

    def mkreadonlyfs_chroot(self, chroot: str) -> None:
        """Make readonly filesystem image of chroot."""
        chroot_dir = os.path.join(self.temp, chroot)
        cmd = list()
        exclude_file = os.path.join(self.opts.share, "data", "fll_rootfs_exclusions")
        image_file = self.get_distro_imagefile(chroot)
        if self.conf["options"]["readonly_filesystem"] == "squashfs":
            cmd = ["mksquashfs", ".", image_file, "-noappend"]

            shutil.copy(exclude_file, os.path.join(chroot_dir, "fll"))
            cmd.extend(["-wildcards", "-ef", "/fll/fll_rootfs_exclusions"])

            squashfs_comp = self.conf["options"].get("squashfs_comp")
            if squashfs_comp in ["gzip", "lz4", "lzo", "xz", "zstd"]:
                cmd.extend(["-comp", squashfs_comp])
                if squashfs_comp == "xz":
                    cmd.extend(["-Xbcj", "x86"])

            squashfs_processors = self.conf["options"].get("squashfs_processors")
            if squashfs_processors:
                cmd.extend(["-processors", f"{squashfs_processors}"])
            squashfs_throttle = self.conf["options"].get("squashfs_throttle")
            if squashfs_throttle:
                cmd.extend(["-throttle", f"{squashfs_throttle}"])

            cmd.append("-no-progress")
            cmd.extend(["-e", image_file])

            self.log.info(
                f"{chroot} - creating squashfs ({squashfs_comp}) filesystem..."
            )
            self.chroot_exec(chroot, cmd)
        elif self.conf["options"]["readonly_filesystem"] == "erofs":
            image_file = os.path.join(self.temp, image_file)
            erofs_compression = self.conf["options"].get("erofs_compression")
            erofs_comp_level = self.conf["options"].get("erofs_comp_level")
            erofs_uuid = self.conf["chroots"][chroot].get("uuid")
            cmd = ["mkfs.erofs", f"-U{erofs_uuid}", image_file, chroot_dir]
            if erofs_compression != "none":
                if erofs_comp_level:
                    erofs_compression += f",{erofs_comp_level}"
                cmd.insert(1, f"-z{erofs_compression}")
            erofs_options = self.conf["options"].get("erofs_options")
            if erofs_options:
                cmd.insert(1, f"{erofs_options}")
            with open(exclude_file) as ef:
                for exclude in ef.readlines():
                    exclude = exclude.rstrip()
                    if exclude.find("*") > 0:
                        excludes = glob.glob(os.path.join(chroot_dir, exclude))
                        for ex in excludes:
                            if os.path.exists(ex):
                                cmd.insert(
                                    1,
                                    f"--exclude-path={ex.replace(chroot_dir + '/', '')}",
                                )
                    else:
                        if os.path.exists(os.path.join(chroot_dir, exclude)):
                            cmd.insert(1, f"--exclude-path={exclude}")
            if self.opts.debug:
                cmd.insert(1, "-d9")
            else:
                cmd.insert(1, "-d0")
            self.log.info(
                f"{chroot} - creating erofs ({erofs_compression}) filesystem..."
            )
            self.exec_cmd(cmd)
            shutil.move(image_file, chroot_dir)

    def stage_chroot(self, chroot: str) -> None:
        """Stage files for an chroot for final genisofs."""
        self.log.info(f"{chroot} - staging live media for chroot...")
        chroot_dir = os.path.join(self.temp, chroot)
        image_file = os.path.join(chroot_dir, self.get_distro_imagefile(chroot))
        image_dir = os.path.join(
            self.temp, "staging", self.conf["distro"]["FLL_IMAGE_DIR"]
        )
        try:
            os.chmod(image_file, 0o644)
            shutil.move(image_file, image_dir)
        except IOError:
            self.log.exception("failed to move readonly rootfs image to staging dir")
            raise FllError

    def hashsum(self, filename: str) -> str:
        """Return SHA-256 hex digest of a file."""
        h = hashlib.sha256()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def sign_file(self, filename) -> None:
        """Sign a file with hashkey if available."""
        if self.opts.hashkey:
            self.log.info(f"signing file: {filename}")
            cmd = ["gpg", "-s", "--default-key"]
            cmd.append(self.opts.hashkey)
            cmd.append(filename)
            self.exec_cmd(cmd)
        else:
            self.log.info(f"not signing file (no key given): {filename}")

    def gen_live_media(self) -> None:
        """Generate live media iso image."""
        stage = os.path.join(self.temp, "staging")

        distro_name = self.conf["distro"]["FLL_DISTRO_NAME"]
        image_dir = self.conf["distro"]["FLL_IMAGE_DIR"]

        iso_name = f"{distro_name}-{self.timestamp}.{self.run_id}.{self.chroots[0]}"
        for index, chroot in enumerate(self.chroots[1:]):
            common_prefix = os.path.commonprefix([self.chroots[index], chroot])
            iso_name += f"+{chroot.replace(common_prefix, '')}"
        iso_name += ".iso"
        iso_file = os.path.join(self.opts.output_dir, iso_name)

        sha256_file = iso_file + ".sha256"

        bootloader = self.conf["options"]["bootloader"]
        if bootloader == "grub":
            if not os.path.isfile(
                os.path.join(stage, "boot/grub/i386-pc/grub_eltorito")
            ):
                self.log.critical("grub El Torito image not found in staging")
                raise FllError
            grub_mbr_img = os.path.join(stage, "boot/grub/i386-pc/boot_hybrid.img")
        else:
            if not os.path.isfile(os.path.join(stage, "efi.img")):
                self.log.critical(f"EFI image not found in staging for {bootloader}")
                raise FllError

        gpt_filesystems = []
        for chroot in self.chroots:
            image_file = self.get_distro_imagefile(chroot)
            image_path = os.path.join(image_dir, image_file)
            if os.path.isfile(os.path.join(stage, image_path)):
                gpt_filesystems.append(image_path)

        xorriso_cmd = [
            "xorriso",
            "-report_about", "HINT",
            "-as", "mkisofs",
            "-graft-points",
            "-pad", "-l", "-iso-level", "3", "-v",
        ]
        if bootloader == "grub":
            xorriso_cmd += [
                "-no-emul-boot",
                "-boot-load-size", "4",
                "-boot-info-table",
                "-b", "boot/grub/i386-pc/grub_eltorito",
                "--grub2-boot-info",
                "--grub2-mbr", grub_mbr_img,
            ]
        xorriso_cmd += [f"--modification-date={self.xorriso_uuid.replace('-', '')}"]
        if os.path.isfile(os.path.join(stage, "efi.img")):
            xorriso_cmd += [
                "--efi-boot", "efi.img",
                "-efi-boot-part",
                "--efi-boot-image",
            ]
            gpt_filesystems.append("efi.img")
        xorriso_cmd += ["--protective-msdos-label", "-V", distro_name[:32]]
        if os.path.isdir(os.path.join(stage, "boot")):
            xorriso_cmd += ["--sort-weight", "0", "/", "--sort-weight", "1", "/boot"]
            if bootloader == "grub" and os.path.isdir(
                os.path.join(stage, "boot/grub")
            ):
                xorriso_cmd += ["--sort-weight", "2", "/boot/grub"]
            elif bootloader == "systemd-boot" and os.path.isdir(
                os.path.join(stage, "loader")
            ):
                xorriso_cmd += ["--sort-weight", "2", "/loader"]
        xorriso_cmd += ["-x", "efi", "-x", "genisoimage.sort", "-o", iso_file, stage]

        self.log.info("generating iso image of live media...")
        self.exec_cmd(xorriso_cmd)

        self.log.info("converting to hybrid iso...")
        try:
            run_gpthybrid(
                iso_file,
                gpt_filesystems,
                verbose=self.opts.verbose,
                log_fn=self.log.info,
            )
        except subprocess.CalledProcessError:
            self.log.exception("gpthybrid failed")
            raise FllError

        os.chown(iso_file, self.opts.uid, self.opts.gid)
        self.live_media = iso_file

        self.log.info("calculating hashsum of live media iso image...")
        try:
            sha256sum = self.hashsum(iso_file)
            with open(sha256_file, "w") as f:
                f.write("%s *%s\n" % (sha256sum, os.path.basename(iso_file)))
        except IOError:
            self.log.exception("failed to write hashsum file")
            raise FllError
        finally:
            os.chown(sha256_file, self.opts.uid, self.opts.gid)
            if self.opts.hashkey:
                self.log.info(f"signing {sha256_file}...")
                self.sign_file(sha256_file)
                os.chown(sha256_file + ".gpg", self.opts.uid, self.opts.gid)

        for f in glob.glob("%s*" % os.path.splitext(iso_file)[0]):
            self.log.info(f)

        if self.opts.update_grub:
            self.log.info("updating grub2-fll-fromiso entries...")
            self.exec_cmd(["update-grub"])

        if self.opts.write_iso:
            grub_uuid = (
                self.persist_uuid
                if self.opts.persist
                and self.conf["options"]["bootloader"] == "grub"
                else None
            )
            try:
                write_iso(
                    iso_file,
                    self.opts.write_iso,
                    persist=self.opts.persist,
                    persist_uuid=grub_uuid,
                    verbose=self.opts.verbose,
                    log_fn=self.log.info,
                )
            except subprocess.CalledProcessError:
                self.log.exception("fllisodd failed")
                raise FllError

    def log_build_stats(self) -> None:
        duration = int(time.perf_counter() - self.time)
        m, s = divmod(duration, 60)
        self.log.info(f"build duration was {m:d} minutes and {s:02d} seconds")

    def init_chroots(self) -> None:
        """Initialise and check global defaults for all chroots."""
        self.chroots = (
            [chroot for chroot in self.opts.chroots]
            if self.opts.chroots
            else self.conf["chroots"].keys()
        )
        self.chroots = list(dict.fromkeys(self.chroots))
        for chroot in self.chroots:
            if not self.conf["chroots"].get(chroot):
                self.log.error(f"chroot '{chroot}' not defined in {self.opts.config}")
                raise FllError()
            self.conf["chroots"][chroot]["uuid"] = uuidgen()
            self.log.debug(f"uuid for {chroot}: {self.conf['chroots'][chroot]['uuid']}")

        if self.opts.persist:
            self.log.debug("forcing readonly_filesystem=erofs for rootfs")
            self.conf["options"]["readonly_filesystem"] = "erofs"

    def write_quickemu_conf(self) -> None:
        if not self.opts.quickemu:
            return
        quickemu_conf = f"{self.live_media}.quickemu.conf"
        quickemu_disk = f"{self.live_media}.disk.qcow2"
        with open(quickemu_conf, "w") as quickemu_conf_fh:
            quickemu_conf_fh.write(f'disk_img="{os.path.basename(quickemu_disk)}"\n')
            quickemu_conf_fh.write(f'iso="{os.path.basename(self.live_media)}"\n')
        os.chown(quickemu_conf, self.opts.uid, self.opts.gid)
        self.log.info(f"quickemu --vm {quickemu_conf}")

    def init_chroot(self, chroot: str) -> None:
        """Initialise variables for chroot."""
        self.profiles[chroot] = copy.deepcopy(self.parse_package_profile(chroot))

    def _build_chroot(self, chroot: str) -> None:
        """Run the full build pipeline for a single chroot."""
        threading.current_thread().name = chroot

        distro_name = self.conf["distro"]["FLL_DISTRO_NAME"]
        log_filename = os.path.join(
            self.opts.output_dir,
            f"{distro_name}-{self.timestamp}.{self.run_id}.log.{chroot}",
        )
        fmt = logging.Formatter("%(asctime)s %(levelname)-5s %(message)s")
        handler = logging.FileHandler(filename=log_filename, mode="w")
        handler.setFormatter(fmt)
        handler.setLevel(logging.DEBUG)
        thread_id = threading.current_thread().ident
        handler.addFilter(lambda r: r.thread == thread_id)
        self.log.addHandler(handler)
        self.log.info(f"{chroot} - logging to {log_filename}")

        try:
            self.init_chroot(chroot)
            with self._bootstrap_sem:
                self.chroot_bootstrap(chroot)
            self.dpkg_divert(chroot)
            self.write_default_conffiles(chroot)
            self.write_distro_defaults(chroot)
            self.preseed_debconf(chroot)
            self.prime_apt(chroot)
            self.install_packages(chroot)
            self.install_flatpaks(chroot)
            self.configure_locales(chroot)
            self.post_installation(chroot)
            self.write_manifest(chroot)
            self.write_final_conffiles(chroot)
            self.dpkg_undo_divert(chroot)
            self.create_initramfs(chroot)
            with self._staging_lock:
                self.stage_bootloader(chroot)
            self.clean_chroot(chroot)
            self.mkreadonlyfs_chroot(chroot)
            self.stage_chroot(chroot)
            self.nuke_chroot(chroot)
        finally:
            self.log.removeHandler(handler)
            handler.close()
            os.chown(log_filename, self.opts.uid, self.opts.gid)

    def main(self) -> None:
        """Main loop."""
        self.init_cli_options()
        self.init_configuration()
        self.init_logfile()
        self.init_build_directory()
        self.init_chroots()
        main_thread_id = threading.current_thread().ident

        def logfile_filter(r):
            return r.thread == main_thread_id

        self._logfile_handler.addFilter(logfile_filter)
        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.opts.jobs
            ) as pool:
                futures = {pool.submit(self._build_chroot, c): c for c in self.chroots}
                for fut in concurrent.futures.as_completed(futures):
                    fut.result()
        finally:
            self._logfile_handler.removeFilter(logfile_filter)
        self.write_bootloader_config()
        self.gen_live_media()
        self.log_build_stats()
        self.write_configuration()
        self.write_quickemu_conf()


def main() -> None:
    import sysconfig

    # Source-tree: share/ is one level above bin/.
    # Installed: data_files land in {prefix}/share/pyfll/; sysconfig gives us
    # the right prefix regardless of whether it is /usr, ~/.local, or a venv.
    # The caller can always override with --share.
    _bin_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    _src_share = os.path.normpath(os.path.join(_bin_dir, "../share"))
    if os.path.isdir(_src_share):
        share_path = _src_share
    else:
        share_path = os.path.join(sysconfig.get_path("data"), "share", "pyfll")
    cli = argparse.ArgumentParser(description="F*** Live Linux builder.", prog="fll")
    cli.add_argument(
        "-A",
        "--apt-cache",
        action="store_true",
        default=False,
        help="Keep cached apt URIs. Must be defined in config "
        + "file. Default: %(default)s",
    )
    cli.add_argument(
        "-b",
        "--build",
        action="store",
        type=str,
        metavar="<directory>",
        required=True,
        help="Build directory. A large amount of free space " + "is required.",
    )
    cli.add_argument(
        "-B",
        "--binary",
        action="store_true",
        default=False,
        help="Do binary build only. Disable generation of "
        + "URI lists. Default: %(default)s",
    )
    cli.add_argument(
        "-c",
        "--config",
        action="store",
        type=str,
        metavar="<config file>",
        required=True,
        help="Configuration file. This option may be used "
        + "more than once to process multiple configurations. "
        + "A configuration file must be specified.",
    )
    cli.add_argument(
        "-C",
        "--chroots",
        nargs="+",
        metavar="<chroot>",
        help="Name of chroot(s) to build. Default: all",
    )
    cli.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug mode. Extra output will be "
        + "to assist in development. Default: %(default)s",
    )
    cli.add_argument(
        "-j",
        "--jobs",
        action="store",
        type=int,
        default=None,
        metavar="<N>",
        help="Number of chroots to build in parallel. "
        + "Default: all chroots concurrently. Use 1 for serial output.",
    )
    cli.add_argument(
        "-k",
        "--hashkey",
        action="store",
        default=None,
        type=str,
        metavar="<key id>",
        help="Set key " + "to sign MD5 and SHA256 hashes of the live media.",
    )
    cli.add_argument(
        "-L",
        "--locales",
        nargs="+",
        metavar="<locale>",
        default=[os.environ.get("LANG", "en_US").split(".")[0]],
        help="Fallback locales to use in all chroots. "
        + "Vaules in config file override. Default: %(default)s",
    )
    cli.add_argument(
        "-o",
        "--output-dir",
        action="store",
        default=None,
        type=str,
        metavar="<directory>",
        help="Output directory, where the product of this "
        + "program will be generated.",
    )
    cli.add_argument(
        "-p",
        "--persist",
        action="store_true",
        default=False,
        help="Create persist partition for use by overlayfs as "
        + "upper storage backing. Default: %(default)s",
    )
    cli.add_argument(
        "-P",
        "--preserve",
        action="store_true",
        default=False,
        help="Preserve build directory. Disable automatic "
        + "cleanup of the build area at exit.",
    )
    cli.add_argument(
        "-Q",
        "--quickemu",
        action="store_true",
        default=False,
        help="Write a configuration file for quickemu.",
    )
    cli.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="Enable quiet mode. Only high priority messages " + "will be generated.",
    )
    cli.add_argument(
        "-T",
        "--timezone",
        action="store_true",
        default=False,
        help="Add host timezone to boot cmdline of live media. "
        + "Default: %(default)s",
    )
    cli.add_argument(
        "-U",
        "--update-grub",
        action="store_true",
        default=False,
        help="Execute update-grub after generating live media.",
    )
    cli.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose mode. All messages will be "
        + "generated, such as announcing current operation.",
    )
    cli.add_argument(
        "-w",
        "--write-iso",
        action="store",
        default=None,
        type=str,
        metavar="<device>",
        help="Write final live media to device with dd via fllisodd. "
        + "WARNING: destroys all existing data on target device!!!",
    )

    # These options are managed by the fll shell snippet non-interactively
    cli.add_argument(
        "--share", action="store", type=str, help=argparse.SUPPRESS, default=share_path
    )
    cli.add_argument(
        "--gid", action="store", type=int, help=argparse.SUPPRESS, default=os.getgid()
    )
    cli.add_argument(
        "--uid", action="store", type=int, help=argparse.SUPPRESS, default=os.getuid()
    )
    cli.add_argument(
        "--non-root", action="store_true", help=argparse.SUPPRESS, default=False
    )
    arguments = cli.parse_args()

    try:
        fll = FLLBuilder(arguments)
        fll.main()
    except KeyboardInterrupt:
        pass
    except FllError:
        sys.exit(1)
