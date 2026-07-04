# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import argparse
import atexit
import concurrent.futures
import datetime
import glob
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from configobj import ConfigObj, flatten_errors
from validate import Validator

from pyfll.apt import AptMixin
from pyfll.bootloader import BootloaderMixin
from pyfll.chroot import ChrootExecMixin
from pyfll.exceptions import FllError
from pyfll.gpt import run_gpthybrid
from pyfll.isodd import write_iso
from pyfll.profile import PackageProfileMixin
from pyfll.util import uuidgen


class FLLBuilder(BootloaderMixin, AptMixin, PackageProfileMixin, ChrootExecMixin):
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
        self.persist_luks_uuid = uuidgen()
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
        elif self.opts.quiet:
            self.init_logger("WARNING")
        else:
            self.init_logger("INFO")

    def get_distro_imagefile(self, chroot: str) -> str:
        """Return image file that compressed chroot will be archived to."""
        image_file = self.conf["distro"]["FLL_IMAGE_FILE"]
        return f"{image_file}.{chroot}"

    def get_distro_stamp(self, chroot: str) -> str:
        """Return a string suitable for the distro stamp file."""
        profiles = " ".join(self.conf["chroots"][chroot]["packages"]["profile"])
        stamp = self.conf["distro"]["FLL_DISTRO_NAME"]
        if self.conf["distro"].get("FLL_DISTRO_CODENAME"):
            stamp += f" {self.conf["distro"]['FLL_DISTRO_CODENAME']}"
        if self.conf["distro"].get("FLL_DISTRO_CODENAME_REV"):
            stamp += f" {self.conf["distro"]['FLL_DISTRO_CODENAME_REV']}"
        stamp += f" - {profiles} - {self.timestamp}"

        self.log.debug(f"stamp: {stamp}")
        return stamp

    def init_configuration(self) -> None:
        """Parse build configuration file and return it in a dict."""
        self.log.info(f"reading configuration file: {self.opts.config}")
        fll_config_spec = os.path.join(self.opts.share, "fll.conf.spec")
        self.conf = ConfigObj(self.opts.config, configspec=fll_config_spec)
        self.validate_configobj(self.conf)

    def validate_configobj(self, obj: ConfigObj) -> None:
        self.log.debug(f"validating {obj.filename}")
        validator = Validator()
        result = obj.validate(validator, preserve_errors=True)
        fatal_error = False
        for entry in flatten_errors(obj, result):
            section_list, key, error = entry
            if key is not None:
                section_list.append(key)
            else:
                section_list.append("[missing section]")
            section_string = " => ".join(section_list)
            if not error:
                error = "missing value or section"
            self.log.critical(f"{obj.filename}: {error}: {section_string}")
            fatal_error = True
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
            except OSError:
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
            except OSError:
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
            except OSError:
                self.log.exception("failed to setup resolv.conf and resolved.conf")
                raise FllError

    def hashsum(self, filename: str) -> str:
        """Return SHA-256 hex digest of a file."""
        h = hashlib.sha256()
        with open(filename, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def sign_file(self, filename: str) -> None:
        """Sign a file with hashkey if available."""
        if self.opts.hashkey:
            self.log.info(f"signing file: {filename}")
            cmd = ["gpg", "-s", "--default-key"]
            cmd.append(self.opts.hashkey)
            cmd.append(filename)
            self.exec_cmd(cmd)
        else:
            self.log.info(f"not signing file (no key given): {filename}")

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
        except OSError:
            self.log.exception("failed to move readonly rootfs image to staging dir")
            raise FllError

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
        except OSError:
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
            try:
                write_iso(
                    iso_file,
                    self.opts.write_iso,
                    persist=self.opts.persist,
                    persist_uuid=self.persist_uuid if self.opts.persist else None,
                    persist_luks_uuid=self.persist_luks_uuid if self.opts.encrypt else None,
                    encrypt=self.opts.encrypt,
                    verbose=self.opts.verbose,
                    log_fn=self.log.info,
                )
            except subprocess.CalledProcessError:
                self.log.exception("isodd failed")
                raise FllError

        if self.opts.upgrade:
            from pyfll.isodd import upgrade_iso
            try:
                upgrade_iso(
                    iso_file,
                    self.opts.upgrade,
                    encrypt=self.opts.encrypt,
                    verbose=self.opts.verbose,
                    log_fn=self.log.info,
                )
            except subprocess.CalledProcessError:
                self.log.exception("upgrade_iso failed")
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
                raise FllError
            self.conf["chroots"][chroot]["uuid"] = uuidgen()
            self.log.debug(f"uuid for {chroot}: {self.conf['chroots'][chroot]['uuid']}")
            # Resolve the merged profile now (config + profile + modules) so a
            # bad desktop= default fails fast here, before any chroot assembly.
            self.profiles[chroot] = self.parse_package_profile(chroot)
            self.validate_desktop(chroot)

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

    def validate_desktop(self, chroot: str) -> None:
        """Fail the build early if a chroot's `desktop` default is not among the
        sessions provided by its profile(s). Called from init_chroots(), before
        any chroot assembly, so a typo aborts cheaply rather than after a full
        bootstrap. An empty `desktop` (the spec default) means 'let the
        bootloader pick alphabetically', which is always valid."""
        default = self.conf["chroots"][chroot]["packages"].get("desktop")
        if not default:
            return
        desktops = self.profiles[chroot].desktops
        if default not in desktops:
            self.log.critical(
                f"{chroot}: desktop={default!r} is not among the sessions "
                f"provided by its profile(s): {sorted(desktops)}"
            )
            raise FllError

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
            with self._bootstrap_sem:
                self.chroot_bootstrap(chroot)
            self.dpkg_divert(chroot)
            self.write_default_conffiles(chroot)
            self.write_distro_defaults(chroot)
            self.preseed_debconf(chroot)
            self.prime_apt(chroot)
            self.pre_installation(chroot)
            self.install_packages(chroot)
            self.install_flatpaks(chroot)
            self.configure_locales(chroot)
            self.post_installation(chroot)
            self.write_manifest(chroot)
            self.hold_kernel_packages(chroot)
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
        help="Configuration file. A configuration file must be specified.",
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
        help="Write final live media to device with dd via isodd. "
        + "WARNING: destroys all existing data on target device!!!",
    )
    cli.add_argument(
        "-u",
        "--upgrade",
        action="store",
        default=None,
        type=str,
        metavar="<device>",
        help=(
            "After building the ISO, upgrade it onto <device> in-place using "
            "dd conv=notrunc. The btrfs persist partition is preserved; "
            "@root is reset, @home is untouched. Supply --encrypt if the "
            "persist partition is encrypted."
        ),
    )
    cli.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        default=False,
        help=(
            "Encrypt the persist partition with LUKS2 using an interactive "
            "passphrase. Requires --persist. Also signals --upgrade that the "
            "persist partition is encrypted and requires unlocking."
        ),
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
