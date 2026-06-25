# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import glob
import os
import shutil
import tarfile
import tempfile

from pyfll.exceptions import FllError
from pyfll.util import host_timezone


class BootloaderMixin:
    """Mixin providing bootloader staging and configuration methods for FLLBuilder."""

    BOOTLOADER_REGISTRY = {
        "grub":         ("stage_grub",         "write_grub_cfg"),
        "grub-efi":     ("stage_grub_efi",     "write_grub_efi_cfg"),
        "systemd-boot": ("stage_systemd_boot", "write_systemd_loader_conf"),
        "refind":       ("stage_refind",       "write_refind_conf"),
    }

    def _build_efi_fat_img(self, stage_dir: str) -> None:
        """Build a dynamically-sized FAT EFI system partition image from staging/efi/."""
        efi_img = os.path.join(stage_dir, "efi.img")
        efi_dir = os.path.join(stage_dir, "efi")

        # Walk the staging tree once, collecting both total file size and
        # file count.  FAT allocates in whole clusters, so every file wastes
        # up to one cluster regardless of its actual size.  With hundreds of
        # small grub .mod/.lst/locale files the cluster waste dominates.
        # Overhead budget:
        #   file_count * cluster_size  — worst-case cluster alignment waste
        #   2% of total_bytes          — FAT tables + reserved sectors,
        #                                scaled to content so a tiny grub
        #                                hybrid ESP (2-3 EFI files, <5 MiB)
        #                                does not balloon to 4+ MiB of waste
        #   512 KiB minimum            — floor for very small images
        total_bytes = 0
        file_count = 0
        for dirpath, dirnames, filenames in os.walk(efi_dir):
            for fname in filenames:
                total_bytes += os.path.getsize(os.path.join(dirpath, fname))
                file_count += 1
        fat_cluster_size = 4096  # bytes, standard FAT32 default
        fat_metadata = max(512 * 1024, int(total_bytes * 0.02))
        img_size = total_bytes + file_count * fat_cluster_size + fat_metadata
        # Round up to a 2048-byte (4-sector) boundary, consistent with
        # gpthybrid's sgdisk_align=4 and ISO9660 logical block size
        img_size = ((img_size + 2047) // 2048) * 2048
        self.log.info(f"creating EFI FAT image ({img_size // 1024 // 1024} MiB)...")

        # Pre-allocate image file and format as FAT
        with open(efi_img, "wb") as f:
            f.truncate(img_size)
        self.exec_cmd(["mformat", "-i", efi_img, "::"])

        # Copy each top-level item from staging/efi/ into the FAT root so that
        # EFI/BOOT/, EFI/Linux/, loader/ etc. land at the correct depth
        for item in sorted(os.listdir(efi_dir)):
            self.exec_cmd(
                ["mcopy", "-s", "-i", efi_img, os.path.join(efi_dir, item), "::/"]
            )

    def stage_grub(self, chroot: str) -> None:
        """Create grub2 BIOS El Torito and EFI boot images."""
        chroot_dir = os.path.join(self.temp, chroot)
        stage_dir = os.path.join(self.temp, "staging")

        boot_dir = os.path.join(self.temp, "staging", "boot")
        os.makedirs(boot_dir, 0o755, exist_ok=True)
        # for grub, stage the initramfs and kernel images on the iso
        initrds = glob.glob(os.path.join(chroot_dir, "boot", "initrd.img-*"))
        if len(initrds) == 1:
            self.log.debug(f"copying {initrds[0]} to staging dir")
            shutil.copy(initrds[0], os.path.join(boot_dir, f"initrd.img-{chroot}"))
        else:
            self.log.critical(
                "could not find initramfs image to " + "copy to staging dir."
            )
            raise FllError

        images = glob.glob(os.path.join(chroot_dir, "boot", "vmlinuz-*"))
        if len(images) == 1:
            self.log.debug(f"copying {images[0]} to staging dir")
            shutil.copy(images[0], os.path.join(boot_dir, f"vmlinuz-{chroot}"))
        else:
            self.log.critical(
                "could not find linux kernel image to " + "copy to staging dir."
            )
            raise FllError

        grub_dir = os.path.join(boot_dir, "grub")
        os.makedirs(grub_dir, 0o755, exist_ok=True)
        if not os.path.isfile(os.path.join(grub_dir, "grub.cfg")):
            shutil.copy(os.path.join(self.opts.share, "data/grub.cfg"), grub_dir)
            shutil.copy(
                os.path.join(chroot_dir, "usr/share/grub/unicode.pf2"), grub_dir
            )
            shutil.copytree(
                os.path.join(self.opts.share, "data/locales"),
                os.path.join(grub_dir, "locales"),
            )
            shutil.copytree(
                os.path.join(self.opts.share, "data/tz"),
                os.path.join(grub_dir, "tz"),
            )
            theme_dir = f"themes/{self.conf['distro']['FLL_GFXBOOT_THEME']}"
            if os.path.isfile(
                os.path.join(chroot_dir, f"usr/share/grub/{theme_dir}/theme.txt")
            ):
                shutil.copytree(
                    os.path.join(chroot_dir, f"usr/share/grub/{theme_dir}"),
                    os.path.join(grub_dir, theme_dir),
                )

        grub_pc_dir_src = os.path.join(chroot_dir, "usr/lib/grub/i386-pc")
        if os.path.isdir(grub_pc_dir_src):
            grub2_modules = glob.glob(os.path.join(grub_pc_dir_src, "*.mod"))
            if grub2_modules:
                gfiles = [
                    os.path.join(grub_pc_dir_src, f)
                    for f in os.listdir(grub_pc_dir_src)
                    if f.endswith(".mod") or f.endswith(".img") or f.endswith(".lst")
                ]
            else:
                gfiles = [
                    os.path.join(grub_pc_dir_src, f)
                    for f in os.listdir(grub_pc_dir_src)
                    if f.startswith("stage2") or f.startswith("iso9660")
                ]

            if not gfiles:
                self.log.exception("grub stage files not found")
                raise FllError

            grub_pc_dir = os.path.join(boot_dir, "grub", "i386-pc")
            if not os.path.isdir(grub_pc_dir):
                self.log.debug("copying grub stage files to boot dir")
                os.makedirs(grub_pc_dir, 0o755)
                for file in gfiles:
                    try:
                        shutil.copy(file, grub_pc_dir)
                    except OSError:
                        self.log.exception("failed to copy grub file to staging dir")
                        raise FllError

        eltorito_dst = os.path.join(boot_dir, "grub/i386-pc/grub_eltorito")
        if os.path.isdir(grub_pc_dir_src) and not os.path.exists(eltorito_dst):
            self.log.info(f"{chroot} - creating grub2 El Torito image...")
            cmd = [
                "grub-mkimage",
                "-d",
                "/usr/lib/grub/i386-pc/",
                "--prefix=/boot/grub",
                "--format=i386-pc-eltorito",
                "-o",
                "/fll/grub_eltorito",
                "biosdisk",
                "iso9660",
            ]
            self.chroot_exec(chroot, cmd)
            shutil.move(
                os.path.join(chroot_dir, "fll/grub_eltorito"),
                eltorito_dst,
            )

        efitypes = {"x86_64-efi": "bootx64", "i386-efi": "bootia32"}

        have_efi = any(
            os.path.isdir(os.path.join(chroot_dir, f"usr/lib/grub/{efitype}"))
            for efitype in efitypes
        )
        if not have_efi:
            return

        efi_boot_dir = os.path.join(stage_dir, "efi/EFI/BOOT")
        os.makedirs(efi_boot_dir, exist_ok=True)

        for efitype, efitarget in efitypes.items():
            if not os.path.isdir(os.path.join(chroot_dir, f"usr/lib/grub/{efitype}")):
                continue

            efi_dst = os.path.join(efi_boot_dir, f"{efitarget}.efi")
            if not os.path.isfile(efi_dst):
                self.log.info(f"{chroot} - creating grub2 EFI boot images...")
                memdisk_img = os.path.join(chroot_dir, "fll/grub_efi_memdisk.img")
                with tempfile.TemporaryDirectory() as memdisk_src:
                    grub_cfg_dir = os.path.join(memdisk_src, "boot/grub")
                    os.makedirs(grub_cfg_dir)
                    with open(os.path.join(grub_cfg_dir, "grub.cfg"), "w") as cfg:
                        cfg.write(f"search --fs-uuid --set=root {self.xorriso_uuid}\n")
                        cfg.write("set prefix=(${root})/boot/grub\n")
                        cfg.write("source $prefix/grub.cfg\n")
                    with tarfile.open(memdisk_img, "w") as tar:
                        tar.add(os.path.join(memdisk_src, "boot"), arcname="boot")

                self.log.info(
                    f"{chroot} - creating grub2 {efitype} EFI image ({efitarget}.efi)..."
                )
                efi_out_host = os.path.join(chroot_dir, f"fll/{efitarget}.efi")
                cmd = [
                    "grub-mkimage",
                    "-O",
                    efitype,
                    "-m",
                    "/fll/grub_efi_memdisk.img",
                    "--prefix=(memdisk)/boot/grub",
                    "-o",
                    f"/fll/{efitarget}.efi",
                    "search",
                    "iso9660",
                    "configfile",
                    "normal",
                    "memdisk",
                    "tar",
                    "part_msdos",
                    "part_gpt",
                    "lvm",
                    "fat",
                    "ext2",
                ]
                self.chroot_exec(chroot, cmd)
                shutil.move(efi_out_host, efi_dst)
                os.unlink(memdisk_img)

            gfile_dir = os.path.join(chroot_dir, f"usr/lib/grub/{efitype}")
            grub_efi_dir = os.path.join(boot_dir, "grub", efitype)
            if not os.path.isdir(grub_efi_dir):
                gfiles = [
                    os.path.join(gfile_dir, f)
                    for f in os.listdir(gfile_dir)
                    if f.endswith(".mod") or f.endswith(".lst")
                ]
                gfiles.append(os.path.join(chroot_dir, "usr/share/grub/unicode.pf2"))
                if gfiles:
                    self.log.debug(f"copying grub {efitype} stage files to boot dir")
                    os.makedirs(grub_efi_dir, 0o755)
                    for file in gfiles:
                        try:
                            shutil.copy(file, grub_efi_dir)
                        except OSError:
                            self.log.exception(
                                "failed to copy grub efi file to staging dir"
                            )
                            raise FllError

        memtest_arch_map = {
            "x86_64-efi": "mt86+x64",
            "i386-efi": "mt86+ia32",
        }
        for efitype, mt in memtest_arch_map.items():
            if not os.path.isdir(os.path.join(chroot_dir, f"usr/lib/grub/{efitype}")):
                continue
            memtest = os.path.join(chroot_dir, "boot", mt)
            memtest_out = os.path.join(boot_dir, mt)
            if os.path.isfile(memtest) and not os.path.isfile(memtest_out):
                self.log.debug(f"copying {mt} to boot dir")
                try:
                    shutil.copy(memtest, memtest_out)
                except OSError:
                    self.log.exception(f"failed to copy {mt} to staging dir")
                    raise FllError

    def stage_grub_efi(self, chroot: str) -> None:
        """Stage grub EFI binaries, kernel, initramfs, and grub config entirely
        within the ESP FAT tree. Nothing grub-related is written to the
        ISO9660 layer for this bootloader."""
        chroot_dir = os.path.join(self.temp, chroot)
        stage_dir = os.path.join(self.temp, "staging")

        efitypes = {"x86_64-efi": "bootx64", "i386-efi": "bootia32"}
        have_efi = any(
            os.path.isdir(os.path.join(chroot_dir, f"usr/lib/grub/{efitype}"))
            for efitype in efitypes
        )
        if not have_efi:
            self.log.critical(f"{chroot} - grub EFI directories not found")
            raise FllError

        efi_boot_dir = os.path.join(stage_dir, "efi/EFI/BOOT")
        os.makedirs(efi_boot_dir, exist_ok=True)

        # Per-efitype: build the EFI binary and stage module files if this
        # chroot provides that arch's grub files and the binary is not yet
        # staged. Each chroot only carries grub files for its own arch, so
        # each binary is created exactly once by whichever chroot runs first.
        # Memdisk stub grub.cfg: locate the FAT volume by searching for
        # kernels.cfg, which is unique to our build and written only to
        # the FAT by write_grub_efi_cfg().  search_fs_file must be baked
        # into the binary (see grub-mkimage modules below) for --file to
        # work; the generic search module alone does not provide it.
        for efitype, efitarget in efitypes.items():
            if not os.path.isdir(os.path.join(chroot_dir, f"usr/lib/grub/{efitype}")):
                continue

            efi_dst = os.path.join(efi_boot_dir, f"{efitarget}.efi")
            if not os.path.isfile(efi_dst):
                self.log.info(
                    f"{chroot} - creating grub2 {efitype} EFI image ({efitarget}.efi)..."
                )
                memdisk_img = os.path.join(chroot_dir, "fll/grub_efi_memdisk.img")
                with tempfile.TemporaryDirectory() as memdisk_src:
                    grub_cfg_dir = os.path.join(memdisk_src, "boot/grub")
                    os.makedirs(grub_cfg_dir)
                    with open(os.path.join(grub_cfg_dir, "grub.cfg"), "w") as cfg:
                        cfg.write(
                            "search --no-floppy --file --set=root /boot/grub/kernels.cfg\n"
                        )
                        cfg.write("set prefix=($root)/boot/grub\n")
                        cfg.write("source $prefix/grub.cfg\n")
                    with tarfile.open(memdisk_img, "w") as tar:
                        tar.add(os.path.join(memdisk_src, "boot"), arcname="boot")
                cmd = [
                    "grub-mkimage",
                    "-O",
                    efitype,
                    "-m",
                    "/fll/grub_efi_memdisk.img",
                    "--prefix=(memdisk)/boot/grub",
                    "-o",
                    f"/fll/{efitarget}.efi",
                    "search",
                    "search_fs_file",
                    "configfile",
                    "normal",
                    "memdisk",
                    "tar",
                    "part_msdos",
                    "part_gpt",
                    "lvm",
                    "fat",
                    "ext2",
                ]
                self.chroot_exec(chroot, cmd)
                shutil.move(os.path.join(chroot_dir, f"fll/{efitarget}.efi"), efi_dst)
                os.unlink(memdisk_img)

            # Stage grub EFI module and font files inside the FAT tree
            gfile_dir = os.path.join(chroot_dir, f"usr/lib/grub/{efitype}")
            gfiles = [
                os.path.join(gfile_dir, f)
                for f in os.listdir(gfile_dir)
                if f.endswith(".mod") or f.endswith(".lst")
            ]
            unicode_pf2 = os.path.join(chroot_dir, "usr/share/grub/unicode.pf2")
            if os.path.isfile(unicode_pf2):
                gfiles.append(unicode_pf2)
            esp_grub_dir = os.path.join(stage_dir, f"efi/boot/grub/{efitype}")
            os.makedirs(esp_grub_dir, exist_ok=True)
            for f in gfiles:
                if os.path.isfile(f):
                    shutil.copy(f, esp_grub_dir)

        # Stage grub data files (locales, tz, theme) inside the FAT tree — once only
        esp_grub_base = os.path.join(stage_dir, "efi/boot/grub")
        if not os.path.isfile(os.path.join(esp_grub_base, "grub.cfg")):
            shutil.copy(os.path.join(self.opts.share, "data/grub.cfg"), esp_grub_base)
            # unicode.pf2 must be at /boot/grub/unicode.pf2 on the FAT;
            # grub.cfg calls loadfont at that path before enabling gfxterm
            unicode_pf2 = os.path.join(chroot_dir, "usr/share/grub/unicode.pf2")
            if os.path.isfile(unicode_pf2):
                shutil.copy(unicode_pf2, esp_grub_base)
            shutil.copytree(
                os.path.join(self.opts.share, "data/locales"),
                os.path.join(esp_grub_base, "locales"),
                dirs_exist_ok=True,
            )
            shutil.copytree(
                os.path.join(self.opts.share, "data/tz"),
                os.path.join(esp_grub_base, "tz"),
                dirs_exist_ok=True,
            )
            theme_dir = f"themes/{self.conf['distro']['FLL_GFXBOOT_THEME']}"
            if os.path.isfile(
                os.path.join(chroot_dir, f"usr/share/grub/{theme_dir}/theme.txt")
            ):
                shutil.copytree(
                    os.path.join(chroot_dir, f"usr/share/grub/{theme_dir}"),
                    os.path.join(esp_grub_base, theme_dir),
                    dirs_exist_ok=True,
                )

        # Stage memtest binaries inside the FAT tree
        for mt in ["mt86+ia32", "mt86+x64"]:
            memtest = os.path.join(chroot_dir, "boot", mt)
            if os.path.isfile(memtest):
                self.log.debug(f"copying {mt} to ESP")
                shutil.copy(memtest, os.path.join(stage_dir, "efi/boot", mt))

        # Stage kernel and initramfs for this chroot inside the FAT tree.
        # kernels.cfg entries reference /{chroot}/vmlinuz and /{chroot}/initrd.
        vmlinuz_files = glob.glob(os.path.join(chroot_dir, "boot", "vmlinuz-*"))
        initrd_files = glob.glob(os.path.join(chroot_dir, "boot", "initrd.img-*"))
        if len(vmlinuz_files) != 1 or len(initrd_files) != 1:
            self.log.critical(
                f"{chroot} - could not find unique kernel/initramfs for ESP staging"
            )
            raise FllError
        esp_chroot_dir = os.path.join(stage_dir, f"efi/{chroot}")
        os.makedirs(esp_chroot_dir, exist_ok=True)
        self.log.info(f"{chroot} - staging kernel and initramfs onto ESP...")
        shutil.copy(vmlinuz_files[0], os.path.join(esp_chroot_dir, "vmlinuz"))
        shutil.copy(initrd_files[0], os.path.join(esp_chroot_dir, "initrd"))

    def stage_systemd_boot(self, chroot: str) -> None:
        """Stage systemd-boot EFI binaries and copy kernel/initramfs onto the ESP."""
        chroot_dir = os.path.join(self.temp, chroot)
        stage_dir = os.path.join(self.temp, "staging")

        efi_src_dir = os.path.join(chroot_dir, "usr/lib/systemd/boot/efi")
        if not os.path.isdir(efi_src_dir):
            self.log.critical(f"{chroot} - systemd-boot EFI binaries not found")
            raise FllError

        # Stage the fallback bootloader binaries into EFI/BOOT/ on the ESP.
        # Runs per-chroot but is idempotent - same files each time.
        efi_boot_dir = os.path.join(stage_dir, "efi/EFI/BOOT")
        os.makedirs(efi_boot_dir, exist_ok=True)
        efi_binaries = {
            "systemd-bootx64.efi": "bootx64.efi",
            "systemd-bootia32.efi": "bootia32.efi",
            "systemd-bootaa64.efi": "bootaa64.efi",
        }
        for src_name, dst_name in efi_binaries.items():
            src = os.path.join(efi_src_dir, src_name)
            if os.path.isfile(src):
                self.log.debug(f"{chroot} - staging {dst_name}")
                shutil.copy(src, os.path.join(efi_boot_dir, dst_name))

        # Copy the kernel and initramfs for this chroot onto the ESP under a
        # per-chroot subdirectory.  All loader/entries/*.conf files for this
        # chroot's desktop variants point at these two files, so the kernel and
        # initramfs are stored exactly once per chroot regardless of how many
        # desktop specific entries are generated.
        vmlinuz_files = glob.glob(os.path.join(chroot_dir, "boot", "vmlinuz-*"))
        initrd_files = glob.glob(os.path.join(chroot_dir, "boot", "initrd.img-*"))
        if len(vmlinuz_files) != 1 or len(initrd_files) != 1:
            self.log.critical(
                f"{chroot} - could not find unique kernel/initramfs for ESP staging"
            )
            raise FllError

        esp_chroot_dir = os.path.join(stage_dir, f"efi/{chroot}")
        os.makedirs(esp_chroot_dir, exist_ok=True)
        self.log.info(f"{chroot} - staging kernel and initramfs onto ESP...")
        shutil.copy(vmlinuz_files[0], os.path.join(esp_chroot_dir, "vmlinuz"))
        shutil.copy(initrd_files[0], os.path.join(esp_chroot_dir, "initrd"))

        # for systemd-boot stage memtest on the ESP
        memtest_binaries = {
            "bootx64.efi": os.path.join(
                chroot_dir, "usr/lib/memtest86+/memtest86+x64.iso"
            ),
            "bootia32.efi": os.path.join(
                chroot_dir, "usr/lib/memtest86+/memtest86+ia32.iso"
            ),
        }
        for memtest_efi, memtest_iso in memtest_binaries.items():
            memtest_out = os.path.join(stage_dir, f"efi/{memtest_efi}")
            if os.path.isfile(memtest_iso) and not os.path.isfile(memtest_out):
                self.log.debug(f"extracting {memtest_efi} ...")
                try:
                    self.exec_cmd(
                        [
                            "osirrox",
                            "-indev",
                            memtest_iso,
                            "-extract",
                            f"/EFI/BOOT/{memtest_efi}",
                            memtest_out,
                        ]
                    )
                except FllError:
                    self.log.warning(
                        f"failed to extract {memtest_efi} from {memtest_iso}, skipping"
                    )

    def stage_refind(self, chroot: str) -> None:
        """Stage rEFInd EFI binary, assets, and kernel/initramfs onto the ESP."""
        chroot_dir = os.path.join(self.temp, chroot)
        stage_dir = os.path.join(self.temp, "staging")
        arch = self.conf["chroots"][chroot]["packages"]["arch"]

        arch_map = {
            "amd64": ("refind_x64.efi", "bootx64.efi"),
            "i386": ("refind_ia32.efi", "bootia32.efi"),
            "arm64": ("refind_aa64.efi", "bootaa64.efi"),
        }
        src_name, dst_name = arch_map.get(arch, ("refind_x64.efi", "bootx64.efi"))

        refind_pkg_dir = os.path.join(chroot_dir, "usr/share/refind/refind")
        src_efi = os.path.join(refind_pkg_dir, src_name)
        if not os.path.isfile(src_efi):
            self.log.critical(f"{chroot} - rEFInd EFI binary not found: {src_efi}")
            raise FllError

        efi_boot_dir = os.path.join(stage_dir, "efi/EFI/BOOT")
        os.makedirs(efi_boot_dir, exist_ok=True)
        self.log.debug(f"{chroot} - staging {dst_name} to EFI/BOOT/")
        shutil.copy(src_efi, os.path.join(efi_boot_dir, dst_name))

        icons_dst = os.path.join(efi_boot_dir, "icons")
        if not os.path.isdir(icons_dst):
            icons_src = os.path.join(refind_pkg_dir, "icons")
            if os.path.isdir(icons_src):
                self.log.debug(f"{chroot} - staging rEFInd icons")
                shutil.copytree(icons_src, icons_dst)
            else:
                self.log.warning(f"{chroot} - rEFInd icons not found: {icons_src}")

        fonts_dst = os.path.join(efi_boot_dir, "fonts")
        if not os.path.isdir(fonts_dst):
            fonts_src = os.path.join(chroot_dir, "usr/share/refind/fonts")
            if os.path.isdir(fonts_src):
                self.log.debug(f"{chroot} - staging rEFInd fonts")
                shutil.copytree(fonts_src, fonts_dst)
            else:
                self.log.warning(f"{chroot} - rEFInd fonts not found: {fonts_src}")

        wallpaper_name = self.conf["distro"]["FLL_WALLPAPER"].lstrip("/")
        banner_dst = os.path.join(efi_boot_dir, "background.png")
        if not os.path.isfile(banner_dst):
            wallpaper_link = os.path.join(chroot_dir, f"{wallpaper_name}-wide.png")
            if os.path.islink(wallpaper_link):
                link_target = os.readlink(wallpaper_link)
                if os.path.isabs(link_target):
                    real_path = os.path.join(chroot_dir, link_target.lstrip("/"))
                else:
                    real_path = os.path.join(
                        os.path.dirname(wallpaper_link), link_target
                    )
                if os.path.isfile(real_path):
                    self.log.debug(f"{chroot} - staging rEFInd banner: {real_path}")
                    shutil.copy(real_path, banner_dst)

        distro = self.conf["distro"]["FLL_DISTRO_NAME"]
        icon_name = f"os_{distro.lower()}.png"
        icons_staging = os.path.join(efi_boot_dir, "icons")
        icon_dst = os.path.join(icons_staging, icon_name)
        if not os.path.isfile(icon_dst):
            icon_src = os.path.join(
                chroot_dir,
                f"etc/calamares/branding/{distro}/{distro}-icon.png",
            )
            if os.path.isfile(icon_src):
                self.log.debug(f"{chroot} - staging rEFInd distro icon: {icon_name}")
                os.makedirs(icons_staging, exist_ok=True)
                shutil.copy(icon_src, icon_dst)

        memtest_map = {
            "bootx64.efi": "usr/lib/memtest86+/memtest86+x64.iso",
            "bootia32.efi": "usr/lib/memtest86+/memtest86+ia32.iso",
        }
        tools_dir = os.path.join(stage_dir, "efi/EFI/tools")
        os.makedirs(tools_dir, exist_ok=True)
        for efi_name, iso_rel_path in memtest_map.items():
            memtest_iso = os.path.join(chroot_dir, iso_rel_path)
            mt_name = efi_name.replace("boot", "memtest86+")
            memtest_out = os.path.join(tools_dir, mt_name)
            if os.path.isfile(memtest_iso) and not os.path.isfile(memtest_out):
                self.log.debug(f"{chroot} - extracting {mt_name} from memtest ISO")
                try:
                    self.exec_cmd(
                        [
                            "osirrox",
                            "-indev",
                            memtest_iso,
                            "-extract",
                            f"/EFI/BOOT/{efi_name}",
                            memtest_out,
                        ]
                    )
                except FllError:
                    self.log.warning(
                        f"{chroot} - failed to extract memtest {mt_name}, skipping"
                    )

        vmlinuz_files = glob.glob(os.path.join(chroot_dir, "boot", "vmlinuz-*"))
        initrd_files = glob.glob(os.path.join(chroot_dir, "boot", "initrd.img-*"))
        if len(vmlinuz_files) != 1 or len(initrd_files) != 1:
            self.log.critical(
                f"{chroot} - could not find unique kernel/initramfs for ESP staging"
            )
            raise FllError
        esp_chroot_dir = os.path.join(stage_dir, f"efi/{chroot}")
        os.makedirs(esp_chroot_dir, exist_ok=True)
        self.log.info(f"{chroot} - staging kernel and initramfs onto ESP...")
        shutil.copy(vmlinuz_files[0], os.path.join(esp_chroot_dir, "vmlinuz"))
        shutil.copy(initrd_files[0], os.path.join(esp_chroot_dir, "initrd"))

    def stage_bootloader(self, chroot: str) -> None:
        """Dispatch boot image creation to the configured bootloader."""
        bootloader = self.conf["options"]["bootloader"]
        try:
            stage_fn, _ = self.BOOTLOADER_REGISTRY[bootloader]
        except KeyError:
            self.log.critical(f"unknown bootloader: {bootloader!r}")
            raise FllError
        getattr(self, stage_fn)(chroot)

    def write_grub_cfg(self) -> None:
        """Write grub.cfg for live media."""
        self.log.info("writing grub.cfg for live media...")
        stage_dir = os.path.join(self.temp, "staging")
        boot_dir = os.path.join(stage_dir, "boot")
        grub_dir = os.path.join(boot_dir, "grub")
        distro = self.conf["distro"]["FLL_DISTRO_NAME"]
        timeout = self.conf["options"].get("boot_timeout", "-1")

        with open(os.path.join(grub_dir, "kernels.cfg"), "w") as kcfg:
            for chroot in self.chroots:
                vmlinuz = f"vmlinuz-{chroot}"
                initrd = f"initrd.img-{chroot}"
                arch = self.conf["chroots"][chroot]["packages"]["arch"]
                cmdline = self.config_boot_cmdline(distro, chroot)
                indent = ""
                desktops = sorted(self.profiles[chroot].desktops)

                for filename in [vmlinuz, initrd]:
                    if not os.path.isfile(os.path.join(boot_dir, filename)):
                        self.log.critical(f"{filename} was not found in {boot_dir}")
                        raise FllError

                if arch[0:3] == "amd":
                    indent += "  "
                    kcfg.write("if cpuid -l; then\n")
                    kcfg.write(f'{indent}havekernel="Y"\n')

                if len(self.chroots) > 1 and len(desktops) > 1:
                    title = f"{distro} {chroot} [{', '.join(desktops)}]"
                    kcfg.write(
                        f'{indent}submenu --class={distro}.{arch} "{title}"' + " {\n"
                    )
                    indent += "  "

                for desktop in desktops:
                    title = f"{distro} {chroot} {desktop}"
                    # arch is passed to the --class option so that a 64bit fred icon
                    # may be displayed next to the menu entry by gfxboot theme
                    kcfg.write(
                        f'{indent}menuentry --class={distro}.{arch} "{title}"' + " {\n"
                    )
                    kcfg.write(
                        f"{indent}  linux /boot/{vmlinuz} {cmdline} desktop={desktop} $kopts\n"
                    )
                    kcfg.write(f"{indent}  initrd /boot/{initrd}\n")
                    kcfg.write(f"{indent}" + "}\n")
                else:
                    if len(desktops) == 0:
                        title = f"{distro} {chroot}"
                        kcfg.write(
                            f'{indent}menuentry --class={distro}.{arch} "{title}"'
                            + " {\n"
                        )
                        kcfg.write(
                            f"{indent}  linux /boot/{vmlinuz} {cmdline} $kopts\n"
                        )
                        kcfg.write(f"{indent}  initrd /boot/{initrd}\n")
                        kcfg.write(f"{indent}" + "}\n")

                if len(self.chroots) > 1 and len(desktops) > 1:
                    indent = indent[:-2]
                    kcfg.write(f"{indent}" + "}\n")

                if arch[0:3] == "amd":
                    kcfg.write("fi\n")

            kcfg.write('if [ "${havekernel}" != "Y" ]; then\n')
            kcfg.write(
                '  menuentry --class=find.none "NO SUITABLE KERNELS AVAILABLE" {\n'
            )
            kcfg.write("    echo $@\n")
            kcfg.write(
                '    echo "There are no kernels suitable for this machine available."\n'
            )
            kcfg.write('    echo ""\n')
            kcfg.write("    if ! cpuid -l; then\n")
            kcfg.write('      echo "This machine is NOT 64bit capable."\n')
            kcfg.write("    fi\n")
            kcfg.write('    echo ""\n')
            kcfg.write('    echo "Press Escape to halt computer."\n')
            kcfg.write(f"    sleep --verbose --interruptible {timeout}\n")
            kcfg.write("    halt\n")
            kcfg.write("  }\n")
            kcfg.write("fi\n")

        self.log.debug("writing loopback.cfg for live media")
        with open(os.path.join(grub_dir, "loopback.cfg"), "w") as lcfg:
            lcfg.write("source /boot/grub/grub.cfg\n")

        self.log.debug("writing variable.cfg for live media")
        with open(os.path.join(grub_dir, "variable.cfg"), "w") as vcfg:
            grub_theme = (
                f"grub/themes/{self.conf['distro']['FLL_GFXBOOT_THEME']}/theme.txt"
            )
            if os.path.isfile(os.path.join(boot_dir, grub_theme)):
                vcfg.write(f"grub_theme=/boot/{grub_theme}\n")
            vcfg.write(f"timeout={timeout}\n")

        # Build the FAT EFI system partition image now that all chroots have
        # staged their arch-specific EFI content under staging/efi/
        stage_dir = os.path.join(self.temp, "staging")
        if os.path.isdir(os.path.join(stage_dir, "efi")):
            self._build_efi_fat_img(stage_dir)

    def write_grub_efi_cfg(self) -> None:
        """Write grub kernels.cfg and variable.cfg into the ESP FAT tree,
        then build efi.img. All grub config is self-contained in the FAT;
        nothing is written to the ISO9660 layer."""
        self.log.info("writing grub-efi configuration onto ESP...")
        stage_dir = os.path.join(self.temp, "staging")
        esp_grub_dir = os.path.join(stage_dir, "efi/boot/grub")
        os.makedirs(esp_grub_dir, exist_ok=True)

        distro = self.conf["distro"]["FLL_DISTRO_NAME"]
        timeout = self.conf["options"].get("boot_timeout", "-1")

        with open(os.path.join(esp_grub_dir, "kernels.cfg"), "w") as kcfg:
            for chroot in self.chroots:
                # Kernel and initramfs live in /{chroot}/ on the FAT volume
                vmlinuz = f"/{chroot}/vmlinuz"
                initrd = f"/{chroot}/initrd"
                arch = self.conf["chroots"][chroot]["packages"]["arch"]
                cmdline = self.config_boot_cmdline(distro, chroot)
                indent = ""
                desktops = sorted(self.profiles[chroot].desktops)

                if arch[0:3] == "amd":
                    indent += "  "
                    kcfg.write("if cpuid -l; then\n")
                    kcfg.write(f'{indent}havekernel="Y"\n')

                if len(self.chroots) > 1 and len(desktops) > 1:
                    title = f"{distro} {chroot} [{', '.join(desktops)}]"
                    kcfg.write(
                        f'{indent}submenu --class={distro}.{arch} "{title}"' + " {\n"
                    )
                    indent += "  "

                for desktop in desktops:
                    title = f"{distro} {chroot} {desktop}"
                    kcfg.write(
                        f'{indent}menuentry --class={distro}.{arch} "{title}"' + " {\n"
                    )
                    kcfg.write(
                        f"{indent}  linux {vmlinuz} {cmdline} desktop={desktop} $kopts\n"
                    )
                    kcfg.write(f"{indent}  initrd {initrd}\n")
                    kcfg.write(f"{indent}" + "}\n")
                else:
                    if len(desktops) == 0:
                        title = f"{distro} {chroot}"
                        kcfg.write(
                            f'{indent}menuentry --class={distro}.{arch} "{title}"'
                            + " {\n"
                        )
                        kcfg.write(f"{indent}  linux {vmlinuz} {cmdline} $kopts\n")
                        kcfg.write(f"{indent}  initrd {initrd}\n")
                        kcfg.write(f"{indent}" + "}\n")

                if len(self.chroots) > 1 and len(desktops) > 1:
                    indent = indent[:-2]
                    kcfg.write(f"{indent}" + "}\n")

                if arch[0:3] == "amd":
                    kcfg.write("fi\n")

            kcfg.write('if [ "${havekernel}" != "Y" ]; then\n')
            kcfg.write(
                '  menuentry --class=find.none "NO SUITABLE KERNELS AVAILABLE" {\n'
            )
            kcfg.write("    echo $@\n")
            kcfg.write(
                '    echo "There are no kernels suitable for this machine available."\n'
            )
            kcfg.write('    echo ""\n')
            kcfg.write("    if ! cpuid -l; then\n")
            kcfg.write('      echo "This machine is NOT 64bit capable."\n')
            kcfg.write("    fi\n")
            kcfg.write('    echo ""\n')
            kcfg.write('    echo "Press Escape to halt computer."\n')
            kcfg.write(f"    sleep --verbose --interruptible {timeout}\n")
            kcfg.write("    halt\n")
            kcfg.write("  }\n")
            kcfg.write("fi\n")

        self.log.debug("writing variable.cfg for grub-efi")
        with open(os.path.join(esp_grub_dir, "variable.cfg"), "w") as vcfg:
            # esp_grub_dir is already staging/efi/boot/grub, so the theme
            # is one level below — no leading "grub/" in the relative path.
            # The FAT path written into variable.cfg needs the full prefix.
            grub_theme_rel = (
                f"themes/{self.conf['distro']['FLL_GFXBOOT_THEME']}/theme.txt"
            )
            if os.path.isfile(os.path.join(esp_grub_dir, grub_theme_rel)):
                vcfg.write(f"grub_theme=/boot/grub/{grub_theme_rel}\n")
            vcfg.write(f"timeout={timeout}\n")

        # All ESP content is staged under staging/efi/; build efi.img now.
        self._build_efi_fat_img(stage_dir)

    def write_systemd_loader_conf(self) -> None:
        """Write systemd-boot loader entries and loader.conf; build efi.img."""
        self.log.info("writing systemd-boot loader configuration...")
        stage_dir = os.path.join(self.temp, "staging")

        # All loader content lives inside staging/efi/ so it ends up in the
        # FAT image, not in the ISO9660 tree.
        loader_dir = os.path.join(stage_dir, "efi/loader")
        entries_dir = os.path.join(loader_dir, "entries")
        os.makedirs(entries_dir, exist_ok=True)

        distro = self.conf["distro"]["FLL_DISTRO_NAME"]
        timeout = self.conf["options"].get("boot_timeout", "30")

        # One entry file per desktop (or one per chroot when there are no
        # desktops).  All entries for the same chroot share the single
        # vmlinuz and initrd that create_systemd_boot_images() copied onto
        # the ESP, so the kernel and initramfs are stored only once per chroot.
        first_entry = None
        for chroot in self.chroots:
            cmdline_base = self.config_boot_cmdline(distro, chroot)
            desktops = sorted(self.profiles[chroot].desktops)

            entries = []
            if desktops:
                for desktop in desktops:
                    entries.append(
                        (
                            f"{chroot}-{desktop}",
                            f"{distro} {chroot} {desktop}",
                            f"{cmdline_base} desktop={desktop}",
                        )
                    )
            else:
                entries.append((chroot, f"{distro} {chroot}", cmdline_base))

            for entry_name, title, opts in entries:
                if first_entry is None:
                    first_entry = entry_name
                self.log.debug(f"writing loader entry: {entry_name}.conf")
                with open(os.path.join(entries_dir, f"{entry_name}.conf"), "w") as f:
                    f.write(f"title   {title}\n")
                    f.write(f"linux   /{chroot}/vmlinuz\n")
                    f.write(f"initrd  /{chroot}/initrd\n")
                    f.write(f"options {opts}\n")

        for mt in ["bootx64.efi", "bootia32.efi"]:
            memtest = os.path.join(stage_dir, f"efi/{mt}")
            if os.path.isfile(memtest):
                self.log.debug(f"writing {mt} to loader entry")
                with open(os.path.join(entries_dir, f"{mt}.conf"), "w") as f:
                    f.write(f"title Memory test ({mt})\n")
                    f.write(f"efi   /{mt}\n")

        self.log.debug("writing efi/loader/loader.conf")
        with open(os.path.join(loader_dir, "loader.conf"), "w") as f:
            f.write(f"timeout {timeout}\n")
            if first_entry:
                f.write(f"default {first_entry}.conf\n")
            f.write("editor yes\n")

        # All ESP content (EFI/BOOT/, {chroot}/, loader/) is now staged under
        # staging/efi/; build the FAT image from it.
        self._build_efi_fat_img(stage_dir)

    def write_refind_conf(self) -> None:
        """Write rEFInd configuration and pack the ESP FAT image."""
        self.log.info("writing rEFInd configuration...")
        stage_dir = os.path.join(self.temp, "staging")
        refind_boot_dir = os.path.join(stage_dir, "efi/EFI/BOOT")
        os.makedirs(refind_boot_dir, exist_ok=True)

        distro = self.conf["distro"]["FLL_DISTRO_NAME"]
        timeout = self.conf["options"].get("boot_timeout", "30")

        banner_file = os.path.join(refind_boot_dir, "background.png")
        icon_name = f"os_{distro.lower()}.png"
        icon_path = (
            f"/EFI/BOOT/icons/{icon_name}"
            if os.path.isfile(os.path.join(refind_boot_dir, "icons", icon_name))
            else "/EFI/BOOT/icons/os_linux.png"
        )

        with open(os.path.join(refind_boot_dir, "refind.conf"), "w") as f:
            f.write(f"timeout {timeout}\n")
            f.write("scanfor manual,firmware\n")
            if os.path.isfile(banner_file):
                f.write("banner /EFI/BOOT/background.png\n")
                f.write("banner_scale fillscreen\n")
                f.write("use_graphics_for linux\n")
            f.write("\n")

            for chroot in self.chroots:
                cmdline_base = self.config_boot_cmdline(distro, chroot)
                desktops = sorted(self.profiles[chroot].desktops)

                for number, desktop in enumerate(desktops):
                    f.write(f'menuentry "{distro} {desktop}" {{\n')
                    f.write(f"    loader /{chroot}/vmlinuz\n")
                    f.write(f"    initrd /{chroot}/initrd\n")
                    f.write(f'    options "{cmdline_base} desktop={desktop}"\n')
                    f.write(f"    icon {icon_path}\n")
                    f.write("}\n\n")
                    if number == len(desktops) - 1:
                        break
                else:
                    f.write(f'menuentry "{distro} {chroot}" {{\n')
                    f.write(f"    loader /{chroot}/vmlinuz\n")
                    f.write(f"    initrd /{chroot}/initrd\n")
                    f.write(f'    options "{cmdline_base}"\n')
                    f.write(f"    icon {icon_path}\n")
                    f.write("}\n\n")

        self._build_efi_fat_img(stage_dir)

    def write_bootloader_config(self) -> None:
        """Dispatch boot configuration writing to the configured bootloader."""
        bootloader = self.conf["options"]["bootloader"]
        try:
            _, config_fn = self.BOOTLOADER_REGISTRY[bootloader]
        except KeyError:
            self.log.critical(f"unknown bootloader: {bootloader!r}")
            raise FllError
        getattr(self, config_fn)()

    def config_boot_cmdline(self, distro: str, chroot: str) -> str:
        image_dir = self.conf["distro"]["FLL_IMAGE_DIR"]
        cmdline = self.conf["options"].get("boot_cmdline")
        rootfs_uuid = self.conf["chroots"][chroot].get("uuid")
        if self.opts.timezone:
            cmdline += f" tz={host_timezone()}"
        if len(self.opts.locales) == 1:
            cmdline += f" lang={self.opts.locales[0]}"
        cmdline = (
            f"iso_uuid={self.xorriso_uuid} "
            + f"image_dir={image_dir} image_file={distro}.{chroot} "
            + cmdline
        )
        if self.conf["options"]["readonly_filesystem"] == "erofs":
            cmdline += f" rootfs_uuid={rootfs_uuid}"
            if self.opts.persist:
                cmdline += f" persist_uuid={self.persist_uuid}"
                if self.opts.encrypt:
                    cmdline += f" persist_luks_uuid={self.persist_luks_uuid}"
        if self.conf["options"]["initramfs_tool"] == "initramfs-tools":
            cmdline = "boot=fll " + cmdline
        elif self.conf["options"]["initramfs_tool"] == "dracut":
            cmdline = "systemd.gpt_auto=0 SYSTEMD_SULOGIN_FORCE=1 " + cmdline
        self.log.debug(f"boot_cmdline: {cmdline}")
        return cmdline
