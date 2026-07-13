# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import os
import types

from pyfll.bootloader import BootloaderMixin


def _make_arm64_bootloader(tmp_path):
    """A single arm64 chroot with no desktops -- the minimal shape needed to
    reach the 'NO SUITABLE KERNELS AVAILABLE' fallback logic."""
    bl = BootloaderMixin.__new__(BootloaderMixin)
    bl.log = logging.getLogger("test_bootloader")
    bl.temp = str(tmp_path)
    bl.chroots = ["arm64chroot"]
    bl.profiles = {"arm64chroot": types.SimpleNamespace(desktops=set())}
    bl.xorriso_uuid = "11111111-1111-1111-1111-111111111111"
    bl.persist_uuid = None
    bl.persist_luks_uuid = None
    bl.opts = types.SimpleNamespace(
        timezone=False, locales=[], persist=False, encrypt=False
    )
    bl._build_efi_fat_img = lambda stage_dir: None
    bl.conf = {
        "distro": {
            "FLL_DISTRO_NAME": "aptosid",
            "FLL_IMAGE_DIR": "live",
            "FLL_GFXBOOT_THEME": "aptosid",
        },
        "options": {
            "boot_timeout": "-1",
            "boot_cmdline": "",
            "readonly_filesystem": "squashfs",
            "initramfs_tool": "initramfs-tools",
        },
        "chroots": {
            "arm64chroot": {
                "packages": {"arch": "arm64"},
            }
        },
    }
    return bl


def test_write_grub_efi_cfg_sets_havekernel_for_non_amd_arch(tmp_path):
    """arm64/i386 kernel entries aren't cpuid-gated, so havekernel="Y" must
    still be written unconditionally, or the 'NO SUITABLE KERNELS AVAILABLE'
    fallback always fires despite a valid entry above it."""
    bl = _make_arm64_bootloader(tmp_path)

    bl.write_grub_efi_cfg()

    kernels_cfg = os.path.join(
        tmp_path, "staging", "efi/boot/grub", "kernels.cfg"
    )
    text = open(kernels_cfg).read()

    assert 'havekernel="Y"' in text
    # not inside a cpuid-gated if-block: arm64 doesn't need the amd64 runtime
    # long-mode check
    assert "if cpuid -l" not in text
    assert "NO SUITABLE KERNELS AVAILABLE" in text
