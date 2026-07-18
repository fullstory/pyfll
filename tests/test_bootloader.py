# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import os
import types

import pyfll.bootloader
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


def test_write_grub_efi_cfg_per_desktop_entries_and_no_fallback_menuentry(tmp_path):
    """A chroot with desktops gets one menuentry per desktop and must NOT
    also get the empty-desktops fallback entry (the two used to be for/else
    branches of the same for loop; verify both still fire independently)."""
    bl = _make_arm64_bootloader(tmp_path)
    bl.chroots = ["amd64chroot"]
    bl.profiles = {
        "amd64chroot": types.SimpleNamespace(desktops={"xfce", "sway"})
    }
    bl.conf["chroots"] = {"amd64chroot": {"packages": {"arch": "amd64"}}}

    bl.write_grub_efi_cfg()

    kernels_cfg = os.path.join(tmp_path, "staging", "efi/boot/grub", "kernels.cfg")
    text = open(kernels_cfg).read()

    assert text.count("menuentry --class=aptosid.amd64") == 2
    assert 'menuentry --class=aptosid.amd64 "aptosid amd64chroot"' not in text


def test_config_boot_cmdline_grub_omits_lang_tz(tmp_path, monkeypatch):
    """grub carries lang/tz via the locale menu (variable.cfg + $kopts), so
    include_locale=False must keep them out of the baked cmdline; the default
    (systemd-boot/refind) still bakes them."""
    monkeypatch.setattr(pyfll.bootloader, "host_timezone", lambda: "Europe/Berlin")
    bl = _make_arm64_bootloader(tmp_path)
    bl.opts.timezone = True
    bl.opts.locales = ["de_DE"]

    baked = bl.config_boot_cmdline("aptosid", "arm64chroot")
    assert "lang=de_DE" in baked
    assert "tz=Europe/Berlin" in baked

    grub = bl.config_boot_cmdline("aptosid", "arm64chroot", include_locale=False)
    assert "lang=" not in grub
    assert "tz=" not in grub


def test_grub_efi_variable_cfg_preseeds_locale(tmp_path, monkeypatch):
    """When lang/tz are preseeded, variable.cfg must set the grub locale-menu
    vars so the menu reflects them (and $kopts carries them), and kernels.cfg
    must not bake them a second time."""
    monkeypatch.setattr(pyfll.bootloader, "host_timezone", lambda: "Europe/Berlin")
    bl = _make_arm64_bootloader(tmp_path)
    bl.opts.timezone = True
    bl.opts.locales = ["de_DE"]

    bl.write_grub_efi_cfg()

    grub_dir = os.path.join(tmp_path, "staging", "efi/boot/grub")
    variable_cfg = open(os.path.join(grub_dir, "variable.cfg")).read()
    assert 'timezone="tz=Europe/Berlin"' in variable_cfg
    assert 'def_timezone="Europe/Berlin"' in variable_cfg
    assert "source /boot/grub/locales/de_DE" in variable_cfg

    kernels_cfg = open(os.path.join(grub_dir, "kernels.cfg")).read()
    assert "lang=de_DE" not in kernels_cfg
    assert "tz=Europe/Berlin" not in kernels_cfg


def test_grub_efi_variable_cfg_no_locale_when_unset(tmp_path):
    """No preseed -> variable.cfg carries no locale vars, leaving grub's
    en_US/UTC fallback untouched."""
    bl = _make_arm64_bootloader(tmp_path)

    bl.write_grub_efi_cfg()

    variable_cfg = open(
        os.path.join(tmp_path, "staging", "efi/boot/grub", "variable.cfg")
    ).read()
    assert "def_timezone" not in variable_cfg
    assert "bootlang" not in variable_cfg
    assert "locales/" not in variable_cfg
