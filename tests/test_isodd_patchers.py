# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

from pyfll.isodd import (
    _patch_grub_efi_kernels_cfg,
    _patch_refind_conf,
    _patch_systemd_boot_entries,
)


def test_patch_grub_efi_kernels_cfg_appends_param(tmp_path):
    grub_dir = tmp_path / "boot" / "grub"
    grub_dir.mkdir(parents=True)
    kernels_cfg = grub_dir / "kernels.cfg"
    kernels_cfg.write_text(
        "menuentry 'foo' {\n"
        "    linux /vmlinuz root=/dev/sda1\n"
        "    initrd /initrd.img\n"
        "}\n"
    )

    _patch_grub_efi_kernels_cfg(str(tmp_path), "toram", "1")

    text = kernels_cfg.read_text()
    assert "linux /vmlinuz root=/dev/sda1 toram=1\n" in text


def test_patch_grub_efi_kernels_cfg_replaces_existing_value(tmp_path):
    grub_dir = tmp_path / "boot" / "grub"
    grub_dir.mkdir(parents=True)
    kernels_cfg = grub_dir / "kernels.cfg"
    kernels_cfg.write_text("    linux /vmlinuz toram=0 quiet\n")

    _patch_grub_efi_kernels_cfg(str(tmp_path), "toram", "1")

    assert "toram=1" in kernels_cfg.read_text()
    assert "toram=0" not in kernels_cfg.read_text()


def test_patch_grub_efi_kernels_cfg_missing_file_is_noop(tmp_path):
    # should not raise when boot/grub/kernels.cfg doesn't exist
    _patch_grub_efi_kernels_cfg(str(tmp_path), "toram", "1")


def test_patch_systemd_boot_entries_appends_param(tmp_path):
    entries_dir = tmp_path / "loader" / "entries"
    entries_dir.mkdir(parents=True)
    (entries_dir / "01-fll.conf").write_text(
        "title fll\noptions root=/dev/sda1 quiet\n"
    )

    _patch_systemd_boot_entries(str(tmp_path), "toram", "1")

    text = (entries_dir / "01-fll.conf").read_text()
    assert "options root=/dev/sda1 quiet toram=1\n" in text


def test_patch_systemd_boot_entries_ignores_non_conf_files(tmp_path):
    entries_dir = tmp_path / "loader" / "entries"
    entries_dir.mkdir(parents=True)
    other = entries_dir / "readme.txt"
    other.write_text("options should not be touched\n")

    _patch_systemd_boot_entries(str(tmp_path), "toram", "1")

    assert other.read_text() == "options should not be touched\n"


def test_patch_refind_conf_only_touches_menuentry_options(tmp_path):
    efi_dir = tmp_path / "EFI" / "BOOT"
    efi_dir.mkdir(parents=True)
    refind_conf = efi_dir / "refind.conf"
    refind_conf.write_text(
        'options "root=/dev/sda1"\n'
        "menuentry fll {\n"
        '    options "root=/dev/sda1 quiet"\n'
        "}\n"
    )

    _patch_refind_conf(str(tmp_path), "toram", "1")

    lines = refind_conf.read_text().splitlines()
    # the top-level options line, outside any menuentry block, is untouched
    assert lines[0] == 'options "root=/dev/sda1"'
    assert '    options "root=/dev/sda1 quiet toram=1"' in lines
