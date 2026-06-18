# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import argparse
import os
import re
import subprocess
import sys
import tempfile

from pyfll.util import run_process

SGDISK = "/usr/sbin/sgdisk"
SGDISK_ALIGN = 4
MIB_SECTORS = 2048


def extract_grub_persist_uuid(
    iso: str, verbose: bool = False, log_fn=print
) -> str | None:
    """Extract persist_uuid from /boot/grub/kernels.cfg inside the ISO.

    Used for grub ISOs where the UUID is baked into the ISO9660 tree by pyfll
    at build time. Returns the UUID string, or None if not found.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        kernels_cfg = os.path.join(tmpdir, "kernels.cfg")
        try:
            run_process(
                [
                    "osirrox",
                    "-indev",
                    iso,
                    "-extract",
                    "/boot/grub/kernels.cfg",
                    kernels_cfg,
                ],
                verbose=verbose,
                log_fn=log_fn,
            )
            with open(kernels_cfg) as f:
                content = f.read()
        except (Exception, OSError):
            return None

        match = re.search(r"persist_uuid=(\S+)", content)
        return match.group(1) if match else None


def detect_bootloader(
    iso: str, verbose: bool = False, log_fn=print
) -> str | None:
    """Detect which bootloader the ISO was built with.

    grub (BIOS/EFI hybrid) stores kernels.cfg directly on the ISO9660 layer.
    grub-efi, systemd-boot, and rEFInd all embed an efi.img containing all
    required boot artifacts and configuration.

    Returns one of: "grub", "grub-efi", "systemd-boot", "refind", or None.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        kernels_cfg = os.path.join(tmpdir, "kernels.cfg")
        try:
            run_process(
                [
                    "osirrox",
                    "-indev",
                    iso,
                    "-extract",
                    "/boot/grub/kernels.cfg",
                    kernels_cfg,
                ],
                verbose=verbose,
                log_fn=log_fn,
            )
            if os.path.isfile(kernels_cfg):
                return "grub"
        except Exception:
            pass

        efi_img = os.path.join(tmpdir, "efi.img")
        try:
            run_process(
                ["osirrox", "-indev", iso, "-extract", "/efi.img", efi_img],
                verbose=verbose,
                log_fn=log_fn,
            )
        except Exception:
            pass

        if os.path.isfile(efi_img):
            kernels_cfg_fat = os.path.join(tmpdir, "kernels.cfg.fat")
            try:
                run_process(
                    [
                        "mcopy",
                        "-i",
                        efi_img,
                        "::/boot/grub/kernels.cfg",
                        kernels_cfg_fat,
                    ],
                    verbose=verbose,
                    log_fn=log_fn,
                )
                if os.path.isfile(kernels_cfg_fat):
                    return "grub-efi"
            except Exception:
                pass

            loader_conf = os.path.join(tmpdir, "loader.conf")
            try:
                run_process(
                    [
                        "mcopy",
                        "-i",
                        efi_img,
                        "::/loader/loader.conf",
                        loader_conf,
                    ],
                    verbose=verbose,
                    log_fn=log_fn,
                )
                if os.path.isfile(loader_conf):
                    return "systemd-boot"
            except Exception:
                pass

            refind_conf = os.path.join(tmpdir, "refind.conf")
            try:
                run_process(
                    [
                        "mcopy",
                        "-i",
                        efi_img,
                        "::/EFI/BOOT/refind.conf",
                        refind_conf,
                    ],
                    verbose=verbose,
                    log_fn=log_fn,
                )
                if os.path.isfile(refind_conf):
                    return "refind"
            except Exception:
                pass

    return None


def find_esp_partition(
    device: str, verbose: bool = False, log_fn=print
) -> str | None:
    """Return the device node of the EFI System Partition on *device*.

    Scans sgdisk --print for a partition with type code EF00.
    Returns the device path (e.g. /dev/sdb2), or None if not found.
    """
    output = run_process([SGDISK, "--print", device], verbose=verbose, log_fn=log_fn)
    for line in output:
        fields = line.split()
        if len(fields) >= 6 and fields[0].isdigit() and fields[5].upper() == "EF00":
            partnum = fields[0]
            real_device = os.path.realpath(device)
            if real_device[-1].isdigit():
                return f"{real_device}p{partnum}"
            return f"{real_device}{partnum}"
    return None


def inject_persist_uuid_into_esp(
    esp_dev: str, uuid: str, verbose: bool = False, log_fn=print
) -> None:
    """Mount the EFI System Partition and write persist_uuid=<uuid> into every
    boot entry that does not already carry it.

    Handles grub-efi, systemd-boot, and rEFInd configurations.
    The mount is always cleaned up, even on error.
    """
    with tempfile.TemporaryDirectory() as mnt:
        run_process(["mount", esp_dev, mnt], verbose=verbose, log_fn=log_fn)
        try:
            _patch_grub_efi_kernels_cfg(mnt, uuid, verbose=verbose, log_fn=log_fn)
            _patch_systemd_boot_entries(mnt, uuid, verbose=verbose, log_fn=log_fn)
            _patch_refind_conf(mnt, uuid, verbose=verbose, log_fn=log_fn)
        finally:
            run_process(["umount", mnt], verbose=verbose, log_fn=log_fn)


def _patch_grub_efi_kernels_cfg(
    mnt: str, uuid: str, verbose: bool = False, log_fn=print
) -> None:
    """Append persist_uuid=<uuid> to every 'linux' line in
    <mnt>/boot/grub/kernels.cfg that does not already carry it."""
    kernels_cfg = os.path.join(mnt, "boot", "grub", "kernels.cfg")
    if not os.path.isfile(kernels_cfg):
        return

    with open(kernels_cfg) as f:
        lines = f.readlines()

    changed = False
    new_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("linux ") and f"persist_uuid={uuid}" not in stripped:
            line = line.rstrip() + f" persist_uuid={uuid}\n"
            changed = True
        new_lines.append(line)

    if changed:
        if verbose:
            log_fn(f"# patching {kernels_cfg}")
        with open(kernels_cfg, "w") as f:
            f.writelines(new_lines)


def _patch_systemd_boot_entries(
    mnt: str, uuid: str, verbose: bool = False, log_fn=print
) -> None:
    """Append persist_uuid=<uuid> to every 'options' line in
    <mnt>/loader/entries/*.conf that does not already carry it."""
    entries_dir = os.path.join(mnt, "loader", "entries")
    if not os.path.isdir(entries_dir):
        return

    for fname in sorted(os.listdir(entries_dir)):
        if not fname.endswith(".conf"):
            continue
        fpath = os.path.join(entries_dir, fname)
        with open(fpath) as f:
            lines = f.readlines()

        changed = False
        new_lines: list[str] = []
        for line in lines:
            if line.startswith("options ") and f"persist_uuid={uuid}" not in line:
                line = line.rstrip() + f" persist_uuid={uuid}\n"
                changed = True
            new_lines.append(line)

        if changed:
            if verbose:
                log_fn(f"# patching {fpath}")
            with open(fpath, "w") as f:
                f.writelines(new_lines)


def _patch_refind_conf(
    mnt: str, uuid: str, verbose: bool = False, log_fn=print
) -> None:
    """Append persist_uuid=<uuid> to every 'options' line inside a menuentry
    block in <mnt>/EFI/BOOT/refind.conf that does not already carry it."""
    refind_conf = os.path.join(mnt, "EFI", "BOOT", "refind.conf")
    if not os.path.isfile(refind_conf):
        return

    with open(refind_conf) as f:
        lines = f.readlines()

    in_menuentry = False
    changed = False
    new_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("menuentry "):
            in_menuentry = True
        elif stripped == "}":
            in_menuentry = False
        elif (
            in_menuentry
            and stripped.startswith("options ")
            and f"persist_uuid={uuid}" not in stripped
        ):
            rstripped = line.rstrip()
            if rstripped.endswith('"'):
                line = rstripped[:-1] + f' persist_uuid={uuid}"\n'
            else:
                line = rstripped + f" persist_uuid={uuid}\n"
            changed = True
        new_lines.append(line)

    if changed:
        if verbose:
            log_fn(f"# patching {refind_conf}")
        with open(refind_conf, "w") as f:
            f.writelines(new_lines)


def storage_partition_dev(
    device: str, verbose: bool = False, log_fn=print
) -> str:
    """Return the device path of the last partition on *device*.

    Reads sgdisk --print in reverse and returns the path for the last entry
    whose first field is a partition number.
    """
    output = run_process([SGDISK, "--print", device], verbose=verbose, log_fn=log_fn)
    for line in reversed(output):
        fields = line.split()
        if fields and fields[0].isdigit():
            partnum = fields[0]
            real_device = os.path.realpath(device)
            if real_device[-1].isdigit():
                return os.path.realpath(f"{real_device}p{partnum}")
            else:
                return os.path.realpath(f"{real_device}{partnum}")
    sys.exit(f"error: could not determine storage partition on {device}")


def read_last_partition_sectors(
    device: str, verbose: bool = False, log_fn=print
) -> tuple[int, int, str, str] | None:
    """Return (start, end, typecode, name) of the last partition on *device*, or None.

    sgdisk --print columns: Number Start End Size(value) Size(unit) Code Name...
    """
    output = run_process([SGDISK, "--print", device], verbose=verbose, log_fn=log_fn)
    for line in reversed(output):
        fields = line.split()
        if fields and fields[0].isdigit():
            if len(fields) >= 6:
                start, end, typecode = int(fields[1]), int(fields[2]), fields[5]
                name = " ".join(fields[6:]) if len(fields) > 6 else ""
                return (start, end, typecode, name)
    return None


def iso_size_mib(iso: str) -> int:
    size = os.path.getsize(iso)
    return (size + (1024 * 1024 - 1)) // (1024 * 1024)


def setup_btrfs_persist(
    btrfs_dev: str, persist_uuid: str, verbose: bool = False, log_fn=print
) -> None:
    cmd = ["mkfs.btrfs", "-L", "fll-persist"]
    if persist_uuid:
        cmd += ["-U", persist_uuid]
    cmd.append(btrfs_dev)
    run_process(cmd, verbose=verbose, log_fn=log_fn)
    with tempfile.TemporaryDirectory() as mnt:
        run_process(
            ["mount", "-o", "subvolid=5", "-t", "btrfs", btrfs_dev, mnt],
            verbose=verbose,
            log_fn=log_fn,
        )
        try:
            run_process(
                ["btrfs", "subvolume", "create", os.path.join(mnt, "@root")],
                verbose=verbose,
                log_fn=log_fn,
            )
            run_process(
                ["btrfs", "subvolume", "create", os.path.join(mnt, "@home")],
                verbose=verbose,
                log_fn=log_fn,
            )
        finally:
            run_process(["umount", mnt], verbose=verbose, log_fn=log_fn)


def luks_format_and_open(
    part_dev: str,
    luks_uuid: str,
    mapper_name: str,
    verbose: bool = False,
    log_fn=print,
) -> None:
    subprocess.run(
        ["cryptsetup", "luksFormat", "--uuid", luks_uuid, part_dev],
        check=True,
    )
    subprocess.run(
        ["cryptsetup", "luksOpen", part_dev, mapper_name],
        check=True,
    )


def luks_close(mapper_name: str, verbose: bool = False, log_fn=print) -> None:
    run_process(
        ["cryptsetup", "luksClose", mapper_name],
        verbose=verbose,
        log_fn=log_fn,
    )


def luks_open_interactive(
    part_dev: str, mapper_name: str, verbose: bool = False
) -> None:
    subprocess.run(
        ["cryptsetup", "luksOpen", part_dev, mapper_name],
        check=True,
    )


def inject_luks_uuid_into_esp(
    esp_dev: str, luks_uuid: str, verbose: bool = False, log_fn=print
) -> None:
    """Mount the EFI System Partition and write persist_luks_uuid=<luks_uuid>
    into every boot entry that does not already carry it.

    Handles grub-efi, systemd-boot, and rEFInd configurations.
    The mount is always cleaned up, even on error.
    """
    with tempfile.TemporaryDirectory() as mnt:
        run_process(["mount", esp_dev, mnt], verbose=verbose, log_fn=log_fn)
        try:
            # grub-efi kernels.cfg
            kernels_cfg = os.path.join(mnt, "boot", "grub", "kernels.cfg")
            if os.path.isfile(kernels_cfg):
                with open(kernels_cfg) as f:
                    lines = f.readlines()
                changed = False
                new_lines: list[str] = []
                for line in lines:
                    stripped = line.strip()
                    if (
                        stripped.startswith("linux ")
                        and f"persist_luks_uuid={luks_uuid}" not in stripped
                    ):
                        line = line.rstrip() + f" persist_luks_uuid={luks_uuid}\n"
                        changed = True
                    new_lines.append(line)
                if changed:
                    if verbose:
                        log_fn(f"# patching {kernels_cfg}")
                    with open(kernels_cfg, "w") as f:
                        f.writelines(new_lines)

            # systemd-boot entries
            entries_dir = os.path.join(mnt, "loader", "entries")
            if os.path.isdir(entries_dir):
                for fname in sorted(os.listdir(entries_dir)):
                    if not fname.endswith(".conf"):
                        continue
                    fpath = os.path.join(entries_dir, fname)
                    with open(fpath) as f:
                        lines = f.readlines()
                    changed = False
                    new_lines = []
                    for line in lines:
                        if (
                            line.startswith("options ")
                            and f"persist_luks_uuid={luks_uuid}" not in line
                        ):
                            line = line.rstrip() + f" persist_luks_uuid={luks_uuid}\n"
                            changed = True
                        new_lines.append(line)
                    if changed:
                        if verbose:
                            log_fn(f"# patching {fpath}")
                        with open(fpath, "w") as f:
                            f.writelines(new_lines)

            # rEFInd conf
            refind_conf = os.path.join(mnt, "EFI", "BOOT", "refind.conf")
            if os.path.isfile(refind_conf):
                with open(refind_conf) as f:
                    lines = f.readlines()
                in_menuentry = False
                changed = False
                new_lines = []
                for line in lines:
                    stripped = line.strip()
                    if stripped.startswith("menuentry "):
                        in_menuentry = True
                    elif stripped == "}":
                        in_menuentry = False
                    elif (
                        in_menuentry
                        and stripped.startswith("options ")
                        and f"persist_luks_uuid={luks_uuid}" not in stripped
                    ):
                        rstripped = line.rstrip()
                        if rstripped.endswith('"'):
                            line = rstripped[:-1] + f' persist_luks_uuid={luks_uuid}"\n'
                        else:
                            line = rstripped + f" persist_luks_uuid={luks_uuid}\n"
                        changed = True
                    new_lines.append(line)
                if changed:
                    if verbose:
                        log_fn(f"# patching {refind_conf}")
                    with open(refind_conf, "w") as f:
                        f.writelines(new_lines)
        finally:
            run_process(["umount", mnt], verbose=verbose, log_fn=log_fn)


def reset_system_subvol(
    btrfs_dev: str, verbose: bool = False, log_fn=print
) -> None:
    try:
        run_process(
            ["udevadm", "settle", "--timeout=10"],
            verbose=verbose,
            log_fn=log_fn,
        )
    except Exception:
        pass
    with tempfile.TemporaryDirectory() as mnt:
        run_process(
            ["mount", "-o", "subvolid=5", "-t", "btrfs", btrfs_dev, mnt],
            verbose=verbose,
            log_fn=log_fn,
        )
        try:
            run_process(
                ["btrfs", "subvolume", "delete", os.path.join(mnt, "@root")],
                verbose=verbose,
                log_fn=log_fn,
            )
            run_process(
                ["btrfs", "subvolume", "create", os.path.join(mnt, "@root")],
                verbose=verbose,
                log_fn=log_fn,
            )
        finally:
            run_process(["umount", mnt], verbose=verbose, log_fn=log_fn)


def write_iso(
    iso: str,
    device: str,
    persist: bool = False,
    persist_uuid: str | None = None,
    persist_luks_uuid: str | None = None,
    encrypt: bool = False,
    verbose: bool = False,
    log_fn=print,
) -> None:
    """Write *iso* to *device* with dd and optionally create a persistent
    btrfs storage partition."""
    bootloader = None

    if persist:
        log_fn(f"Detecting bootloader in {iso}...")
        bootloader = detect_bootloader(iso, verbose=verbose, log_fn=log_fn)
        if bootloader is None:
            sys.exit("error: could not detect bootloader in ISO")
        log_fn(f"Detected bootloader: {bootloader}")

        if bootloader == "grub":
            if not persist_uuid:
                log_fn(f"Extracting persist_uuid from {iso} (grub)...")
                persist_uuid = extract_grub_persist_uuid(
                    iso, verbose=verbose, log_fn=log_fn
                )
                if persist_uuid is None:
                    sys.exit(
                        "error: persist_uuid not found in boot/grub/kernels.cfg\n"
                        "       Was the ISO built with pyfll --persist?"
                    )
            log_fn(f"persist_uuid: {persist_uuid}")

    log_fn(f"Wiping {device}...")
    run_process(
        ["wipefs", "--all", "--force", device], verbose=verbose, log_fn=log_fn
    )

    log_fn(f"Writing {iso} to {device}...")
    run_process(
        ["dd", f"if={iso}", f"of={device}", "bs=1M", "status=progress"],
        verbose=verbose,
        log_fn=log_fn,
    )

    log_fn("Relocating GPT alt header...")
    run_process(
        [SGDISK, "--move-second-header", device], verbose=verbose, log_fn=log_fn
    )

    log_fn("Settling partition table...")
    run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)

    if persist:
        log_fn(f"Creating gap and persist partitions on {device}...")
        gap_mib = iso_size_mib(iso) * 2
        gap_start_sector = (iso_size_mib(iso) + 1) * MIB_SECTORS
        gap_end_sector = gap_start_sector + (gap_mib * MIB_SECTORS) - 1

        run_process(
            [
                SGDISK,
                f"--set-alignment={SGDISK_ALIGN}",
                f"--new=0:{gap_start_sector}:{gap_end_sector}",
                "--typecode=0:0700",
                "--change-name=0:fll-gap",
                device,
            ],
            verbose=verbose,
            log_fn=log_fn,
        )

        run_process(
            [
                SGDISK,
                "--align-end",
                f"--set-alignment={SGDISK_ALIGN}",
                "--new=0:0:0",
                "--typecode=0:8300",
                "--change-name=0:fll-persist",
                device,
            ],
            verbose=verbose,
            log_fn=log_fn,
        )

        run_process(["partprobe", device], verbose=verbose, log_fn=log_fn)
        run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)
        part_dev = storage_partition_dev(device, verbose=verbose, log_fn=log_fn)

        if encrypt:
            if not persist_luks_uuid:
                import uuid as _uuid
                persist_luks_uuid = str(_uuid.uuid4())
            luks_format_and_open(
                part_dev, persist_luks_uuid, "fll-persist-setup",
                verbose=verbose, log_fn=log_fn,
            )
            btrfs_dev = "/dev/mapper/fll-persist-setup"
        else:
            btrfs_dev = part_dev

        if persist_uuid:
            setup_btrfs_persist(btrfs_dev, persist_uuid, verbose, log_fn)
        else:
            setup_btrfs_persist(btrfs_dev, "", verbose, log_fn)
            blkid_out = run_process(
                ["blkid", "-s", "UUID", "-o", "value", btrfs_dev],
                verbose=verbose,
                log_fn=log_fn,
            )
            persist_uuid = blkid_out[0].strip() if blkid_out else None
            if not persist_uuid:
                sys.exit(
                    f"error: could not read UUID from {btrfs_dev} after mkfs.btrfs"
                )

        if encrypt:
            luks_close("fll-persist-setup", verbose=verbose, log_fn=log_fn)
            esp_dev = find_esp_partition(device, verbose=verbose, log_fn=log_fn)
            if esp_dev:
                inject_luks_uuid_into_esp(
                    esp_dev, persist_luks_uuid, verbose=verbose, log_fn=log_fn
                )

        if bootloader != "grub":
            esp_dev = find_esp_partition(device, verbose=verbose, log_fn=log_fn)
            if esp_dev is None:
                sys.exit("error: EFI System Partition not found on device")
            inject_persist_uuid_into_esp(
                esp_dev, persist_uuid, verbose=verbose, log_fn=log_fn
            )

    run_process(
        [SGDISK, f"--set-alignment={SGDISK_ALIGN}", "--verify", device],
        verbose=verbose,
        log_fn=log_fn,
    )

    log_fn("Done.")


def upgrade_iso(
    iso: str,
    device: str,
    persist_uuid: str | None = None,
    encrypt: bool = False,
    verbose: bool = False,
    log_fn=print,
) -> None:
    """Write *iso* to *device* with dd conv=notrunc, then reset @root."""

    if not persist_uuid:
        persist_uuid = extract_grub_persist_uuid(iso, verbose=verbose, log_fn=log_fn)
    if not persist_uuid:
        bootloader = detect_bootloader(iso, verbose=verbose, log_fn=log_fn)
        if bootloader != "grub":
            esp_dev = find_esp_partition(device, verbose=verbose, log_fn=log_fn)
            if esp_dev:
                with tempfile.TemporaryDirectory() as mnt:
                    run_process(
                        ["mount", "-o", "ro", esp_dev, mnt],
                        verbose=verbose,
                        log_fn=log_fn,
                    )
                    try:
                        for dirpath, _, filenames in os.walk(mnt):
                            for fname in filenames:
                                fpath = os.path.join(dirpath, fname)
                                try:
                                    with open(fpath) as f:
                                        content = f.read()
                                    m = re.search(r"persist_uuid=(\S+)", content)
                                    if m:
                                        persist_uuid = m.group(1)
                                        break
                                except (OSError, UnicodeDecodeError):
                                    pass
                            if persist_uuid:
                                break
                    finally:
                        run_process(
                            ["umount", mnt], verbose=verbose, log_fn=log_fn
                        )
    if not persist_uuid:
        sys.exit("error: could not determine persist_uuid for upgrade")

    # Save persist partition sectors before dd overwrites the partition table.
    persist_part_sectors = None
    if encrypt:
        persist_part_sectors = read_last_partition_sectors(
            device, verbose=verbose, log_fn=log_fn
        )
        if persist_part_sectors is None:
            sys.exit("error: could not read persist partition sectors before upgrade")
        log_fn(
            f"Persist partition: start={persist_part_sectors[0]}"
            f" end={persist_part_sectors[1]}"
            f" type={persist_part_sectors[2]}"
        )

    log_fn(f"Upgrading ISO on {device} (dd conv=notrunc)...")
    subprocess.run(
        ["dd", f"if={iso}", f"of={device}", "bs=1M", "conv=notrunc", "status=progress"],
        check=True,
    )

    log_fn("Relocating GPT alt header...")
    run_process([SGDISK, "--move-second-header", device], verbose=verbose, log_fn=log_fn)
    run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)

    if encrypt:
        # Re-add the persist partition entry that dd erased from the partition table.
        start, end, typecode, name = persist_part_sectors
        sgdisk_cmd = [
            SGDISK,
            f"--set-alignment={SGDISK_ALIGN}",
            f"--new=0:{start}:{end}",
            f"--typecode=0:{typecode}",
        ]
        if name:
            sgdisk_cmd.append(f"--change-name=0:{name}")
        sgdisk_cmd.append(device)
        log_fn("Restoring persist partition entry...")
        run_process(sgdisk_cmd, verbose=verbose, log_fn=log_fn)
        run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)

        part_dev = storage_partition_dev(device, verbose=verbose, log_fn=log_fn)
        result = subprocess.run(
            ["cryptsetup", "isLuks", part_dev],
            capture_output=True,
        )
        if result.returncode != 0:
            sys.exit(f"error: {part_dev} is not a LUKS container after restore")
        luks_open_interactive(part_dev, "fll-persist-upgrade", verbose=verbose)
        btrfs_dev = "/dev/mapper/fll-persist-upgrade"
    else:
        btrfs_dev = f"/dev/disk/by-uuid/{persist_uuid}"

    reset_system_subvol(btrfs_dev, verbose=verbose, log_fn=log_fn)

    if encrypt:
        luks_close("fll-persist-upgrade", verbose=verbose, log_fn=log_fn)

    run_process(
        [SGDISK, f"--set-alignment={SGDISK_ALIGN}", "--verify", device],
        verbose=verbose,
        log_fn=log_fn,
    )
    log_fn("Upgrade complete.")


def main() -> None:
    __description__ = """
Write a fll live media ISO image to a block device with dd, and
optionally create a persistent btrfs storage partition, or upgrade
an existing device in-place while preserving the persist partition.
"""
    cli = argparse.ArgumentParser(
        description="Write fll live media ISO to a block device.",
        epilog=__description__,
    )
    cli.add_argument(
        "-i",
        "--iso",
        required=True,
        metavar="<iso>",
        help="Path to the fll live media ISO image.",
    )
    cli.add_argument(
        "-d",
        "--device",
        required=True,
        metavar="<device>",
        help="Target block device. WARNING: destroys all existing data.",
    )
    cli.add_argument(
        "-p",
        "--persist",
        action="store_true",
        default=False,
        help="Create a persistent btrfs storage partition.",
    )
    cli.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Show commands and extra output.",
    )
    cli.add_argument(
        "-U",
        "--upgrade",
        action="store_true",
        default=False,
        help=(
            "Upgrade mode: write the new ISO with dd conv=notrunc (persist "
            "partition untouched), then reset @root. @home is never touched."
        ),
    )
    cli.add_argument(
        "-e",
        "--encrypt",
        action="store_true",
        default=False,
        help=(
            "Encrypt the persist partition with LUKS2 using an interactive "
            "passphrase. Only valid with --persist. The same passphrase unlocks "
            "the device at boot and at upgrade time."
        ),
    )
    args = cli.parse_args()

    if not os.path.isfile(args.iso):
        sys.exit(f"error: ISO not found: {args.iso}")
    if not os.path.exists(args.device):
        sys.exit(f"error: device not found: {args.device}")
    if args.persist and args.upgrade:
        sys.exit("error: --persist and --upgrade are mutually exclusive")
    if args.encrypt and not args.persist and not args.upgrade:
        sys.exit("error: --encrypt requires --persist or --upgrade")

    if args.upgrade:
        upgrade_iso(
            args.iso,
            args.device,
            encrypt=args.encrypt,
            verbose=args.verbose,
        )
    else:
        write_iso(
            args.iso,
            args.device,
            persist=args.persist,
            encrypt=args.encrypt,
            verbose=args.verbose,
        )
