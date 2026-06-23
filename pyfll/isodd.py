# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import os
import re
import shlex
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
        except (subprocess.CalledProcessError, OSError):
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
        except (subprocess.CalledProcessError, OSError):
            pass

        efi_img = os.path.join(tmpdir, "efi.img")
        try:
            run_process(
                ["osirrox", "-indev", iso, "-extract", "/efi.img", efi_img],
                verbose=verbose,
                log_fn=log_fn,
            )
        except (subprocess.CalledProcessError, OSError):
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
            except (subprocess.CalledProcessError, OSError):
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
            except (subprocess.CalledProcessError, OSError):
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
            except (subprocess.CalledProcessError, OSError):
                pass

    return None


def read_iso_persist_uuids(
    iso: str, verbose: bool = False, log_fn=print
) -> tuple[str | None, str | None]:
    """Return (persist_uuid, persist_luks_uuid) baked into the ISO's boot config.

    Reads grub's kernels.cfg from the ISO9660 layer when present, otherwise the
    grub-efi/systemd-boot/rEFInd config files from inside efi.img. Either value
    is None if absent (persist_luks_uuid only exists for encrypted builds).
    """

    def grep(text: str) -> tuple[str | None, str | None]:
        pu = re.search(r"persist_uuid=(\S+)", text)
        plu = re.search(r"persist_luks_uuid=(\S+)", text)
        return (pu.group(1) if pu else None, plu.group(1) if plu else None)

    persist_uuid = None
    persist_luks_uuid = None
    with tempfile.TemporaryDirectory() as tmp:
        # grub (BIOS/EFI hybrid): kernels.cfg lives on the ISO9660 layer
        kernels_cfg = os.path.join(tmp, "kernels.cfg")
        try:
            run_process(
                ["osirrox", "-indev", iso, "-extract",
                 "/boot/grub/kernels.cfg", kernels_cfg],
                verbose=verbose, log_fn=log_fn,
            )
        except (subprocess.CalledProcessError, OSError):
            pass
        if os.path.isfile(kernels_cfg):
            with open(kernels_cfg) as f:
                return grep(f.read())

        # ESP-based bootloaders: pull config files out of efi.img
        efi_img = os.path.join(tmp, "efi.img")
        try:
            run_process(
                ["osirrox", "-indev", iso, "-extract", "/efi.img", efi_img],
                verbose=verbose, log_fn=log_fn,
            )
        except (subprocess.CalledProcessError, OSError):
            return None, None
        if not os.path.isfile(efi_img):
            return None, None

        texts: list[str] = []

        # grub-efi: kernels.cfg inside the FAT
        kernels_cfg_fat = os.path.join(tmp, "kernels.cfg.fat")
        try:
            run_process(
                ["mcopy", "-i", efi_img, "::/boot/grub/kernels.cfg", kernels_cfg_fat],
                verbose=verbose, log_fn=log_fn,
            )
        except (subprocess.CalledProcessError, OSError):
            pass
        if os.path.isfile(kernels_cfg_fat):
            with open(kernels_cfg_fat) as f:
                texts.append(f.read())

        # systemd-boot: loader/entries/*.conf. Loop-mount the FAT image
        # read-only and read the entries directly, rather than relying on
        # mtools' directory-copy semantics. upgrade_iso always runs as root,
        # so a loop mount is available here.
        mnt = os.path.join(tmp, "efi_mnt")
        os.mkdir(mnt)
        try:
            run_process(
                ["mount", "-t", "vfat", "-o", "loop,ro", efi_img, mnt],
                verbose=verbose, log_fn=log_fn,
            )
        except (subprocess.CalledProcessError, OSError):
            mnt = None
        if mnt:
            try:
                entries_dir = os.path.join(mnt, "loader", "entries")
                if os.path.isdir(entries_dir):
                    for fname in sorted(os.listdir(entries_dir)):
                        try:
                            with open(os.path.join(entries_dir, fname)) as f:
                                texts.append(f.read())
                        except OSError:
                            pass
            finally:
                run_process(["umount", mnt], verbose=verbose, log_fn=log_fn)

        # rEFInd: EFI/BOOT/refind.conf
        refind_conf = os.path.join(tmp, "refind.conf")
        try:
            run_process(
                ["mcopy", "-i", efi_img, "::/EFI/BOOT/refind.conf", refind_conf],
                verbose=verbose, log_fn=log_fn,
            )
        except (subprocess.CalledProcessError, OSError):
            pass
        if os.path.isfile(refind_conf):
            with open(refind_conf) as f:
                texts.append(f.read())

        for text in texts:
            pu, plu = grep(text)
            if pu and not persist_uuid:
                persist_uuid = pu
            if plu and not persist_luks_uuid:
                persist_luks_uuid = plu

    return persist_uuid, persist_luks_uuid


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


def inject_cmdline_param_into_esp(
    esp_dev: str, param: str, value: str, verbose: bool = False, log_fn=print
) -> None:
    """Mount the EFI System Partition and write param=value into every boot
    entry that does not already carry it.

    Handles grub-efi, systemd-boot, and rEFInd configurations.
    The mount is always cleaned up, even on error.
    """
    with tempfile.TemporaryDirectory() as mnt:
        run_process(["mount", esp_dev, mnt], verbose=verbose, log_fn=log_fn)
        try:
            _patch_grub_efi_kernels_cfg(mnt, param, value, verbose=verbose, log_fn=log_fn)
            _patch_systemd_boot_entries(mnt, param, value, verbose=verbose, log_fn=log_fn)
            _patch_refind_conf(mnt, param, value, verbose=verbose, log_fn=log_fn)
        finally:
            run_process(["umount", mnt], verbose=verbose, log_fn=log_fn)


def _patch_grub_efi_kernels_cfg(
    mnt: str, param: str, value: str, verbose: bool = False, log_fn=print
) -> None:
    """Append param=value to every 'linux' line in
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
        if stripped.startswith("linux ") and f"{param}={value}" not in stripped:
            rstripped = re.sub(rf"\s+{param}=\S+", "", line.rstrip())
            line = rstripped + f" {param}={value}\n"
            changed = True
        new_lines.append(line)

    if changed:
        if verbose:
            log_fn(f"# patching {kernels_cfg}")
        with open(kernels_cfg, "w") as f:
            f.writelines(new_lines)


def _patch_systemd_boot_entries(
    mnt: str, param: str, value: str, verbose: bool = False, log_fn=print
) -> None:
    """Append param=value to every 'options' line in
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
            if line.startswith("options ") and f"{param}={value}" not in line:
                rstripped = re.sub(rf"\s+{param}=\S+", "", line.rstrip())
                line = rstripped + f" {param}={value}\n"
                changed = True
            new_lines.append(line)

        if changed:
            if verbose:
                log_fn(f"# patching {fpath}")
            with open(fpath, "w") as f:
                f.writelines(new_lines)


def _patch_refind_conf(
    mnt: str, param: str, value: str, verbose: bool = False, log_fn=print
) -> None:
    """Append param=value to every 'options' line inside a menuentry block in
    <mnt>/EFI/BOOT/refind.conf that does not already carry it."""
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
            and f"{param}={value}" not in stripped
        ):
            rstripped = re.sub(rf"\s+{param}=\S+", "", line.rstrip())
            if rstripped.endswith('"'):
                line = rstripped[:-1] + f' {param}={value}"\n'
            else:
                line = rstripped + f" {param}={value}\n"
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
    cmd = ["mkfs.btrfs", "-f", "-L", "fll-persist"]
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
    # subprocess.run directly (not run_process): luksFormat/luksOpen prompt
    # interactively for a passphrase and need the real tty.
    # -q skips the "Are you sure? (Type yes)" overwrite confirmation -- redundant
    # here since dd has already overwritten the whole device by this point.
    format_cmd = ["cryptsetup", "-q", "luksFormat", "--uuid", luks_uuid, part_dev]
    open_cmd = ["cryptsetup", "luksOpen", part_dev, mapper_name]
    if verbose:
        log_fn(f"# {shlex.join(format_cmd)}")
    subprocess.run(format_cmd, check=True)
    if verbose:
        log_fn(f"# {shlex.join(open_cmd)}")
    subprocess.run(open_cmd, check=True)


def luks_close(mapper_name: str, verbose: bool = False, log_fn=print) -> None:
    run_process(
        ["cryptsetup", "luksClose", mapper_name],
        verbose=verbose,
        log_fn=log_fn,
    )


def luks_open_interactive(
    part_dev: str, mapper_name: str, verbose: bool = False, log_fn=print
) -> None:
    # subprocess.run directly (not run_process): luksOpen prompts
    # interactively for a passphrase and needs the real tty.
    open_cmd = ["cryptsetup", "luksOpen", part_dev, mapper_name]
    if verbose:
        log_fn(f"# {shlex.join(open_cmd)}")
    subprocess.run(open_cmd, check=True)


def btrfs_set_uuid(
    btrfs_dev: str, new_uuid: str, verbose: bool = False, log_fn=print
) -> None:
    """Re-stamp a btrfs filesystem's visible UUID (fsid) to new_uuid. The
    filesystem must be unmounted. ``-M`` sets the METADATA_UUID incompat
    feature and changes only the superblock fsid, leaving the metadata blocks
    keyed by their original UUID -- fast and safe regardless of filesystem
    size (no full metadata rewrite)."""
    run_process(
        ["btrfstune", "-M", new_uuid, btrfs_dev],
        verbose=verbose,
        log_fn=log_fn,
    )


def luks_set_uuid(
    part_dev: str, new_uuid: str, verbose: bool = False, log_fn=print
) -> None:
    """Re-stamp a LUKS header's UUID. The container must not be active."""
    run_process(
        ["cryptsetup", "-q", "luksUUID", part_dev, "--uuid", new_uuid],
        verbose=verbose,
        log_fn=log_fn,
    )


def btrfs_check(btrfs_dev: str, verbose: bool = False, log_fn=print) -> None:
    """Run a read-only btrfs consistency check, raising on failure. Never
    repairs -- ``--repair`` can worsen corruption. The filesystem must be
    unmounted."""
    run_process(
        ["btrfs", "check", "--readonly", btrfs_dev],
        verbose=verbose,
        log_fn=log_fn,
    )


def reset_system_subvol(
    btrfs_dev: str, verbose: bool = False, log_fn=print
) -> None:
    try:
        run_process(
            ["udevadm", "settle", "--timeout=10"],
            verbose=verbose,
            log_fn=log_fn,
        )
    except (subprocess.CalledProcessError, OSError):
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
        gap_mib = max(1024, (iso_size_mib(iso) + 1) // 2)
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
                inject_cmdline_param_into_esp(
                    esp_dev, "persist_luks_uuid", persist_luks_uuid,
                    verbose=verbose, log_fn=log_fn,
                )

        if bootloader != "grub":
            esp_dev = find_esp_partition(device, verbose=verbose, log_fn=log_fn)
            if esp_dev is None:
                sys.exit("error: EFI System Partition not found on device")
            inject_cmdline_param_into_esp(
                esp_dev, "persist_uuid", persist_uuid,
                verbose=verbose, log_fn=log_fn,
            )

    run_process(
        [SGDISK, f"--set-alignment={SGDISK_ALIGN}", "--verify", device],
        verbose=verbose,
        log_fn=log_fn,
    )

    if persist:
        log_fn("Persist partition ready:")
        log_fn(f"  device:            {part_dev}")
        log_fn("  label:             fll-persist")
        log_fn("  filesystem:        btrfs (subvolumes @root, @home)")
        log_fn(f"  persist_uuid:      {persist_uuid}")
        if encrypt:
            log_fn("  encryption:        LUKS2")
            log_fn(f"  persist_luks_uuid: {persist_luks_uuid}")
    log_fn(f"Live media written to {device}. Done.")


def upgrade_iso(
    iso: str,
    device: str,
    persist_uuid: str | None = None,
    persist_luks_uuid: str | None = None,
    encrypt: bool = False,
    verbose: bool = False,
    log_fn=print,
) -> None:
    """Write *iso* to *device* with dd conv=notrunc, then conform the on-disk
    persist partition to the freshly written boot config and reset @root.

    Rather than patching the new ISO's boot config to point at the existing
    on-disk UUIDs (impossible for pure grub, whose persist_uuid lives in the
    read-only ISO9660 layer), this re-stamps the on-disk persist partition's
    UUIDs to match what the new ISO bakes in: the btrfs fsid via
    ``btrfstune -M`` and, when encrypted, the LUKS header UUID via
    ``cryptsetup luksUUID``. @home is preserved; @root is reset.
    """
    # The UUIDs the freshly written boot config will look for at boot time.
    iso_persist_uuid, iso_persist_luks_uuid = read_iso_persist_uuids(
        iso, verbose=verbose, log_fn=log_fn
    )
    if not persist_uuid:
        persist_uuid = iso_persist_uuid
    if not persist_luks_uuid:
        persist_luks_uuid = iso_persist_luks_uuid
    if not persist_uuid:
        sys.exit("error: could not determine target persist_uuid from ISO boot config")
    if encrypt and not persist_luks_uuid:
        sys.exit(
            "error: could not determine target persist_luks_uuid from ISO boot config"
        )
    log_fn(f"Target persist_uuid: {persist_uuid}")
    if encrypt:
        log_fn(f"Target persist_luks_uuid: {persist_luks_uuid}")

    # Save persist partition sectors before dd overwrites the partition table.
    persist_part_sectors = read_last_partition_sectors(
        device, verbose=verbose, log_fn=log_fn
    )
    has_persist = (
        persist_part_sectors is not None
        and persist_part_sectors[3] == "fll-persist"
    )

    if has_persist:
        log_fn(
            f"Persist partition: start={persist_part_sectors[0]}"
            f" end={persist_part_sectors[1]}"
            f" type={persist_part_sectors[2]}"
        )
    elif encrypt:
        sys.exit("error: could not read fll-persist partition sectors before upgrade")

    if has_persist:
        new_iso_mib = iso_size_mib(iso)
        persist_start_mib = persist_part_sectors[0] // MIB_SECTORS
        if new_iso_mib >= persist_start_mib:
            sys.exit(
                f"error: new ISO ({new_iso_mib} MiB) would overwrite fll-persist "
                f"(starts at {persist_start_mib} MiB) -- upgrade aborted"
            )

    if has_persist:
        # Pre-flight: verify the persist filesystem is sound before writing
        # anything. Run while the original partition table is still intact (the
        # fll-persist entry survives until dd), so a failure aborts with the
        # existing install untouched.
        check_abort = (
            "error: btrfs check failed on the persist filesystem; upgrade "
            "aborted (run 'btrfs check' manually to inspect)"
        )
        part_dev_pre = storage_partition_dev(device, verbose=verbose, log_fn=log_fn)
        if encrypt:
            result = subprocess.run(
                ["cryptsetup", "isLuks", part_dev_pre],
                capture_output=True,
            )
            if result.returncode != 0:
                sys.exit(f"error: {part_dev_pre} is not a LUKS container")
            log_fn("Unlocking persist partition to verify it (you will be "
                   "prompted again to apply the upgrade)...")
            luks_open_interactive(
                part_dev_pre, "fll-persist-check", verbose=verbose, log_fn=log_fn
            )
            try:
                log_fn("Checking persist filesystem before upgrade...")
                btrfs_check(
                    "/dev/mapper/fll-persist-check", verbose=verbose, log_fn=log_fn
                )
            except subprocess.CalledProcessError:
                luks_close("fll-persist-check", verbose=verbose, log_fn=log_fn)
                sys.exit(check_abort)
            luks_close("fll-persist-check", verbose=verbose, log_fn=log_fn)
        else:
            try:
                log_fn("Checking persist filesystem before upgrade...")
                btrfs_check(part_dev_pre, verbose=verbose, log_fn=log_fn)
            except subprocess.CalledProcessError:
                sys.exit(check_abort)

    log_fn(f"Upgrading ISO on {device} (dd conv=notrunc)...")
    subprocess.run(
        ["dd", f"if={iso}", f"of={device}", "bs=1M", "conv=notrunc", "status=progress"],
        check=True,
    )

    log_fn("Relocating GPT alt header...")
    run_process([SGDISK, "--move-second-header", device], verbose=verbose, log_fn=log_fn)
    run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)

    if has_persist:
        gap_start_lines = run_process(
            [SGDISK, "--first-aligned-in-largest", device],
            verbose=verbose,
            log_fn=log_fn,
        )
        gap_start_sector = int(gap_start_lines[0].strip())
        gap_end_sector = persist_part_sectors[0] - 1
        log_fn(f"Recreating fll-gap partition ({gap_start_sector}:{gap_end_sector})...")
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
        run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)

        # Re-add the persist partition entry that dd erased from the partition
        # table. Required for both encrypted and plain persist partitions: the
        # new ISO's GPT (written by dd) does not carry fll-gap/fll-persist.
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

        if encrypt:
            result = subprocess.run(
                ["cryptsetup", "isLuks", part_dev],
                capture_output=True,
            )
            if result.returncode != 0:
                sys.exit(f"error: {part_dev} is not a LUKS container after restore")
            # Conform the LUKS header UUID to the new boot config, then unlock.
            log_fn(f"Re-stamping LUKS header UUID -> {persist_luks_uuid}...")
            luks_set_uuid(part_dev, persist_luks_uuid, verbose=verbose, log_fn=log_fn)
            run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)
            luks_open_interactive(
                part_dev, "fll-persist-upgrade", verbose=verbose, log_fn=log_fn
            )
            btrfs_dev = "/dev/mapper/fll-persist-upgrade"
        else:
            btrfs_dev = part_dev

        # Conform the btrfs fsid to the new boot config's persist_uuid so the
        # booted system finds the persist filesystem regardless of bootloader.
        # This is what makes pure grub upgrades work: its persist_uuid lives in
        # the read-only ISO9660 layer and cannot be patched after dd.
        log_fn(f"Re-stamping persist btrfs UUID -> {persist_uuid}...")
        btrfs_set_uuid(btrfs_dev, persist_uuid, verbose=verbose, log_fn=log_fn)
        run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)

        reset_system_subvol(btrfs_dev, verbose=verbose, log_fn=log_fn)

        if encrypt:
            luks_close("fll-persist-upgrade", verbose=verbose, log_fn=log_fn)

    run_process(
        [SGDISK, f"--set-alignment={SGDISK_ALIGN}", "--verify", device],
        verbose=verbose,
        log_fn=log_fn,
    )
    log_fn("Upgrade complete.")
