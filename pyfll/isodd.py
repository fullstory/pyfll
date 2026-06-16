import argparse
import os
import re
import sys
import tempfile

from pyfll.util import run_process

SGDISK = "/usr/sbin/sgdisk"
SGDISK_ALIGN = 4


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
            line = line.rstrip() + f" persist_uuid={uuid}\n"
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


def write_iso(
    iso: str,
    device: str,
    persist: bool = False,
    persist_uuid: str | None = None,
    verbose: bool = False,
    log_fn=print,
) -> None:
    """Write *iso* to *device* with dd and optionally create a persistent
    ext4 storage partition."""
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
        log_fn(f"Appending storage partition to {device}...")
        run_process(
            [
                SGDISK,
                f"--set-alignment={SGDISK_ALIGN}",
                "--align-end",
                "--new=0:0:0",
                "--typecode=0:8300",
                "--change-name=0:storage",
                device,
            ],
            verbose=verbose,
            log_fn=log_fn,
        )
        run_process(["partprobe", device], verbose=verbose, log_fn=log_fn)
        run_process(["udevadm", "settle"], verbose=verbose, log_fn=log_fn)
        part_dev = storage_partition_dev(device, verbose=verbose, log_fn=log_fn)

        if bootloader == "grub":
            log_fn(f"Formatting {part_dev} as ext4 (UUID: {persist_uuid})...")
            run_process(
                ["mkfs.ext4", "-U", persist_uuid, part_dev],
                verbose=verbose,
                log_fn=log_fn,
            )
        else:
            log_fn(f"Formatting {part_dev} as ext4...")
            run_process(
                ["mkfs.ext4", part_dev], verbose=verbose, log_fn=log_fn
            )

            blkid_out = run_process(
                ["blkid", "-s", "UUID", "-o", "value", part_dev],
                verbose=verbose,
                log_fn=log_fn,
            )
            persist_uuid = blkid_out[0].strip() if blkid_out else None
            if not persist_uuid:
                sys.exit(f"error: could not read UUID from {part_dev} after mkfs.ext4")
            log_fn(f"persist_uuid: {persist_uuid}")

            esp_dev = find_esp_partition(device, verbose=verbose, log_fn=log_fn)
            if esp_dev is None:
                sys.exit(
                    f"error: EFI System Partition (EF00) not found on {device}\n"
                    "       Was the ISO built with an ESP-based bootloader?"
                )
            log_fn(f"Injecting persist_uuid into ESP ({esp_dev})...")
            inject_persist_uuid_into_esp(
                esp_dev, persist_uuid, verbose=verbose, log_fn=log_fn
            )

    run_process(
        [SGDISK, f"--set-alignment={SGDISK_ALIGN}", "--verify", device],
        verbose=verbose,
        log_fn=log_fn,
    )

    log_fn("Done.")


def main() -> None:
    __description__ = """
Write a fll live media ISO image to a block device with dd, and
optionally create a persistent ext4 storage partition using the
persist_uuid embedded in the ISO's boot configuration by pyfll.
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
        help="Create a persistent ext4 storage partition.",
    )
    cli.add_argument(
        "-u",
        "--persist-uuid",
        default=None,
        metavar="<uuid>",
        help="UUID for the persistent storage partition. If not given, "
        + "extracted from boot/grub/kernels.cfg inside the ISO.",
    )
    cli.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Show commands and extra output.",
    )
    args = cli.parse_args()

    if not os.path.isfile(args.iso):
        sys.exit(f"error: ISO not found: {args.iso}")
    if not os.path.exists(args.device):
        sys.exit(f"error: device not found: {args.device}")

    write_iso(
        args.iso,
        args.device,
        persist=args.persist,
        persist_uuid=args.persist_uuid,
        verbose=args.verbose,
    )
