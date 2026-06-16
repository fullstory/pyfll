# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

# https://www.rodsbooks.com/gdisk/hybrid.html
import argparse
from operator import itemgetter

from pyfll.util import run_process

SGDISK = "/usr/sbin/sgdisk"
SGDISK_ALIGN = 4


def run_gpthybrid(
    iso: str,
    filesystems: list[str],
    verbose: bool = False,
    log_fn=print,
) -> None:
    """Rearrange the GPT partition table to expose compressed filesystems
    within the isofs wrapper as partition type block devices."""

    # dump the existing GPT partition table
    old_partitions = dict()
    for line in run_process([SGDISK, "--print", iso], verbose=verbose, log_fn=log_fn):
        if not line.startswith("   "):
            continue
        num, start, end, size, unit, code = line.split()[:6]
        name = " ".join(line.split()[6:])
        if verbose:
            log_fn(
                f"num={num} start={start} end={end} size={size}"
                f" unit={unit} code={code} name={name}"
            )
        old_partitions[num] = {
            "start": start,
            "end": end,
            "size": size,
            "unit": unit,
            "code": code,
            "name": name,
        }

    # delete all existing partitions
    sgdisk_delete = [SGDISK, iso]
    for num in reversed(old_partitions.keys()):
        sgdisk_delete.insert(1, f"--delete={num}")
    run_process(sgdisk_delete, verbose=verbose, log_fn=log_fn)

    # find sector start position and size for each filesystem via osirrox
    osirrox = ["osirrox", "-pkt_output", "on", "-indev", iso]
    for fs in filesystems:
        osirrox.extend(["-find", fs, "-exec", "report_sections", "--"])
    osirrox_report = run_process(osirrox, verbose=verbose, log_fn=log_fn)

    fs_data: dict = {}
    for line in osirrox_report:
        if not line.startswith("R:1: File data lba:  "):
            continue
        xt, startlba, blocks, sectsize, name = line[21:].split(",")
        xt = int(xt.strip())
        startlba = int(startlba.strip())
        blocks = int(blocks.strip())
        sectsize = int(sectsize.strip())
        name = name.strip().strip("'")
        if name in fs_data:
            # blocks and sectsize are additive across isofs extents
            fs_data[name] = {
                "xt": f"{fs_data[name]['xt']}+{xt}",
                "startlba": fs_data[name]["startlba"],
                "blocks": fs_data[name]["blocks"] + blocks,
                "sectsize": fs_data[name]["sectsize"] + sectsize,
                "name": name,
            }
        else:
            fs_data[name] = {
                "xt": xt,
                "startlba": startlba,
                "blocks": blocks,
                "sectsize": sectsize,
                "name": name,
            }
        if verbose:
            log_fn(
                f"xt={fs_data[name]['xt']}"
                f" startlba={fs_data[name]['startlba']}"
                f" blocks={fs_data[name]['blocks']}"
                f" sectsize={fs_data[name]['sectsize']}"
                f" name={name}"
            )

    # re-assemble GPT with filler "GapN" partitions between significant
    # filesystems, aligned to appropriate sector boundaries
    gap = 0
    num = 0
    for fs in sorted(fs_data.values(), key=itemgetter("startlba")):
        num += 1
        first = int(
            run_process(
                [
                    SGDISK,
                    f"--set-alignment={SGDISK_ALIGN}",
                    "--first-aligned-in-largest",
                    iso,
                ],
                verbose=verbose,
                log_fn=log_fn,
            )[0]
        )
        # calculate start sector: ISO 2048-byte LBAs * 4 = 512-byte sectors
        start = fs["startlba"] * 4
        if first < start:
            run_process(
                [
                    SGDISK,
                    "--align-end",
                    f"--set-alignment={SGDISK_ALIGN}",
                    f"--new={num}:{first}:{start - 1}",
                    f"--change-name={num}:Gap{gap}",
                    f"--typecode={num}:0700",
                    iso,
                ],
                verbose=verbose,
                log_fn=log_fn,
            )
            gap += 1
            num += 1
        if fs["name"] == "efi.img":
            fs_name = "EFI boot partition"
            fs_type = "ef00"
        elif fs["name"].endswith(".ef02"):
            fs_name = "BIOS boot partition"
            fs_type = "ef02"
        else:
            fs_name = fs["name"].split(".")[1]
            fs_type = "8300"
        run_process(
            [
                SGDISK,
                f"--set-alignment={SGDISK_ALIGN}",
                f"--new={num}:{start}:+{fs['sectsize'] // 1024}KiB",
                f"--change-name={num}:{fs_name}",
                f"--typecode={num}:{fs_type}",
                iso,
            ],
            verbose=verbose,
            log_fn=log_fn,
        )

    # fill remaining free space with a final gap partition
    first = run_process(
        [
            SGDISK,
            f"--set-alignment={SGDISK_ALIGN}",
            "--first-aligned-in-largest",
            iso,
        ],
        verbose=verbose,
        log_fn=log_fn,
    )[0]
    num += 1
    run_process(
        [
            SGDISK,
            "--align-end",
            f"--set-alignment={SGDISK_ALIGN}",
            f"--new={num}:{first}:",
            f"--change-name={num}:Gap{gap}",
            f"--typecode={num}:0700",
            iso,
        ],
        verbose=verbose,
        log_fn=log_fn,
    )

    run_process([SGDISK, "--move-second-header", iso], verbose=verbose, log_fn=log_fn)
    run_process([SGDISK, "--print", iso], verbose=verbose, log_fn=log_fn)
    run_process(
        [SGDISK, f"--set-alignment={SGDISK_ALIGN}", "--verify", iso],
        verbose=verbose,
        log_fn=log_fn,
    )


def main() -> None:
    cli = argparse.ArgumentParser(description="GPT hybrid iso manipulator.")
    cli.add_argument(
        "-i",
        "--iso",
        action="store",
        type=str,
        metavar="<iso>",
        required=True,
        help="Path to iso file.",
    )
    cli.add_argument(
        "-f",
        "--filesystems",
        nargs="+",
        metavar="<filesystem>",
        required=True,
        help="Paths to filesystems within iso file.",
    )
    cli.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Show process output and extra informational data.",
    )
    args = cli.parse_args()
    run_gpthybrid(args.iso, args.filesystems, verbose=args.verbose)
