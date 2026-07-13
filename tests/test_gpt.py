# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import pyfll.gpt as gpt

SGDISK_PRINT = [
    "Disk /tmp/fll.iso: 2000000 sectors, 1.0 GiB",
    "Sector size (logical): 512 bytes",
    "   1            2048         1050623   512.0 MiB   0700  primary",
]

# "R:1: File data lba:  " is 21 chars; the code slices the rest on that offset.
OSIRROX_REPORT = [
    "R:1: File data lba:    0,   50,   10,   20480, 'efi.img'",
    "R:1: File data lba:    0,  100,  500, 1024000, 'root.squashfs'",
]


def test_run_gpthybrid_parses_report_and_computes_start_sectors(monkeypatch):
    calls = []

    def fake_run_process(cmd, verbose=False, log_fn=print):
        calls.append(cmd)
        if "--print" in cmd:
            return SGDISK_PRINT
        if "-pkt_output" in cmd:
            return OSIRROX_REPORT
        if "--first-aligned-in-largest" in cmd:
            return ["1"]
        return ["0"]

    monkeypatch.setattr(gpt, "run_process", fake_run_process)

    gpt.run_gpthybrid("/tmp/fll.iso", ["efi.img", "root.squashfs"])

    new_args = [a for c in calls for a in c if a.startswith("--new=")]
    # efi.img: startlba=50 * 4 = 200; root.squashfs: startlba=100 * 4 = 400
    starts = {int(a.split(":")[1]) for a in new_args if a.split(":")[1].isdigit()}
    assert {200, 400} <= starts


def test_run_gpthybrid_deletes_all_existing_partitions(monkeypatch):
    calls = []

    def fake_run_process(cmd, verbose=False, log_fn=print):
        calls.append(cmd)
        if "--print" in cmd:
            return [
                "   1            2048         1050623   512.0 MiB   0700  primary",
                "   2         1050624         2000000   463.5 MiB   0700  secondary",
            ]
        if "-pkt_output" in cmd:
            return []
        if "--first-aligned-in-largest" in cmd:
            return ["1"]
        return ["0"]

    monkeypatch.setattr(gpt, "run_process", fake_run_process)

    gpt.run_gpthybrid("/tmp/fll.iso", [])

    delete_call = next(c for c in calls if "--delete=1" in c or "--delete=2" in c)
    assert "--delete=1" in delete_call
    assert "--delete=2" in delete_call
