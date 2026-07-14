# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import shlex
import subprocess
import uuid

from pyfll.exceptions import FllError


def run_process(
    cmd: list[str], verbose: bool = False, log_fn=print
) -> list[str]:
    if verbose:
        log_fn(f"# {shlex.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, encoding="utf-8", check=True)
        if verbose and result.stdout:
            log_fn(result.stdout.rstrip())
        return result.stdout.splitlines()
    except FileNotFoundError as exc:
        if verbose:
            log_fn(f"command not found: {cmd[0]}\n{exc}")
        raise
    except subprocess.CalledProcessError as exc:
        if verbose:
            log_fn(f"command failed: {shlex.join(cmd)}\n{exc}")
        raise


def deduplicate_list(original_list: list) -> list:
    """Return a sorted list with duplicates removed."""
    return sorted(set(original_list))


def multiline_to_list(lines: str) -> list:
    """Return stripped non-empty, non-comment strings from a multiline string."""
    return [
        s.strip()
        for s in lines.splitlines()
        if s.strip() and not s.lstrip().startswith("#")
    ]


def uuidgen() -> str:
    """Return a random UUID string."""
    return str(uuid.uuid4())


def host_timezone() -> str:
    """Return timezone of host system."""
    try:
        tz = subprocess.run(
            ["timedatectl", "show", "--property=Timezone", "--value"],
            capture_output=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise FllError(f"could not determine host timezone via timedatectl: {exc}")
    timezone = tz.stdout.decode().strip("\n")
    if not timezone:
        raise FllError("timedatectl returned an empty timezone")
    return timezone
