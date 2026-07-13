# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import pytest

from pyfll.exceptions import FllError
from pyfll.isodd import storage_partition_dev


def test_storage_partition_dev_raises_fllerror_not_sysexit(monkeypatch):
    """A library function must raise FllError, not sys.exit, so callers like
    builder.gen_live_media can catch and handle it (P2.A1)."""
    import pyfll.isodd as isodd

    monkeypatch.setattr(isodd, "run_process", lambda *a, **k: ["no partitions here"])

    with pytest.raises(FllError, match="could not determine storage partition"):
        storage_partition_dev("/dev/null")
