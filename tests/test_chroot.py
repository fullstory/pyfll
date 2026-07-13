# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import logging
import threading
import time

import pytest

from pyfll.chroot import ChrootExecMixin
from pyfll.exceptions import FllError


def _make_chroot_exec():
    ce = ChrootExecMixin.__new__(ChrootExecMixin)
    ce.log = logging.getLogger("test_chroot")
    ce.env = {}
    ce._abort = threading.Event()
    ce._procs = set()
    ce._procs_lock = threading.Lock()
    ce._nspawn_cmd = lambda chroot, args, capability=None: args
    return ce


def test_chroot_output_deregisters_proc_on_success():
    """self._procs must be empty again once the subprocess exits normally
    (see test_chroot_output_is_registered_before_abort_terminates_it for
    proof that it's registered while running)."""
    ce = _make_chroot_exec()

    output = ce.chroot_output("chroot", ["echo", "hello"])

    assert output.strip() == "hello"
    assert ce._procs == set()  # deregistered after completion


def test_chroot_output_deregisters_on_failure():
    ce = _make_chroot_exec()
    with pytest.raises(FllError):
        ce.chroot_output("chroot", ["false"], quiet=True)
    assert ce._procs == set()


def test_chroot_output_refuses_to_start_when_abort_already_set():
    ce = _make_chroot_exec()
    ce._abort.set()
    with pytest.raises(FllError):
        ce.chroot_output("chroot", ["echo", "should not run"])
    assert ce._procs == set()


def test_chroot_output_is_registered_before_abort_terminates_it():
    """Simulates the real failure mode this fixes: _abort_builds only
    iterates self._procs, so a subprocess that never registers can never be
    terminated by a sibling chroot's abort."""
    ce = _make_chroot_exec()

    def fake_abort_builds():
        ce._abort.set()
        for proc in list(ce._procs):
            proc.terminate()

    # a slow command; the abort fires while it's still registered and running
    result_holder = {}

    def run_and_abort():
        try:
            result_holder["output"] = ce.chroot_output(
                "chroot", ["sleep", "5"], quiet=True
            )
        except FllError:
            result_holder["aborted"] = True

    t = threading.Thread(target=run_and_abort)
    t.start()
    # give chroot_output a moment to register its proc, then abort it
    for _ in range(50):
        if ce._procs:
            break
        time.sleep(0.05)
    assert ce._procs, "proc never registered in self._procs"
    fake_abort_builds()
    t.join(timeout=5)

    assert not t.is_alive()
    assert result_holder.get("aborted")
    assert ce._procs == set()
