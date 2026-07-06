# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import os
import shlex
import subprocess

from pyfll.exceptions import FllError


class ChrootExecMixin:
    """Mixin providing subprocess execution and systemd-nspawn chroot wrappers."""

    def exec_cmd(self, cmd: list, quiet: bool = False) -> None:
        """Execute subprocess, always writing stdout+stderr to the log.

        With *quiet*, a failure is logged at debug level (not as an ERROR with
        traceback); the caller takes over reporting - e.g. apt install, where a
        dedicated analysis follows."""
        if self._abort.is_set():
            raise FllError

        self.log.debug(shlex.join(cmd))

        log_it = self.log.info if self.opts.verbose else self.log.debug

        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                env=self.env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            with self._procs_lock:
                self._procs.add(proc)
            # Lost the race with an abort fired between the check and the add.
            if self._abort.is_set():
                proc.terminate()
            for line in iter(proc.stdout.readline, ""):
                log_it(line.rstrip())
            proc.stdout.close()
            return_code = proc.wait()
            if return_code:
                raise subprocess.CalledProcessError(return_code, shlex.join(cmd))
        except KeyboardInterrupt:
            raise FllError
        except subprocess.CalledProcessError:
            # A terminated child (sibling chroot failed) is expected noise.
            if quiet or self._abort.is_set():
                self.log.debug(f"command failed: {shlex.join(cmd)}")
            else:
                self.log.exception(f"problem executing command: {shlex.join(cmd)}")
            raise FllError
        finally:
            if proc is not None:
                with self._procs_lock:
                    self._procs.discard(proc)

    def _nspawn_cmd(self, chroot: str, args: list, capability: str = None) -> list:
        """Build the systemd-nspawn command line to run *args* in a chroot."""
        chroot_dir = os.path.join(self.temp, chroot)
        cmd = [
            "systemd-nspawn",
            "--quiet",
            f"--directory={chroot_dir}",
            "--as-pid2",
            "--resolv-conf=bind-host",
            "--timezone=off",
            "--restrict-address-families=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
        ]
        if capability:
            cmd.append(f"--capability={capability}")
        for key, value in self.env.items():
            cmd.append(f"--setenv={key}={value}")
        cmd.append("--")
        cmd.extend(args)
        return cmd

    def chroot_exec(
        self, chroot: str, args: list, capability: str = None, quiet: bool = False
    ) -> None:
        """Run command in a chroot via systemd-nspawn."""
        self.exec_cmd(
            self._nspawn_cmd(chroot, args, capability=capability), quiet=quiet
        )

    def chroot_output(self, chroot: str, args: list) -> str:
        """Run command in a chroot and return captured stdout."""
        cmd = self._nspawn_cmd(chroot, args)
        self.log.debug(shlex.join(cmd))
        result = subprocess.run(cmd, env=self.env, capture_output=True, text=True)
        if result.returncode != 0:
            self.log.critical(result.stderr.strip())
            raise FllError
        return result.stdout
