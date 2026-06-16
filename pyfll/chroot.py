import os
import shlex
import subprocess

from pyfll.exceptions import FllError


class ChrootExecMixin:
    """Mixin providing subprocess execution and systemd-nspawn chroot wrappers."""

    def exec_cmd(self, cmd: list) -> None:
        """Execute subprocess, always writing stdout+stderr to the log."""
        self.log.debug(shlex.join(cmd))

        log_it = self.log.info if self.opts.verbose else self.log.debug

        try:
            proc = subprocess.Popen(
                cmd,
                env=self.env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
            )
            for line in iter(proc.stdout.readline, ""):
                log_it(line.rstrip())
            proc.stdout.close()
            return_code = proc.wait()
            if return_code:
                raise subprocess.CalledProcessError(return_code, shlex.join(cmd))
        except KeyboardInterrupt:
            raise FllError
        except subprocess.CalledProcessError:
            self.log.exception(f"problem executing command: {shlex.join(cmd)}")
            raise FllError

    def chroot_exec(self, chroot: str, args: list) -> None:
        """Run command in a chroot via systemd-nspawn."""
        chroot_dir = os.path.join(self.temp, chroot)
        cmd = [
            "systemd-nspawn",
            "--quiet",
            f"--directory={chroot_dir}",
            "--as-pid2",
            "--resolv-conf=bind-host",
            "--timezone=off",
            "--restrict-address-families=AF_INET AF_INET6 AF_UNIX",
        ]
        for key, value in self.env.items():
            cmd.append(f"--setenv={key}={value}")
        cmd.append("--")
        cmd.extend(args)
        self.exec_cmd(cmd)

    def chroot_output(self, chroot: str, args: list) -> str:
        """Run command in a chroot and return captured stdout."""
        chroot_dir = os.path.join(self.temp, chroot)
        cmd = [
            "systemd-nspawn",
            "--quiet",
            f"--directory={chroot_dir}",
            "--as-pid2",
            "--resolv-conf=bind-host",
            "--timezone=off",
            "--restrict-address-families=AF_INET AF_INET6 AF_UNIX",
        ]
        for key, value in self.env.items():
            cmd.append(f"--setenv={key}={value}")
        cmd.append("--")
        cmd.extend(args)
        self.log.debug(shlex.join(cmd))
        result = subprocess.run(cmd, env=self.env, capture_output=True, text=True)
        if result.returncode != 0:
            self.log.critical(result.stderr.strip())
            raise FllError
        return result.stdout
