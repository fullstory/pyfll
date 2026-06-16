# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

class FllError(Exception):
    """A generic error handler that does nothing."""

    pass


class FllLocalesError(FllError):
    """An error class for use by FllLocales."""

    pass
