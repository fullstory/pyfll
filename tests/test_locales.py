# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import pytest

from pyfll.exceptions import FllLocalesError
from pyfll.locales import FllLocales

AVAILABLE = {
    "firefox": {"version": "1.0", "recommends": ""},
    "firefox-l10n-de": {"version": "1.0", "recommends": ""},
    "firefox-l10n-fr": {"version": "1.0", "recommends": ""},
    "libreoffice-core": {"version": "1.0", "recommends": ""},
    "libreoffice-l10n-de": {"version": "1.0", "recommends": ""},
    "libreoffice-l10n-i18n": {"version": "1.0", "recommends": ""},
}
LOCALE_MAP = {
    "firefox": ["firefox-l10n"],
    "libreoffice-core": ["libreoffice-l10n"],
}


def test_detect_locale_packages_exact_match():
    fl = FllLocales(AVAILABLE, ["firefox", "libreoffice-core"], LOCALE_MAP)
    packages = fl.detect_locale_packages("de_DE")
    assert "firefox-l10n-de" in packages
    assert "libreoffice-l10n-de" in packages


def test_detect_locale_packages_i18n_fallback():
    fl = FllLocales(AVAILABLE, ["firefox", "libreoffice-core"], LOCALE_MAP)
    # no libreoffice-l10n-pt package exists; falls back to the -i18n package
    packages = fl.detect_locale_packages("pt_PT")
    assert "libreoffice-l10n-i18n" in packages
    assert "firefox-l10n-de" not in packages
    assert "firefox-l10n-fr" not in packages


def test_detect_locale_packages_english_no_i18n_fallback():
    fl = FllLocales(AVAILABLE, ["firefox", "libreoffice-core"], LOCALE_MAP)
    packages = fl.detect_locale_packages("en_US")
    assert packages == []


def test_compute_locale_loc_suf_list_invalid_locale_raises():
    fl = FllLocales({}, [], {})
    with pytest.raises(FllLocalesError):
        fl.compute_locale_loc_suf_list("not-a-locale")
