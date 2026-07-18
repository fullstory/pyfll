# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

import os

import pytest

from pyfll import grublocale

# A trimmed zone.tab: CH single-zone, DE/US multi-zone (need the override pick).
SAMPLE_ZONE_TAB = (
    "# comment line\n"
    "CH\t+4723+00832\tEurope/Zurich\n"
    "DE\t+5230+01322\tEurope/Berlin\tmost of Germany\n"
    "DE\t+4742+00841\tEurope/Busingen\tBusingen\n"
    "GB\t+513030-0000731\tEurope/London\n"
    "US\t+404251-0740023\tAmerica/New_York\teastern\n"
    "US\t+415100-0873900\tAmerica/Chicago\tcentral\n"
)

# Header + a few representative rows from fll-live-initscripts' locales.tsv.
# de_CH has an xkb_variant (fr) in column 3 -- the keyboard must still come from
# column 2 (xkb_layout, first token 'ch'), which is where the old locales2grub
# regressed by reading column 3.
SAMPLE_TSV = (
    "locale\tis_default\txkb_layout\txkb_variant\tfallback_locales\n"
    "00_00.utf8\t1\tus\t\ten_US.utf8\n"
    "C\t1\tus\t\ten_US.utf8\n"
    "de_CH.utf8\t0\tch,us\tfr\tde_DE.utf8 en_US.utf8\n"
    "de_DE.utf8\t1\tde,us\t\ten_US.utf8\n"
    "en_GB.utf8\t0\tgb,us\t\ten_US.utf8\n"
    "en_US.utf8\t1\tus\t\ten_US.utf8\n"
    "\n"
)


def test_parse_locales_tsv_skips_sentinels_and_reads_layout_column():
    rows = grublocale.parse_locales_tsv(SAMPLE_TSV)
    assert rows == [
        ("de", "CH", "ch"),
        ("de", "DE", "de"),
        ("en", "GB", "gb"),
        ("en", "US", "us"),
    ]


def test_locale_file_sets_lang_keyboard_and_guarded_timezone():
    text = grublocale.locale_file("de", "CH", "ch", "Europe/Zurich")
    assert "lang=de\n" in text
    assert 'bootlang="lang=de_CH"' in text
    assert 'def_bootlang="de_CH"' in text
    assert 'def_keyboard="ch"' in text
    # def_timezone is guarded so a preseeded tz is left untouched
    assert 'if [ -z "${timezone}" ]; then' in text
    assert 'def_timezone="Europe/Zurich"' in text


def test_locale_file_omits_timezone_when_unresolved():
    text = grublocale.locale_file("en", "US", "us")
    assert "def_timezone" not in text


def test_parse_zone_tab_groups_by_country():
    cc_zones = grublocale.parse_zone_tab(SAMPLE_ZONE_TAB)
    assert cc_zones["CH"] == ["Europe/Zurich"]
    assert cc_zones["DE"] == ["Europe/Berlin", "Europe/Busingen"]
    assert "# comment line" not in cc_zones


def test_default_timezone_single_multi_and_unknown():
    cc_zones = grublocale.parse_zone_tab(SAMPLE_ZONE_TAB)
    # single-zone country resolves automatically
    assert grublocale.default_timezone("CH", cc_zones) == "Europe/Zurich"
    # multi-zone country uses the editorial override
    assert grublocale.default_timezone("US", cc_zones) == "America/New_York"
    assert grublocale.default_timezone("DE", cc_zones) == "Europe/Berlin"
    # unknown country -> "" so the caller omits def_timezone
    assert grublocale.default_timezone("ZZ", cc_zones) == ""


def test_multi_zone_overrides_are_valid_current_zones():
    """Guard against typos and tzdata renames (e.g. Kiev -> Kyiv): every
    override must be a real zone.tab entry for its country."""
    zone_tab = "/usr/share/zoneinfo/zone.tab"
    if not os.path.isfile(zone_tab):
        pytest.skip("system zone.tab not available")
    cc_zones = grublocale.parse_zone_tab(open(zone_tab).read())
    for cc, tz in grublocale._MULTI_ZONE_DEFAULT.items():
        assert tz in cc_zones.get(cc, []), f"{cc} default {tz} not in zone.tab"


def test_keyboards_file_us_first_then_sorted_unique():
    text = grublocale.keyboards_file(["us", "de", "ch", "us", "gb", ""])
    assert text.startswith("for kk in us ch de gb; do")
    # 'us' appears once as the leading token, empty layout dropped
    kk = text.splitlines()[0][len("for kk in "):].split(";")[0].split()
    assert kk == ["us", "ch", "de", "gb"]


def test_write_grub_locale_data_generates_from_chroot(tmp_path):
    chroot = tmp_path / "chroot"
    tsv_dir = chroot / "usr/share/fll-live-initscripts"
    tsv_dir.mkdir(parents=True)
    (tsv_dir / "locales.tsv").write_text(SAMPLE_TSV)
    zi = chroot / "usr/share/zoneinfo"
    zi.mkdir(parents=True)
    (zi / "zone.tab").write_text(SAMPLE_ZONE_TAB)

    grub_dir = tmp_path / "grub"
    grub_dir.mkdir()

    grublocale.write_grub_locale_data(str(chroot), str(grub_dir))

    assert os.path.isfile(grub_dir / "locales/keyboards")
    assert not os.path.exists(grub_dir / "locales/C_")  # sentinel skipped
    # single-zone country resolved from zone.tab; multi-zone via override
    assert 'def_timezone="Europe/Zurich"' in (grub_dir / "locales/de_CH").read_text()
    assert 'def_timezone="America/New_York"' in (grub_dir / "locales/en_US").read_text()
    # tz *menu* stays a static asset, not generated here
    assert not os.path.exists(grub_dir / "tz")


def test_write_grub_locale_data_missing_tsv_is_noop_with_warning(tmp_path):
    chroot = tmp_path / "chroot"
    chroot.mkdir()
    grub_dir = tmp_path / "grub"
    grub_dir.mkdir()

    # no locales.tsv -> no locale files, no crash (log is optional)
    grublocale.write_grub_locale_data(str(chroot), str(grub_dir))

    assert not os.path.exists(grub_dir / "locales")
