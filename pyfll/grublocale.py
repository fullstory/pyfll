# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

"""Generate the grub language menu data (locales/ll_CC and locales/keyboards)
that the live grub.cfg sources, from fll-live-initscripts' locales.tsv.
Supersedes the old data/locales2grub perl tool. The timezone menu (data/tz/*)
is a separate hand-maintained asset, but each locale's default timezone is
resolved from tzdata's zone.tab (country code -> zone), since locales.tsv no
longer carries per-locale timezone data."""

import os

# Column indices in locales.tsv, mirroring the schema documented in
# fll-live-initscripts' fll_locales. Update here if the columns are reordered.
_LOCALE = 0
_IS_DEFAULT = 1
_XKB_LAYOUT = 2
_XKB_VARIANT = 3
_FALLBACK = 4

# Representative timezone for countries that span several zones (zone.tab lists
# them with no primary). Single-zone countries resolve automatically, so only
# multi-zone ones need an editorial pick. Keyed by ISO-3166 country code.
_MULTI_ZONE_DEFAULT = {
    "AR": "America/Argentina/Buenos_Aires",
    "AU": "Australia/Sydney",
    "BR": "America/Sao_Paulo",
    "CA": "America/Toronto",
    "CL": "America/Santiago",
    "CN": "Asia/Shanghai",
    "CY": "Asia/Nicosia",
    "DE": "Europe/Berlin",
    "EC": "America/Guayaquil",
    "ES": "Europe/Madrid",
    "MX": "America/Mexico_City",
    "NZ": "Pacific/Auckland",
    "PT": "Europe/Lisbon",
    "RU": "Europe/Moscow",
    "UA": "Europe/Kyiv",
    "US": "America/New_York",
}


def parse_locales_tsv(text: str) -> list:
    """Parse locales.tsv into a list of (ll, cc, layout) tuples, one per usable
    row. layout is the primary XKB layout (first token of xkb_layout), matching
    what fll_locales writes as XKBLAYOUT. Skips the header, the 00_00 sentinel
    and country-less rows (C)."""
    rows = []
    for line in text.splitlines()[1:]:
        if not line.strip():
            continue
        fields = line.split("\t")
        locale = fields[_LOCALE]
        if locale.endswith(".utf8"):
            locale = locale[: -len(".utf8")]
        if "_" not in locale:
            continue  # C, POSIX, ...
        ll, cc = locale.split("_", 1)
        if ll == "00":
            continue
        layout = ""
        if len(fields) > _XKB_LAYOUT:
            layout = fields[_XKB_LAYOUT].split(",")[0].strip()
        rows.append((ll, cc, layout))
    return rows


def parse_zone_tab(text: str) -> dict:
    """Map ISO-3166 country code -> list of timezones, from tzdata's zone.tab."""
    cc_zones = {}
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) < 3:
            continue
        cc_zones.setdefault(fields[0], []).append(fields[2].strip())
    return cc_zones


def default_timezone(cc: str, cc_zones: dict) -> str:
    """Representative timezone for a locale's country code: the sole zone of a
    single-zone country, or the editorial pick for a multi-zone one. Returns ""
    for an unknown country, or a multi-zone one with no pick, so the caller
    omits def_timezone rather than guessing wrong."""
    zones = cc_zones.get(cc)
    if not zones:
        return ""
    if len(zones) == 1:
        return zones[0]
    return _MULTI_ZONE_DEFAULT.get(cc, "")


def locale_file(ll: str, cc: str, layout: str, timezone: str = "") -> str:
    """grub locale file sourced when lang=ll_CC is selected: sets the language
    and, unless the user already picked one, the default keymap and timezone.
    Both defaults are guarded so a preseeded keyboard/tz is left untouched."""
    text = (
        f"lang={ll}\n"
        f'bootlang="lang={ll}_{cc}"\n'
        f'def_bootlang="{ll}_{cc}"\n'
        'if [ -z "${keyboard}" ]; then\n'
        f'  def_keyboard="{layout}"\n'
        "fi\n"
    )
    if timezone:
        text += (
            'if [ -z "${timezone}" ]; then\n'
            f'  def_timezone="{timezone}"\n'
            "fi\n"
        )
    return text


def keyboards_file(layouts: list) -> str:
    """grub keyboards submenu body: 'us' first, then the sorted unique rest."""
    others = sorted({layout for layout in layouts if layout and layout != "us"})
    kk = " ".join(["us"] + others)
    return (
        f"for kk in {kk}; do\n"
        '  menuentry "keytable=${kk}" "${kk}" {\n'
        '    def_keyboard="${2}"\n'
        '    keyboard="keytable=${2}"\n'
        "    menu_reload\n"
        "  }\n"
        "done\n"
    )


def write_grub_locale_data(chroot_dir: str, grub_dir: str, log=None) -> None:
    """Generate locales/ll_CC and locales/keyboards under grub_dir from the
    chroot's locales.tsv."""
    tsv = os.path.join(chroot_dir, "usr/share/fll-live-initscripts/locales.tsv")
    if not os.path.isfile(tsv):
        if log:
            log.warning(f"{tsv} not found; grub language menu will use defaults only")
        return

    cc_zones = {}
    zone_tab = os.path.join(chroot_dir, "usr/share/zoneinfo/zone.tab")
    if os.path.isfile(zone_tab):
        with open(zone_tab) as f:
            cc_zones = parse_zone_tab(f.read())
    elif log:
        log.warning(f"{zone_tab} not found; grub locales will omit def_timezone")

    locales_dir = os.path.join(grub_dir, "locales")
    os.makedirs(locales_dir, exist_ok=True)
    with open(tsv) as f:
        rows = parse_locales_tsv(f.read())
    for ll, cc, layout in rows:
        tz = default_timezone(cc, cc_zones)
        with open(os.path.join(locales_dir, f"{ll}_{cc}"), "w") as f:
            f.write(locale_file(ll, cc, layout, tz))
    with open(os.path.join(locales_dir, "keyboards"), "w") as f:
        f.write(keyboards_file([layout for _, _, layout in rows]))
