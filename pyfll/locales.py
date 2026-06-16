from pyfll.exceptions import FllLocalesError


class FllLocales(object):
    """
    A class which provides the ability to determine lists of locale specific
    Debian packages using it's detect_locale_packages method.

    Arguments:
    available - dict of available packages {name: {version, recommends}}
    packages  - a list or dict of package names which are installed, or are
                going to be installed. Locale specific packages are selected
                for packages in this data structure.
    map       - a dict which maps package names with a list of package prefixes
                from which the locale string pattern matching can be used
                to match locale support packages. The prefered input for map is:
                ConfigObj('data/fll-locales-pkg-map').
    """

    def __init__(self, available: dict, packages: list, locale_map: dict) -> None:
        self.loc_pkgs_set = set()
        for name in available:
            if name not in packages:
                continue
            for loc_pkg in list(locale_map.keys()):
                if name == loc_pkg:
                    loc_pkg_prefix_list = locale_map.get(loc_pkg)
                    if not loc_pkg_prefix_list:
                        break
                    for loc_pkg_prefix in loc_pkg_prefix_list:
                        self.loc_pkgs_set.add(loc_pkg_prefix)
                    break

        self.loc_pkgs_list_dict = dict()
        for loc_pkg in self.loc_pkgs_set:
            self.loc_pkgs_list_dict[loc_pkg] = list()
        for name in available:
            for loc_pkg in self.loc_pkgs_set:
                if name == loc_pkg or name.startswith(loc_pkg + "-"):
                    self.loc_pkgs_list_dict[loc_pkg].append(name)

    def compute_locale_loc_suf_list(self, locale: str) -> list:
        """
        Compute a list of locale package name suffixes. The sequence of
        suffixes are in preferential order, the lowest index being most
        preferential.

        This is a very private method, used by detect_locale_packages.

        Arguments:
        locale - a locale string (eg. en_AU, pt_PT etc.)
        """
        loc_suf_list = list()
        try:
            ll, cc = locale.lower().split("_")
        except ValueError as e:
            raise FllLocalesError(e)
        loc_suf_list.append(f"{ll}-{cc}")
        loc_suf_list.append(f"{ll}{cc}")
        loc_suf_list.append(ll)

        if ll != "en":
            loc_suf_list.append("i18n")

        return loc_suf_list

    def detect_locale_packages(self, locale: str) -> list:
        """
        Process the data structures created at FllLocales instantiation and
        return a list of package names which are the likely best candidates
        for the locale string given as argument.

        Arguments:
        locale - a locale string (eg. en_AU, pt_PT etc.)
        """
        suffixes = self.compute_locale_loc_suf_list(locale)
        ll = locale.lower().split("_")[0]

        loc_pkg_dict = dict()
        for pkg in self.loc_pkgs_set:
            loc_pkgs_list = self.loc_pkgs_list_dict.get(pkg)
            if not loc_pkgs_list:
                continue
            if pkg not in loc_pkg_dict:
                loc_pkg_dict[pkg] = dict()
            for loc_pkg in loc_pkgs_list:
                for idx, suf in enumerate(suffixes):
                    if loc_pkg == "-".join([pkg, suf]):
                        loc_pkg_dict[pkg][idx] = loc_pkg

        packages = list()
        for pkg in self.loc_pkgs_set:
            loc_pkgs_list = self.loc_pkgs_list_dict.get(pkg)
            if not loc_pkgs_list:
                continue
            pkg_candidates = loc_pkg_dict.get(pkg)
            if pkg_candidates:
                best = min(pkg_candidates)
                packages.append(pkg_candidates[best])
            elif ll != "en" and pkg in loc_pkgs_list:
                packages.append(pkg)

        return packages
