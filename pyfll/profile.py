from dataclasses import dataclass, field


def parse_dependency_groups(dep_str: str) -> list:
    """Parse a Depends/Recommends string into a list of OR groups.
    Each group is a list of package names (version constraints stripped)."""
    groups = []
    for group in dep_str.split(","):
        alts = []
        for alt in group.split("|"):
            alt = alt.strip()
            if alt:
                alts.append(alt.split()[0])
        if alts:
            groups.append(alts)
    return groups


@dataclass
class FllProfile:
    """
    Holds the package-related data collected from a single profile file and
    all modules it references.

    Attributes:
        debconf       - debconf pre-seed lines loaded pre-installation
        packages      - Debian package names
        flatpaks      - flatpak app IDs from flathub
        flatpaks_beta - flatpak app IDs from flathub-beta
        desktops      - X11/wayland session .desktop file names
        groups        - groups to add live user into
        postinst      - paths to postinst scripts to run post-installation
        manifest      - package manifest data
    """

    debconf: set = field(default_factory=set)
    packages: set = field(default_factory=set)
    flatpaks: set = field(default_factory=set)
    flatpaks_beta: set = field(default_factory=set)
    desktops: set = field(default_factory=set)
    groups: set = field(default_factory=set)
    postinst: set = field(default_factory=set)
    manifest: dict = field(default_factory=dict)

    def merge(self, other):
        """Add all items from another FllProfile into this one."""
        self.debconf.update(other.debconf)
        self.packages.update(other.packages)
        self.flatpaks.update(other.flatpaks)
        self.flatpaks_beta.update(other.flatpaks_beta)
        self.desktops.update(other.desktops)
        self.groups.update(other.groups)
        self.postinst.update(other.postinst)
