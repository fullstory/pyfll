# pyfll

**FULLSTORY live Linux media mastering utility**

`pyfll` is a Python tool for building bootable Debian-based live ISO images. It bootstraps one or more chroot environments, installs packages according to a declarative configuration, and produces a hybrid ISO with a compressed read-only filesystem — ready to write to USB or burn to disc.

It is the primary build tool behind [aptosid](http://aptosid.com/).

---

## Requirements

| Package | Purpose |
|---|---|
| `python3` ≥ 3.11 | Runtime |
| `python3-debian` | Debian version string comparison |
| `python3-configobj` | Configuration parsing |
| `cdebootstrap` \| `debootstrap` \| `mmdebstrap` | Bootstrap utility |
| `xorriso` | ISO creation |
| `gdisk` | GPT hybrid support |
| `btrfs-progs` | btrfs subvolume management for the persist partition |
| `mtools` | FAT image handling for EFI partition |
| `systemd-container` | Chroot execution via `systemd-nspawn` |
| `cryptsetup` | LUKS2 encryption of the persist partition (optional) |

```bash
sudo apt install python3-debian python3-configobj gdisk xorriso \
    cdebootstrap mtools systemd-container btrfs-progs
```

---

## Quickstart

```bash
git clone https://github.com/fullstory/pyfll.git
cd pyfll
cp fll.conf fll.local.conf
editor fll.local.conf
./fll -c fll.local.conf -b /tmp/fll/
```

`fll` is the execution wrapper: it escalates to root via `sudo` or `su`, then calls `bin/pyfll` with the caller's uid/gid so output files are owned by the invoking user. For all options:

```bash
./fll --help
```

---

## Configuration

`fll.conf` uses a hierarchical INI format parsed by [ConfigObj](https://configobj.readthedocs.io/). The full schema with all defaults is defined in `share/fll.conf.spec` — you only need to specify values you want to override.

### Minimal chroot definition

```ini
[chroots]

[[ debian-sid-amd64-kde ]]

  [[[ packages ]]]
  distro   = debian
  codename = sid
  arch     = amd64
  linux    = amd64                # suffix appended to linux-image- and linux-headers-
  profile  = kde-lite             # one or more profiles from share/profiles/
  browser  = firefox              # x-www-browser alternative
  modules  = firmware, cli-fancy  # extra feature modules from share/modules/

  [[[ repos ]]]
  [[[[ debian ]]]]
  uri        = https://deb.debian.org/debian/
  suite      = sid
  components = main non-free-firmware
```

Multiple chroots can be defined in one config file. Each produces its own squashfs or erofs image on the ISO — useful for shipping multiple desktop flavours from a single build run.

### Key global options

```ini
[ options ]
bootloader          = grub          # grub | grub-efi | refind | systemd-boot
bootstrapper        = mmdebstrap    # cdebootstrap | debootstrap | mmdebstrap
initramfs_tool      = dracut        # dracut | initramfs-tools
readonly_filesystem = squashfs      # squashfs | erofs
squashfs_comp       = zstd          # gzip | lz4 | lzo | xz | zstd
apt_recommends      = no
```

### Adding a custom repository

Use `sources_uri` to fetch a deb822-style `.sources` file directly — no separate keyring package needed:

```ini
[[[[ myrepo ]]]]
sources_uri = https://example.com/debian/myrepo.sources
```

Or specify a repository inline with a named keyring:

```ini
[[[[ aptosid ]]]]
uri        = http://aptosid.com/debian/
suite      = sid
components = main fix.main
keyring    = aptosid-archive-keyring
```

Installing a named `keyring` package is the one unauthenticated step in the
build: apt has no key yet to verify the keyring package itself, so that
single `apt-get install` runs with `--allow-unauthenticated`. Every other
package (including the rest of that repository's packages) is installed
normally, verified against the keyring once it is in place.

---

## Persistent storage

When the `-p` / `--persist` flag is passed to `pyfll`, a persistent btrfs
storage partition is created on the target device alongside the live ISO data.
This partition survives upgrades and provides two features:

- **Persistent system state** — changes made to the live system (packages
  installed, configuration edits) are written to an overlay COW layer and
  survive reboots. Across an `--upgrade`, `/etc` edits are carried forward
  (ostree-style) while the rest of the COW layer is reset.
- **Persistent home directory** — `/home` is stored on a dedicated btrfs
  subvolume and is never affected by upgrades or system resets.

### Partition layout

```
[ ISO data: ESP + erofs read-only rootfs    ]
[ fll-gap  (type 0700, ½ × ISO size, min 1 GiB)  ]  ← headroom for future upgrades
[ fll-persist  (type 8300, btrfs)           ]  ← all remaining space
```

The gap partition is sized at half the current ISO (minimum 1 GiB), so that
a future ISO of up to 1.5× the original size can be written in-place without
overwriting the persist partition.

### btrfs subvolume layout

```
@root                   COW overlay layer (reset on upgrade, /etc preserved)
  <image_file>/           one directory per read-only chroot on the ISO
    upper/                overlay upperdir (etc/ carried across upgrades)
    work/                 overlay workdir
@home                   persistent /home (never reset)
```

### Writing with persist

```bash
sudo ./fll -c fll.local.conf -b /tmp/fll/ --persist --write-iso /dev/sdX
```

### Upgrading in-place

```bash
sudo ./fll -c fll.local.conf -b /tmp/fll/ --persist --upgrade /dev/sdX
```

`--upgrade` writes the new ISO with `dd conv=notrunc` so the persist
partition is untouched, then resets the COW layer — keeping each flavour's
`/etc` and discarding the rest — so the next boot starts clean apart from the
carried-forward `/etc`. `@home` is never touched. `--write-iso` and `--upgrade`
are independent and may be combined or used separately.

### Encrypted persist partition

To encrypt the persist partition at rest with LUKS2:

```bash
sudo ./fll -c fll.local.conf -b /tmp/fll/ \
    --persist --encrypt --write-iso /dev/sdX
```

You will be prompted for a passphrase at write time. At boot, `fll.initramfs`
prompts for the passphrase interactively via Plymouth (or the console if
Plymouth is not active).

For encrypted upgrades, pass `--encrypt` along with `--upgrade`:

```bash
sudo ./fll -c fll.local.conf -b /tmp/fll/ \
    --persist --encrypt --upgrade /dev/sdX
```

You will be prompted for the passphrase to open the existing LUKS container
on the build host before `@root` is reset.

---

## Profiles

Profiles live under `share/profiles/` and define the package set for a desktop environment or base system type. A profile is a ConfigObj file with the following keys:

```
desc = """
    Human-readable description shown in build log.
"""

modules = """
    essential
    hwsupport-essential
    kde-essential
    kde-basic
    xserver
"""

packages = """
    some-extra-package
"""

desktops = """
    plasma
"""
```

- **`modules`** — names of module files from `share/modules/` to compose into this profile (evaluated recursively)
- **`packages`** — additional packages on top of what modules provide
- **`desktops`** — desktop session names (used to generate per-session boot menu entries)
- **`groups`** — supplementary groups to add the live user to

The `profile` key in a chroot definition accepts a space-separated list. Profiles compose — their package sets, modules, desktops, and groups are merged. A profile may also ship a companion `<name>.postinst` shell script that is executed inside the chroot after all packages are installed.

---

## Modules

Modules live under `share/modules/` and are the primary unit of package composition. A profile is typically a thin list of module references; the modules do the actual package selection.

```
desc = """
    Fancy versions of common command line utilities.
"""

packages = """
    bat
    btop
    liquidprompt
    zoxide
"""
```

Supported keys:

| Key | Purpose |
|---|---|
| `desc` | Description shown in build log |
| `packages` | Debian package names to install |
| `packages_amd64` | Architecture-specific packages (also `packages_i386`, `packages_arm64`) |
| `debconf` | `debconf-set-selections` lines preseeded before installation |
| `groups` | Supplementary groups to add the live user to |
| `desktops` | Desktop session names |
| `flatpaks` | Flatpak app IDs to install from Flathub |
| `flatpaks_beta` | Flatpak app IDs to install from Flathub Beta |

A module may also ship a companion `<name>.postinst` script. Postinst scripts are run inside the chroot via `systemd-nspawn` after package installation with the argument `postinst`.

### Recommended packages

The special module `share/modules/recommends` lists packages whose apt Recommends are selectively honoured even when `apt_recommends = no`. Any package listed there will have its recommended dependencies pulled in if those dependencies are already in the wanted package set.

---

## Auditing and maintenance

Building an image takes a long time. `--audit` answers a narrower question much faster: **would apt still install everything the package lists ask for?** It bootstraps a chroot, then checks each package list against the real apt indexes without installing anything.

```bash
./fll --audit -c fll.conf -b /tmp/fll/
```

Like a build, this needs root (the `fll` wrapper handles that) and network access. It exits non-zero if any check fails, so it can be used as a gate. Progress is printed as it goes, and the full detail is written to a log file in the output directory, the same as for a build.

By default it checks every chroot in the config (or just those named with `--chroots`), exactly as each would be built. To check the profiles in `share/profiles/` one at a time instead:

```bash
./fll --audit --profiles kde-lite minimal -c fll.conf -b /tmp/fll/
./fll --audit --profiles all -c fll.conf -b /tmp/fll/
```

This casts a wider net, because a config usually builds only some of the profiles that exist. The chroot definition supplying the distro, architecture and repositories is the first one in the config, or the first given to `--chroots`.

### Why it is quick

One bootstrapped chroot is shared by every target that agrees on distro, codename, architecture and repositories. Checking twenty profiles therefore costs little more than checking one: the bootstrap is paid once, and each profile after it takes a few seconds.

Each target is checked in a throwaway overlay on top of that shared chroot. Nothing a check does can affect the next one, which is what allows a profile's `preinst` script to run for real.

Browsers are checked as targets of their own, one per browser named anywhere in the config. A browser is not tied to a profile — any profile can be built with any of them — so adding one browser to every profile would test the same browser repeatedly and never test the others.

### Reading the report

```
audit summary - 4/4 clean:
  ok   kde-lite: 1553 package(s) to install (260 selected), 1 duplicate declaration(s)
  ok   kodi: 1482 package(s) to install (612 selected), 3 cross-profile overlap(s)
  ok   browser:chromium: 174 package(s) to install (3 selected)
  ok   browser:firefox: 113 package(s) to install (3 selected)
```

- the first number is how many packages apt would really install, dependencies included
- **selected** is how many package names the lists actually asked for
- **duplicate declaration(s)** means a package is named in more than one file of the same package profile. It still installs, so this is only a tidiness note.
- **cross-profile overlap(s)** counts packages a chroot's several profiles each name for themselves, in files of their own. Every profile has to work when built on its own, so this is expected and no file is named. A package the profiles share through one and the same module is a single declaration and is not counted.

A failing target reports what went wrong and, where it can, which profile or module file asked for the offending package.

### What it finds

- packages removed or renamed in the archive
- typos in a package list
- dependencies apt cannot satisfy, and conflicts between packages
- whitelisted recommends that pull in something uninstallable
- entries in `share/modules/recommends` that no longer exist in any repository
- malformed `debconf` preseed lines
- a chroot or profile naming a profile or module file that does not exist
- a `preinst` or `postinst` script that does not parse

The last two are checked before anything is bootstrapped, so a broken tree is reported in seconds. Scripts are parsed with the interpreter named in their shebang, so a Python `postinst` is not judged by shell rules. A script whose interpreter we cannot check is reported as a warning rather than passed silently.

### What it cannot find

Anything that only shows up once packages are really unpacked and configured:

- two packages shipping the same file
- maintainer script or `debconf` failures at configure time
- `postinst` scripts, which run against a fully installed chroot
- initramfs generation, image creation and bootloader staging

It is a resolvability check, not a build. A clean audit does not promise a clean build.

### Checking a config for completeness

`fll.conf` is meant to showcase every build we are capable of. `--complete` reports how much of `share/profiles/` and `share/modules/` a config actually reaches:

```bash
./fll --audit --complete -c fll.conf -b /tmp/fll/
```

Reachability is walked outwards from the chroots a config defines. A chroot names profiles and modules, and a profile names modules — two steps, because a module cannot name another module. So a module counts as reached only if a chroot names it directly, or a profile that some chroot **actually builds** names it. A module named only by a profile that nothing builds is no more exercised than one named nowhere at all.

Three things are reported, each pointing at a different fix:

| Report | Meaning | What to do about it |
|---|---|---|
| `N profile(s) no chroot in <config> builds` | the profile file exists, but no chroot uses it | add a chroot that builds it, or accept it as unused |
| `N module(s) reachable only through a profile no chroot builds` | the gap is in the config, not the module | add a chroot building that profile, and the module comes along |
| `N module(s) no chroot or profile references at all` | nothing anywhere names it | showcase it, or delete it — a module not worth showcasing is probably not worth maintaining |

Each line names the files involved, so the output reads as a to-do list. For example:

```
2 profile(s) no chroot in fll.conf builds: cinnamon lxde
1 module(s) reachable only through a profile no chroot builds:
    gnome-desktop (via gnome)
```

A config that reaches everything prints nothing at all.

These are warnings, never failures, and they are off by default. A personal config that builds a single chroot leaves nearly every profile unbuilt, which is true but not worth reporting on every run — it is the shipped example config whose numbers should be trending to zero.

A reference to a profile or module file that does **not exist** is a different matter: that is always checked, always fatal, and does not need this option.

---

## Utilities

### `bin/gpthybrid`

Converts an ISO produced by xorriso into a GPT hybrid image with proper partition entries for BIOS boot, EFI, and each squashfs/erofs payload. Run automatically by `pyfll` at the end of a build, but can also be used standalone:

```bash
bin/gpthybrid --iso output.iso --filesystems live/filesystem.squashfs efi.img
```

---

## Repository layout

```
pyfll/
├── fll                 # Execution wrapper (handles sudo/uid-gid)
├── bin/
│   ├── pyfll           # Main build entry point (called by fll)
│   └── gpthybrid       # GPT hybrid ISO tool
├── fll.conf            # Example configuration
├── pyfll/              # Python package
│   ├── builder.py      # FLLBuilder orchestration
│   ├── bootloader.py   # Bootloader staging (BootloaderMixin)
│   ├── apt.py          # Package installation (AptMixin)
│   ├── audit.py        # Package list resolvability audit (AuditMixin)
│   ├── chroot.py       # Subprocess/nspawn execution (ChrootExecMixin)
│   ├── profile.py      # Profile data model and parsing (PackageProfileMixin)
│   ├── locales.py      # Locale package detection
│   ├── gpt.py          # GPT hybrid ISO manipulation
│   └── isodd.py        # ISO-to-device writer
└── share/
    ├── fll.conf.spec   # Configuration schema and defaults
    ├── fll.profile.spec
    ├── fll.module.spec
    ├── profiles/       # Desktop environment profiles
    └── modules/        # Composable feature modules
```

---

## License

GNU General Public License v2.0 — see [COPYING](COPYING) for details.
