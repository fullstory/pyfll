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
| `squashfs-tools` \| `erofs-utils` | Read-only filesystem |
| `gdisk` | GPT hybrid support |
| `btrfs-progs` | btrfs subvolume management for the persist partition |
| `mtools` | FAT image handling for EFI partition |
| `systemd-container` | Chroot execution via `systemd-nspawn` |
| `cryptsetup` | LUKS2 encryption of the persist partition (optional) |

```bash
sudo apt install python3-debian python3-configobj gdisk xorriso \
    cdebootstrap erofs-utils squashfs-tools mtools systemd-container \
    btrfs-progs
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

---

## Persistent storage

When the `-p` / `--persist` flag is passed to `pyfll`, a persistent btrfs
storage partition is created on the target device alongside the live ISO data.
This partition survives upgrades and provides two features:

- **Persistent system state** — changes made to the live system (packages
  installed, configuration edits) are written to an overlay COW layer and
  survive reboots.
- **Persistent home directory** — `/home` is stored on a dedicated btrfs
  subvolume and is never affected by upgrades or system resets.

### Partition layout

```
[ ISO data: ESP + erofs read-only rootfs    ]
[ fll-gap  (type 0700, 2× ISO size)         ]  ← headroom for future upgrades
[ fll-persist  (type 8300, btrfs)           ]  ← all remaining space
```

The gap partition is sized at twice the ISO to allow future ISOs to be written
in-place without overwriting the persist partition.

### btrfs subvolume layout

```
@root          COW overlay layer (reset on upgrade)
  <rootfs_uuid>/
    upper/       overlay upperdir
    work/        overlay workdir
@home            persistent /home (never reset)
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
partition is untouched, then resets `@root` so the next boot starts with a
clean COW layer. `@home` is never touched. `--write-iso` and `--upgrade` are
independent and may be combined or used separately.

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

## Utilities

### `bin/gpthybrid`

Converts an ISO produced by xorriso into a GPT hybrid image with proper partition entries for BIOS boot, EFI, and each squashfs/erofs payload. Run automatically by `pyfll` at the end of a build, but can also be used standalone:

```bash
bin/gpthybrid --iso output.iso --filesystems live/filesystem.squashfs efi.img
```

### `bin/fllisodd`

Writes a live ISO to a block device using `dd`, with optional btrfs persist
partition, in-place upgrade, and LUKS2 encryption support. Also callable via
`pyfll --write-iso` and `pyfll --upgrade`.

```bash
# Plain write
sudo bin/fllisodd --iso output.iso --device /dev/sdX

# Write with btrfs persist partition
sudo bin/fllisodd --iso output.iso --device /dev/sdX --persist

# Write with encrypted persist partition (prompts for passphrase)
sudo bin/fllisodd --iso output.iso --device /dev/sdX --persist --encrypt

# Upgrade ISO in-place, preserving the persist partition
sudo bin/fllisodd --iso output.iso --device /dev/sdX --upgrade

# Upgrade an encrypted device (prompts for passphrase)
sudo bin/fllisodd --iso output.iso --device /dev/sdX --upgrade --encrypt
```

---

## Repository layout

```
pyfll/
├── fll                 # Execution wrapper (handles sudo/uid-gid)
├── bin/
│   ├── pyfll           # Main build entry point (called by fll)
│   ├── gpthybrid       # GPT hybrid ISO tool
│   └── fllisodd        # ISO-to-USB writer
├── fll.conf            # Example configuration
├── pyfll/              # Python package
│   ├── builder.py      # FLLBuilder orchestration
│   ├── bootloader.py   # Bootloader staging (BootloaderMixin)
│   ├── apt.py          # Package installation (AptMixin)
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
