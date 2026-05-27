# pyfll

**FULLSTORY live Linux media mastering utility**

`pyfll` is a Python tool for building bootable Debian-based live ISO images. It bootstraps one or more chroot environments, installs packages according to a declarative configuration file, and produces a hybrid ISO with a compressed read-only filesystem — ready to write to USB or burn to disc.

It is the primary build tool behind [aptosid](http://aptosid.com/) and supports a wide range of desktop environments and architectures out of the box.

---

## Features

- Declarative, INI-style configuration via `fll.conf` (powered by [ConfigObj](https://configobj.readthedocs.io/))
- Supports multiple simultaneous chroot builds in a single run
- Choice of bootstrapper: `cdebootstrap`, `debootstrap`, or `mmdebstrap`
- Choice of read-only filesystem: `squashfs` (default) or `erofs`
- Choice of bootloader: GRUB (BIOS/GPT), GRUB EFI, rEFInd, or systemd-boot
- Choice of initramfs generator: `dracut` (default) or `initramfs-tools`
- Multi-architecture support: `amd64` and `i386`
- Modular profile and module system for desktop environments and extra feature sets
- Optional APT cache proxy support (`apt-cacher-ng` / `auto-apt-proxy`)
- Custom repository injection via deb822-style sources files with embedded GPG keys

---

## Requirements

### Required

| Package | Purpose |
|---|---|
| `python` ≥ 3.8 | Runtime |
| `python3-apt` | APT integration |
| `python3-configobj` | Configuration parsing |
| `cdebootstrap` \| `debootstrap` \| `mmdebstrap` | Bootstrap utility |
| `xorriso` | ISO creation |
| `squashfs-tools` \| `erofs-utils` | Read-only filesystem |
| `gdisk` | GPT hybrid support for GRUB |
| `mtools` | FAT image handling |
| `systemd-container` | Chroot execution via `systemd-nspawn` |

### Recommended

| Package | Purpose |
|---|---|
| `apt-cacher-ng` | Local APT cache to speed up repeated builds |
| `auto-apt-proxy` | Automatic cache proxy detection |

Install all required dependencies on Debian/Ubuntu:

```bash
sudo apt install python3-apt python3-configobj gdisk xorriso \
    cdebootstrap erofs-utils squashfs-tools git mtools systemd-container
```

---

## Quickstart

```bash
# 1. Clone the repository
git clone https://github.com/fullstory/pyfll.git
cd pyfll

# 2. Copy and edit the configuration
cp fll.conf fll.local.conf
editor fll.local.conf

# 3. Run the build (requires root)
sudo ./fll -c fll.local.conf -b /tmp/fll/
```

The resulting ISO will be written to the build directory (`/tmp/fll/` in the example above).

For a full list of options:

```bash
./fll --help
```

---

## Configuration

`fll.conf` (and your local override `fll.local.conf`) uses a hierarchical INI format defined by the [ConfigObj](https://configobj.readthedocs.io/en/stable/index.html) library. You must define at least one `[chroots]` entry. Most settings have sensible defaults defined in `share/fll.conf.spec`; you only need to specify values you want to override.

### Chroot definition

Each chroot entry produces one squashfs (or erofs) image on the ISO. The name becomes the image filename and must not contain spaces.

```ini
['chroots']

[[ 'debian-sid-amd64-kde' ]]

  [[[ 'packages' ]]]
  distro   = debian
  codename = sid
  arch     = amd64
  linux    = aptosid-amd64       # linux-image- / linux-headers- suffix
  profile  = kde-lite            # one or more profiles from share/profiles/
  browser  = firefox             # x-www-browser alternative(s)
  modules  = firmware, cli-fancy # extra feature modules from share/modules/
  locales  = en_AU, en_US, de_DE

  [[[ 'repos' ]]]
  [[[[ 'debian' ]]]]
  uri        = https://deb.debian.org/debian/
  suite      = sid
  components = main non-free-firmware

  [[[[ 'aptosid' ]]]]
  uri        = http://aptosid.com/debian/
  suite      = sid
  components = main fix.main
  keyring    = aptosid-archive-keyring
```

Multiple chroots can be stacked in a single `fll.conf`, each producing its own squashfs on the resulting ISO — useful for shipping multiple desktop flavours from a single build run.

### Global options (excerpt)

```ini
[ 'options' ]
bootloader          = grub          # grub | grub-efi | refind | systemd-boot
bootstrapper        = cdebootstrap  # cdebootstrap | debootstrap | mmdebstrap
initramfs_tool      = dracut        # dracut | initramfs-tools
readonly_filesystem = squashfs      # squashfs | erofs
squashfs_comp       = zstd          # gzip | lz4 | lzo | xz | zstd
apt_recommends      = no
```

See `share/fll.conf.spec` for the full schema and all defaults.

### Adding a custom repository

Use `sources_uri` to point to a deb822-style `.sources` file with an embedded GPG public key — no separate keyring package needed:

```ini
[[[[ 'myrepo' ]]]]
sources_uri = https://example.com/debian/myrepo.sources
```

---

## Profiles

Profiles live under `share/profiles/` and define the package set for a desktop environment or environment combination. Each profile is a named list of packages (and optional groups) that gets installed into the chroot on top of the bootstrapped base system.

The `profile` key in a chroot definition accepts a comma-separated list; profiles compose, so you can combine a desktop with a supplementary profile (e.g. `profile = kde-lite, xfce-lite` produces a chroot with both).

### Available profiles

| Profile | Description |
|---|---|
| `kde-lite` | KDE Plasma desktop, trimmed package selection |
| `kde` | KDE Plasma desktop, standard package selection |
| `kde-stripped` | KDE Plasma desktop, minimal package selection |
| `kde-full` | KDE Plasma desktop, full package selection |
| `gnome-lite` | GNOME desktop, trimmed package selection |
| `xfce-lite` | Xfce desktop |
| `lxqt-lite` | LXQt desktop |
| `lxqt-stripped` | LXQt desktop, minimal selection |
| `lxde-lite` | LXDE desktop |
| `cinnamon-lite` | Cinnamon desktop |
| `mate` | MATE desktop |
| `budgie` | Budgie desktop |
| `hyprland` | Hyprland Wayland compositor |
| `sway` | Sway Wayland compositor |
| `labwc` | labwc stacking Wayland compositor |
| `kodi` | Kodi media centre |
| `minimal` | Console-only base system, no X |
| `minimal-x` | Minimal base with X, no desktop |

Profiles can be mixed to produce combined desktops — the example `fll.conf` ships several such combinations (e.g. `kfce` = KDE + Xfce, `lxkde` = LXQt + KDE, `ginnamon` = GNOME + Cinnamon, `knome` = KDE + GNOME).

### Writing your own profile

A profile file is a plain text list of Debian package names, one per line, with support for group references. Place it under `share/profiles/<name>` and reference it by that name in `fll.conf`.

---

## Modules

Modules live under `share/modules/` and represent optional, self-contained feature bundles that are layered on top of a profile. They are specified via the `modules` key and also accept a comma-separated list.

### Available modules

| Module | Description |
|---|---|
| `firmware` | Non-free firmware packages for broad hardware support (Wi-Fi adapters, GPU microcode, etc.) |
| `cli-fancy` | Useful command-line tools and shell enhancements for a richer terminal experience |
| `qemu` | QEMU/KVM virtualisation support and guest tools |

Modules are additive and independent of each other — combine freely:

```ini
modules = firmware, cli-fancy, qemu
```

### Writing your own module

A module file follows the same format as a profile (a package list with optional group references). Place it under `share/modules/<name>` and add the name to the `modules` key in your chroot definition.

---

## Repository layout

```
pyfll/
├── fll              # Main executable
├── fll.conf         # Default/example configuration
├── bin/             # Helper scripts
├── share/
│   ├── fll.conf.spec    # Configuration schema and defaults
│   ├── profiles/        # Desktop environment package lists
│   └── modules/         # Optional feature modules (firmware, cli-fancy, qemu, …)
└── debian/          # Debian packaging metadata
```

---

## License

GNU General Public License v2.0 — see [COPYING](COPYING) for details.
