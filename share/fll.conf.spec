[chroots]
    [[__many__]]
        [[[packages]]]
        distro   = string(default='debian')
        codename = string(default='sid')
        arch     = string(default='amd64')
        linux    = string(default='aptosid-amd64')
        profile  = force_list(default=list('kde-lite'))
        browser  = force_list(default=list())
        modules  = force_list(default=list('firmware'))
        locales  = force_list(default=list())

        [[[repos]]]
            [[[[debian]]]]
            uri        = string(default='https://deb.debian.org/debian/')
            cached     = string(default=None)
            suite      = string(default='sid')
            components = string(default='main non-free-firmware')
            keyring    = string(default=None)

            [[[[aptosid]]]]
            uri        = string(default='http://aptosid.com/debian/')
            cached     = string(default=None)
            suite      = string(default='sid')
            components = string(default='main fix.main')
            keyring    = string(default=aptosid-archive-keyring)

            [[[[__many__]]]]
            uri         = string(default=None)
            cached      = string(default=None)
            suite       = string(default=None)
            components  = string(default=None)
            keyring     = string(default=None)
            sources_uri = string(default=None)
[options]
apt_preferences = string(default=None)
apt_recommends  = option('yes', 'no', default='no')
boot_cmdline    = string(default='apparmor=0 fsck.mode=skip systemd.show_status=1 quiet splash')
boot_theme      = string(default='bgrt')
boot_timeout    = string(default='30')
bootstrapper    = option('cdebootstrap', 'debootstrap', 'mmdebstrap', default='cdebootstrap')
homed_privkey   = string(default=None)
homed_pubkey    = string(default=None)
media_include   = string(default=None)

readonly_filesystem  = option('squashfs', 'erofs', default='squashfs')
squashfs_comp        = option('gzip', 'lz4', 'lzo', 'xz', 'zstd', default='zstd')
squashfs_processors  = integer(min=1, default=None)
squashfs_throttle    = integer(1, 99, default=None)
erofs_compression    = option('lz4', 'lz4hc', 'lzma', 'deflate', 'libdeflate', 'zstd', 'none', default='lzma')
erofs_comp_level     = integer(min=1, default=None)
erofs_uuid           = string(default='00000000-0000-0000-0000-000000000000')
erofs_options        = string(default=None)

[distro]
FLL_DISTRO_NAME = string(default='aptosid')

FLL_IMAGE_DIR  = string(default='aptosid')
FLL_IMAGE_FILE = string(default='aptosid')

FLL_LIVE_USER        = string(default='aptosid')
FLL_LIVE_USER_GROUPS = string(default='dialout dip cdrom audio video input render plugdev floppy netdev bluetooth lpadmin kvm sudo')

FLL_WALLPAPER     = string(default='/usr/share/wallpapers/aptosid-nemesis')
FLL_GFXBOOT_THEME = string(default='aptosid-nemesis')

FLL_IRC_SERVER    = string(default='irc.oftc.net')
FLL_IRC_PORT      = string(default='6697')
FLL_IRC_CHANNEL   = string(default='#aptosid')
