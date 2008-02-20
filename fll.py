#!/usr/bin/python -tt

__author__    = 'Kel Modderman'
__copyright__ = '(C) 2008 Kel Modderman <kel@otaku42.de>'
__license__   = 'GPLv2 or any later version'

from configobj import ConfigObj
from debian_bundle import deb822
from optparse import OptionParser
from subprocess import *

import atexit
import logging
import os
import sys
import shutil
import tempfile


def lines2list(lines):
    """Return a list of stripped strings given a group of line
    separated strings"""
    return [s.strip() for s in lines.splitlines() if s]


class Error(Exception):
    """A generic error handler that does nothing."""
    pass


class FLLBuilder:
    conf = None
    opts = None
    pkgs = None
    temp = None

    log = logging.getLogger("log")
    log.setLevel(logging.DEBUG)

    env = {'LANGUAGE': 'C', 'LC_ALL': 'C', 'LANG' : 'C', 'HOME': '/root',
           'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'SHELL': '/bin/bash',
           'DEBIAN_FRONTEND': 'noninteractive', 'DEBIAN_PRIORITY': 'critical',
           'DEBCONF_NOWARNINGS': 'yes', 'XORG_CONFIG': 'custom'}

    diverts = ['/sbin/modprobe', '/sbin/start-stop-daemon']


    def _initLogger(self, lvl):
        """Set up the logger."""
        fmt = logging.Formatter("%(levelname)s - %(message)s")
        out = logging.StreamHandler()
        out.setFormatter(fmt)
        out.setLevel(lvl)
        self.log.addHandler(out)


    def processOpts(self):
        """Process options."""
        if self.opts.d:
            self._initLogger(logging.DEBUG)
        elif self.opts.v:
            self._initLogger(logging.INFO)
        else:
            self._initLogger(logging.WARNING)

        if self.opts.l:
            try:
                fmt = logging.Formatter("%(asctime)s %(levelname)-8s " +
                                         "%(message)s")
                out = os.path.abspath(self.opts.l)
                file = logging.FileHandler(filename = out, mode = 'w')
                file.setFormatter(fmt)
                file.setLevel(logging.DEBUG)
                self.log.addHandler(file)
            except:
                self.log.exception("failed to setup logfile")
                raise Error
            else:
                os.chown(out, self.opts.u, self.opts.g)

        if self.opts.c:
            if os.path.isfile(self.opts.c):
                self.opts.c = os.path.abspath(self.opts.c)
            else:
                self.log.critical("configuration file does not exist: %s" %
                                  self.opts.c)
                raise Error
        else:
            self.log.critical("no config file specified on command line")
            raise Error

        if self.opts.s:
            if not os.path.isdir(self.opts.s):
                self.log.critical("share directory not exist: %s" %
                                  self.opts.s)
                raise Error

        self.opts.s = os.path.abspath(self.opts.s)

        if not os.path.isdir(self.opts.o):
            try:
                os.makedirs(self.opts.o)
            except:
                self.log.exception("failed to create output dir: %s" %
                                   self.opts.o)
                raise Error

        self.opts.o = os.path.abspath(self.opts.o)

        if not os.path.isdir(self.opts.b):
            try:
                os.makedirs(self.opts.b)
            except:
                self.log.exception("failed to create build dir: %s" %
                                   self.opts.b)
                raise Error

        self.opts.b = os.path.abspath(self.opts.b)


    def parseOpts(self):
        """Parse command line arguments."""
        p = OptionParser(usage = 'fll -c <config file> [-b <directory> ' +
                         '-o <directory> -s <directory>] [-dpqv]')

        p.add_option('-b', '--build', dest = 'b', action = 'store',
                     type = 'string', metavar = '<directory>',
                     help = 'Build directory. A large amount of free space ' +
                     'is required.')

        p.add_option('-B', '--binary', dest = 'B', action = 'store_true',
                     help = 'Do binary build only. Disable generation of ' +
                     'URI lists. Default: %default')

        p.add_option('-c', '--config', dest = 'c', action = 'store',
                     type = 'string', metavar = '<config file>',
                     help = 'Configuration file. This option may be used ' +
                     'more than once to process multiple configurations. ' +
                     'A configuration file must be specified.')

        p.add_option('-d', '--debug', dest = 'd', action = 'store_true',
                     help = 'Enable debug mode. Extra output will be ' +
                     'to assist in development. Default: %default')

        p.add_option('-g', '--gid', dest = 'g', action = 'store',
                     type = 'int', metavar = '<group id>',
                     help = 'Group ID of user doing the build. This ' +
                     'should not normally be required, the wrapper script ' +
                     'will take care of this for you.')

        p.add_option('-l', '--log', dest = 'l', action = 'store',
                     type = 'string', metavar = '<file>',
                     help = 'Log debug output to file.')

        p.add_option('-n', '--non-root', dest = 'n', action = 'store_true',
                     help = 'Start as noon root user (for debugging).')

        p.add_option('-o', '--output', dest = 'o', action = 'store',
                     type = 'string', metavar = '<directory>',
                     help = 'Output directory, where the product of this ' +
                     'program will be generated.')

        p.add_option('-p', '--preserve', dest = 'p', action = 'store_true',
                     help = 'Preserve build directory. Disable automatic ' +
                     'cleanup of the build area at exit.')

        p.add_option('-q', '--quiet', dest = 'v', action = 'store_false',
                     help = 'Enable quiet mode. Only high priority messages ' +
                     'will be generated, such as announcing current')

        p.add_option('-s', '--share', dest = 's', action = 'store',
                     type = 'string', metavar = '<directory>',
                     help = 'Share directory directory containing data ' +
                     'required for the program to function.')

        p.add_option('-u', '--uid', dest = 'u', action = 'store',
                     type = 'int', metavar = '<user id>',
                     help = 'User ID of user doing the build. This ' +
                     'should not normally be required, the wrapper script ' +
                     'will take care of this for you.')

        p.add_option('-v', '--verbose', dest = 'v', action = 'store_true',
                     help = 'Enable verbose mode. All messages will be ' +
                     'generated, such as announcing current operation.')

        p.set_defaults(d = False, b = os.getcwd(), B = False, g = os.getgid(),
                       l = None, n = False, o = os.getcwd(), p = False,
                       s = '/usr/share/fll/', u = os.getuid(), v = True)

        self.opts = p.parse_args()[0]
        self.processOpts()


    def processConf(self):
        """Process configuration options."""
        self.log.info('Processing configuration options...')

        if len(self.conf['archs'].keys()) < 1:
            host_arch = Popen(["dpkg", "--print-architecture"],
                              stdout=PIPE).communicate()[0].rstrip()
            self.conf['archs'][host_arch] = {}
            self.log.debug("default build arch: %s" % host_arch)

        for arch in self.conf['archs'].keys():
            if 'linux' not in self.conf['archs'][arch]:
                if arch == 'i386':
                    if os.path.isfile('/etc/sidux-version'):
                        self.conf['archs'][arch]['linux'] = '2.6-sidux-686'
                    else:
                        self.conf['archs'][arch]['linux'] = '2.6-686'
                else:
                    if os.path.isfile('/etc/sidux-version'):
                        self.conf['archs'][arch]['linux'] = '2.6-sidux-' + arch
                    else:
                        self.conf['archs'][arch]['linux'] = '2.6-' + arch
            self.log.debug("arch = %s, linux = %s" %
                           (arch, self.conf['archs'][arch]['linux']))

        if len(self.conf['repos'].keys()) < 1:
            self.log.critical("no apt repos were specified in build config")
            raise Error

        if 'debian' not in self.conf['repos']:
            self.log.critical("'debian' repo not configured in build config")
            raise Error

        for repo in self.conf['repos'].keys():
            for word in ['label', 'uri', 'suite', 'components']:
                if word not in self.conf['repos'][repo]:
                    self.log.critical("no '%s' for apt repo '%s'" %
                                     (word, repo))
                    raise Error

        if 'profile' not in self.conf['packages']:
            self.conf['packages']['profile'] = 'kde-lite'
        self.log.debug("package profile: %s" %
                       self.conf['packages']['profile'])


    def parseConf(self):
        """Parse build configuration file and return it in a dict."""
        self.log.info("Parsing configuration file...")

        self.conf = ConfigObj(self.opts.c, interpolation = 'Template')
        self.processConf()


    def _processPkgProfile(self, arch, profile, dir):
        """Return a dict, arch string as keys and package list as values."""
        pkgs = {'debconf': [], 'list': [], 'early': []}

        self.log.info("processing package profile for %s: %s" %
                      (arch, os.path.basename(profile)))

        pfile = ConfigObj(profile)

        if 'desc' in pfile:
            for l in lines2list(pfile['desc']):
                self.log.debug("  %s" % l)

        if 'repos' in pfile:
            for r in lines2list(pfile['repos']):
                if r not in self.conf['repos']:
                    self.log.critical("'%s' repo is required " % r +
                                     "by package module '%s'" %
                                     os.path.basename(profile))
                    raise Error

        if 'debconf' in pfile:
            self.log.debug("debconf:")
            for d in lines2list(pfile['debconf']):
                pkgs['debconf'].append(d)
                self.log.debug("  %s", d)

        if 'debconf' in self.conf['packages']:
            self.log.debug("debconf (config):")
            for d in lines2list(self.conf['packages']['debconf']):
                pkgs['debconf'].append(d)
                self.log.debug("  %s" % d)

        if 'packages' in pfile:
            self.log.debug("packages:")
            for p in lines2list(pfile['packages']):
                pkgs['list'].append(p)
                self.log.debug("  %s" % p)

        if 'packages' in self.conf['packages']:
            self.log.debug("packages (config):")
            for p in lines2list(self.conf['packages']['packages']):
                pkgs['list'].append(p)
                self.log.debug("  %s" % p)

        if arch in pfile:
            self.log.debug("packages (%s):" % arch)
            for p in lines2list(pfile[arch]):
                pkgs['list'].append(p)
                self.log.debug("  %s" % p)

        if 'early' in pfile:
            self.log.debug("early:")
            for p in lines2list(pfile['early']):
                pkgs['early'].append(p)
                self.log.debug("  %s" % p)

        deps = ['locales']
        if 'deps' in pfile:
            self.log.debug("deps:")
            for dep in lines2list(pfile['deps']):
                deps.append(dep)
                self.log.debug("  %s" % dep)

        if 'deps' in self.conf['packages']:
            self.log.debug("deps (config):")
            for dep in lines2list(self.conf['packages']['deps']):
                deps.append(dep)
                self.log.debug("  %s" % dep)

        for dep in deps:
            depfile = os.path.join(dir, 'packages.d', dep)

            if not os.path.isfile(depfile):
                self.log.critical("no such dep file: %s" % depfile)
                raise Error

            self.log.info("processing dependency file: %s" %
                          os.path.basename(depfile))

            dfile = ConfigObj(depfile)

            if 'desc' in dfile and self.opts.v:
                for l in lines2list(dfile['desc']):
                    self.log.debug("  %s" % l)

            if 'repos' in dfile:
                for repo in lines2list(dfile['repos']):
                    if repo not in self.conf['repos']:
                        self.log.critical("'%s' repo is required " % r +
                                          "by package module '%s'" %
                                          os.path.basename(depfile))
                        raise Error

            if 'debconf' in dfile:
                self.log.debug("debconf:")
                for d in lines2list(dfile['debconf']):
                    pkgs['debconf'].append(d)
                    self.log.debug("  %s" % d)

            if 'packages' in dfile:
                self.log.debug("packages:")
                for p in lines2list(dfile['packages']):
                    pkgs['list'].append(p)
                    self.log.debug("  %s" % p)

            if arch in dfile:
                self.log.debug("packages (%s):" % arch)
                for p in lines2list(dfile[arch]):
                    pkgs['list'].append(p)
                    self.log.debug("  %s" % p)

            if 'early' in dfile:
                self.log.debug("early:")
                for p in lines2list(dfile['early']):
                    pkgs['early'].append(p)
                    self.log.debug("  %s" % p)

        return pkgs


    def parsePkgProfile(self):
        """Parse packages profile file(s)."""
        dir = os.path.join(self.opts.s, 'packages')
        file = os.path.join(dir, self.conf['packages']['profile'])

        if not os.path.isfile(file):
            self.log.critical("no such package profile file: %s" % file)
            raise Error

        self.pkgs = {}
        for arch in self.conf['archs'].keys():
            self.pkgs[arch] = {}
            self.pkgs[arch] = self._processPkgProfile(arch, file, dir)

        if self.opts.d:
            print self.pkgs


    def stageBuildArea(self):
        """Prepare temporary directory to prepare chroots and stage result."""
        self.log.info('Staging build area...')

        self.temp = tempfile.mkdtemp(prefix = 'fll_', dir = self.opts.b)
        os.chown(self.temp, self.opts.u, self.opts.g)

        if not self.opts.p:
            atexit.register(self.cleanup)

        os.mkdir(os.path.join(self.temp, 'staging'))
        self.log.debug("creating directory: %s" %
                       os.path.join(self.temp, 'staging'))


    def _mount(self, chroot):
        """Mount virtual filesystems in a shoort dir."""
        self.log.debug("mounting virtual filesystems in %s" % chroot)

        virtfs = {'devpts': 'dev/pts', 'proc': 'proc'}

        for v in virtfs.items():
            cmd = ['mount', '-t', v[0], 'fll-' + v[0],
                   os.path.join(chroot, v[1])]
            self.log.debug(' '.join(cmd))

            retv = call(cmd)
            if retv != 0:
                self.log.critical("failed to mount chroot %s" % v[0])
                raise Error


    def _umount(self, chrootdir):
        """Umount any mount points in a given chroot directory."""
        umount_list = []
        for line in open("/proc/mounts"):
            (dev, mnt, fs, options, d, p) = line.split()
            if mnt.startswith(chrootdir):
                umount_list.append(mnt)
        self.log.debug("umount_list: " + ' '.join(umount_list))

        umount_list.sort(key=len)
        umount_list.reverse()

        for mpoint in umount_list:
            self.log.debug("umount %s" % mpoint)
            retv = call(['umount', mpoint])
            if retv != 0:
                self.log.critical("umount failed for: %s" % mpoint)
                raise Error


    def _nuke(self, dir):
        """Nuke directory tree."""
        if os.path.isdir(dir):
            self.log.info("nuking directory: %s" % dir)
            try:
                shutil.rmtree(dir)
            except:
                self.log.exception("unable to remove %s" % dir)
                raise Error
        else:
            self.log.info("no dir to remove")


    def cleanup(self):
        """Clean up the build area."""
        for arch in self.conf['archs'].keys():
            dir = os.path.join(self.temp, arch)
            if os.path.isdir(dir):
                self.log.info("cleaning up %s chroot..." % arch)
                self._umount(dir)
                self._nuke(dir)

        self.log.info('Cleaning up temp dir...')
        self._nuke(self.temp)


    def _execInChroot(self, arch, args, sh = False, ignore_nonzero = False):
        """Run command in a chroot."""
        if os.getenv('http_proxy'):
            e['http_proxy'] = os.getenv('http_proxy')
        if os.getenv('ftp_proxy'):
            e['ftp_proxy'] = os.getenv('ftp_proxy')

        chroot = os.path.join(self.temp, arch)
        cmd = ['chroot', chroot]
        cmd.extend(args)

        self._mount(chroot)

        self.log.info("command: %s", ' '.join(cmd))
        retv = call(cmd, shell = sh, env = self.env)

        self._umount(chroot)

        if retv != 0:
            if ignore_nonzero:
                self.log.info("non zero retval ignored: %d" % retv)
            else:
                self.log.critical("command return value: %d" % retv)
                raise Error

    def _bootStrap(self, arch, verbosity = None, dir = None, mirror = None,
                   flavour = 'minimal', suite = 'sid', ):
        """Bootstrap a debian system with cdebootstrap."""
        if self.opts.d:
            verbosity = '--debug'
        elif self.opts.v:
            verbosity = '--verbose'

        debian = self.conf['repos']['debian']
        if 'cached' in debian and debian['cached']:
            mirror = debian['cached']
        else:
            mirror = debian['uri']

        for arch in self.conf['archs'].keys():
            dir = os.path.join(self.temp, arch)
            cmd = ['cdebootstrap', "--arch=%s" % arch,
                   '--include=apt-utils', "--flavour=%s" % flavour,
                   suite, dir, mirror]

            if verbosity:
                cmd.append(verbosity)

            self.log.info("bootstrapping %s at %s" % (arch, dir))
            self.log.debug(' '.join(cmd))

            retv = call(cmd)
            if retv != 0:
                self.log.critical("failed to bootstrap %s" % arch)
                raise Error

            cmd = 'dpkg --purge cdebootstrap-helper-diverts'
            self._execInChroot(arch, cmd.split())


    def _primeApt(self, arch):
        """Prepare apt for work in each build chroot."""
        dir = os.path.join(self.temp, arch)

        self.log.debug("removing sources.list from %s chroot" % arch)
        list = os.path.join(dir, 'etc/apt/sources.list')
        if os.path.isfile(list):
            os.unlink(list)

        for repo in self.conf['repos'].keys():
            r = self.conf['repos'][repo]
            file = os.path.join(dir, 'etc/apt/sources.list.d',
                                r['label'] + '.list')
            self.log.debug("creating %s" % file)

            line = []
            if 'cached' in r and r['cached']:
                line.append(r['cached'])
            else:
                line.append(r['uri'])

            line.append(r['suite'])
            line.append(r['components'])
            line.append("\n")

            l = ' '.join(line)
            self.log.debug("%s: %s", repo, l.rstrip())

            list = open(file, "w")
            list.write('deb ' + l)
            if not self.opts.B:
                list.write('deb-src ' + l)
            list.close()

        keyrings = []
        for repo in self.conf['repos'].keys():
            r = self.conf['repos'][repo]
            if 'keyring' in r and r['keyring']:
                keyrings.append(r['keyring'])

        if len(keyrings) > 0:
            self._execInChroot(arch, 'apt-get update'.split())
            cmd = ['apt-get', '--allow-unauthenticated', '--yes',
                   'install']
            cmd.extend(keyrings)
            self._execInChroot(arch, cmd)

        gpgkeys = []
        for repo in self.conf['repos'].keys():
            r = self.conf['repos'][repo]
            if 'gpgkey' in r:
                self.log.info("importing gpg key for '%s'" % r['label'])
                gpgkeys.append(r['gpgkey'])

                if r['gpgkey'].startswith('http'):
                    cmd = 'gpg --fetch-keys ' + r['gpgkey']
                    self._execInChroot(arch, cmd.split())
                elif os.path.isfile(r['gpgkey']):
                    dest = os.path.join(self.temp, arch, 'root')
                    file = os.path.basename(r['gpgkey'])
                    shutil.copy(r['gpgkey'], dest)
                    cmd = 'gpg --import /root/' + file
                    self._execInChroot(arch, cmd.split(),
                                       ignore_nonzero = True)
                else:
                    cmd = 'gpg --keyserver wwwkeys.eu.pgp.net '
                    cmd += '--recv-keys ' + r['gpgkey']
                    self._execInChroot(arch, cmd.split(),
                                       ignore_nonzero = True)

        if len(gpgkeys) > 0:
            cmd = 'apt-key add /root/.gnupg/pubring.gpg'
            self._execInChroot(arch, cmd.split())
            self._execInChroot(arch, 'apt-key update'.split())

        self._execInChroot(arch, 'apt-get update'.split())


    def _dpkgAddDivert(self, arch):
        """Divert some facilities and replace temporaily with /bin/true (or
        some other more appropiate facility."""
        chroot = os.path.join(self.temp, arch)
        for d in self.diverts:
            self.log.debug("diverting %s" % d)
            cmd = 'dpkg-divert --add --local --divert ' + d + '.REAL --rename '
            cmd += d
            self._execInChroot(arch, cmd.split())
            shutil.copy(os.path.join(chroot, 'bin/true'),
                        os.path.join(chroot, d.lstrip('/')))

        policyrcd = os.path.join(chroot, 'usr/sbin/policy-rc.d')
        self.log.debug("creating %s" % policyrcd)
        policy = open(policyrcd, 'w')
        policy.write("#!/bin/sh\nexit 101\n")
        policy.close()
        os.chmod(policyrcd, 0700)


    def _dpkgUnDivert(self, arch):
        """Divert some facilities and replace temporaily with /bin/true (or
        some other more appropiate facility."""
        chroot = os.path.join(self.temp, arch)
        for d in self.diverts:
            self.log.debug("undoing diversion of %s" % d)
            os.unlink(os.path.join(chroot, d.lstrip('/')))
            cmd = 'dpkg-divert --rename --remove ' + d
            self._execInChroot(arch, cmd.split())

        policyrcd = os.path.join(chroot, 'usr/sbin/policy-rc.d')
        if os.path.isfile(policyrcd):
            self.log.debug("removing %s" % policyrcd)
            os.unlink(policyrcd)


    def _defaultEtc(self, arch):
        """Initial creation of conffiles required in chroot."""
        chroot = os.path.join(self.temp, arch)

        self.log.debug("creating minimal /etc/fstab...")
        fstab = open(os.path.join(chroot, 'etc/fstab'), 'w')
        fstab.write("# /etc/fstab: static file system information\n")
        fstab.close()

        self.log.debug("creating minimal /etc/network/interfaces...")
        eni = open(os.path.join(chroot, 'etc/network/interfaces'), 'w')
        eni.write("# /etc/network/interfaces -- configuration file for " +
                  "ifup(8), ifdown(8)\n")
        eni.write("\n")
        eni.write("# The loopback interface\n")
        eni.write("auto lo\n")
        eni.write("iface lo inet loopback\n")
        eni.close()

        self.log.debug("creating /etc/hostname...")
        hostname = open(os.path.join(chroot, 'etc/hostname'), 'w')
        hostname.write(self.conf['distro']['FLL_DISTRO_NAME'] + "\n")
        hostname.close()

        self.log.debug("creating /etc/kernel-img.conf...")
        kernelimg = open(os.path.join(chroot, 'etc/kernel-img.conf'), 'w')
        kernelimg.write("do_bootloader = No\n")
        kernelimg.write("warn_initrd   = No\n")
        kernelimg.close()


    def _finalEtc(self, arch):
        """Final editing of conffiles in chroot."""
        chroot = os.path.join(self.temp, arch)

        self.log.debug("completing /etc/kernel-img.conf...")
        kernelimg = open(os.path.join(chroot, 'etc/kernel-img.conf'), 'a')
        kernelimg.write("postinst_hook = /usr/sbin/update-grub\n")
        kernelimg.write("postrm_hook   = /usr/sbin/update-grub\n")
        kernelimg.close()

        self.log.debug("truncating /etc/resolv.conf...")
        resolv = open(os.path.join(chroot, 'etc/resolv.conf'), 'w')
        resolv.close()


    def _preseedDebconf(self, arch):
        """Preseed debcong with values read from package lists."""
        chroot = os.path.join(self.temp, arch)

        if 'debconf' in self.pkgs[arch]:
            self.log.debug("preseeding debconf")
            debconf = open(os.path.join(chroot, 'root/debconf-selections'),
                           'w')
            for d in self.pkgs[arch]['debconf']:
                debconf.write(d + "\n")
            debconf.close()

            cmd = 'debconf-set-selections '
            if self.opts.v:
                cmd += '--verbose '
            cmd += '/root/debconf-selections'

            self._execInChroot(arch, cmd.split())


    def _addTemplates(self):
        """Copy in some templates from data directory."""
        pass


    def _detectLinuxVersion(self, arch):
        """Return version string of a singularly installed linux-image."""
        chroot = os.path.join(self.temp, arch)

        for f in os.listdir(os.path.join(chroot, 'boot')):
            if f.startswith('vmlinuz-'):
                return f.lstrip('vmlinuz-')

        self.debug.critical("failed to detect linux version installed in " +
                            "%s chroot" % arch)
        raise Error


    def _detectLinuxModules(self, arch, kvers):
        """Detect available linux extra modules."""
        chroot = os.path.join(self.temp, arch)
        listsdir = os.path.join(chroot, 'var/lib/apt/lists')
        lists = [os.path.join(listsdir, l) for l in os.listdir(listsdir)
                 if l.endswith('_Packages')]
        
        modules = []
        for list in lists:
            for pkg in deb822.Packages.iter_paragraphs(file(list)):
                if pkg['Package'].endswith('modules-' + kvers):
                    modules.append(pkg['Package'])

        return modules


    def _installLinux(self, arch):
        """Install linux image, headers, extra modules and associated support
        software."""
        version = self.conf['archs'][arch]['linux']

        cmd = 'apt-get --yes install'
        cmd += ' linux-image-' + version
        cmd += ' linux-headers-' + version
        self._execInChroot(arch, cmd.split())

        version = self._detectLinuxVersion(arch)

        cmd = 'update-initramfs -k ' + version + ' -d'
        self._execInChroot(arch, cmd.split())

        modules = self._detectLinuxModules(arch, version)

        cmd = 'apt-get --yes install'.split()
        cmd.extend(modules)
        self._execInChroot(arch, cmd)

        cmd = 'update-initramfs -k ' + version + ' -c'
        if self.opts.v:
            cmd += ' -v'
        self._execInChroot(arch, cmd.split())


    def _installPkgs(self, arch, key):
        """Install packages required very early in the chroot building process
        (such as those containing apt policies/preferences)."""
        cmd = 'apt-get --yes install'.split()
        cmd.extend(self.pkgs[arch][key])
        self._execInChroot(arch, cmd)


    def buildChroot(self):
        """Main loop to call all chroot building functions."""
        archs = self.conf['archs'].keys()
        for arch in archs:
            self._bootStrap(arch)
        for arch in archs:
            self._primeApt(arch)
            self._dpkgAddDivert(arch)
            self._defaultEtc(arch)
            self._preseedDebconf(arch)
            self._installPkgs(arch, 'early')
            self._installLinux(arch)
            self._installPkgs(arch, 'list')
            self._finalEtc(arch)
            self._dpkgUnDivert(arch)


if __name__ == "__main__":
    try:
        fll = FLLBuilder()
        fll.parseOpts()
        fll.parseConf()
        fll.parsePkgProfile()
        fll.stageBuildArea()

        if fll.opts.n:
            sys.exit(0)

        fll.buildChroot()
    except Error:
        sys.exit(1)
