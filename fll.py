#!/usr/bin/python -tt

__author__    = 'Kel Modderman'
__copyright__ = '(C) 2008 Kel Modderman <kel@otaku42.de>'
__license__   = 'GPLv2 or any later version'

from configobj import ConfigObj
from debian_bundle import deb822
from optparse import OptionParser
from subprocess import *

import atexit
import glob
import logging
import os
import sys
import shutil
import tempfile
import time


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
    distro = None

    log = logging.getLogger("log")
    log.setLevel(logging.DEBUG)

    env = {'LANGUAGE': 'C', 'LC_ALL': 'C', 'LANG' : 'C', 'HOME': '/root',
           'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'SHELL': '/bin/bash',
           'DEBIAN_FRONTEND': 'noninteractive', 'DEBIAN_PRIORITY': 'critical',
           'DEBCONF_NOWARNINGS': 'yes', 'XORG_CONFIG': 'custom'}

    diverts = ['/sbin/start-stop-daemon', '/sbin/modprobe',
               '/usr/sbin/policy-rc.d']


    def __filterList(self, list, dup_warn = False):
        """Return a list containing no duplicate items given a list that
        may have duplicate items."""

        d = {}
        for l in list:
            if l in d and dup_warn:
                self.log.debug("duplicate: %s" % l)
            else:
                d[l] = True

        list = d.keys()
        list.sort()

        return list


    def __isexecutable(self, file):
        """Return True is file is executable, False otherwise."""
        if os.access(file, os.X_OK) and not os.path.isdir(file):
            return True
        else:
            return False


    def _initLogger(self, lvl):
        """Set up the logger."""
        fmt = logging.Formatter("%(asctime)s %(levelname)s - %(message)s")
        out = logging.StreamHandler()
        out.setFormatter(fmt)
        out.setLevel(lvl)
        self.log.addHandler(out)


    def _processOpts(self):
        """Process options."""
        if self.opts.d:
            self._initLogger(logging.DEBUG)
        else:
            self._initLogger(logging.INFO)

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

        p.add_option('-q', '--quiet', dest = 'q', action = 'store_true',
                     help = 'Enable quiet mode. Only high priority messages ' +
                     'will be generated.')

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

        p.set_defaults(b = os.getcwd(), B = False, d = False, g = os.getgid(),
                       l = None, n = False, o = os.getcwd(), p = False,
                       q = False, s = '/usr/share/fll/', u = os.getuid(),
                       v = False)

        self.opts = p.parse_args()[0]
        self._processOpts()


    def _processDefaults(self, arch, d):
        """Form a distro-defaults data structure to be written to
        /etc/default/distro of each chroot, and used for release name."""
        for k in ['FLL_DISTRO_NAME', 'FLL_IMAGE_DIR', 'FLL_IMAGE_FILE',
                  'FLL_MEDIA_NAME', 'FLL_MOUNTPOINT', 'FLL_LIVE_USER',
                  'FLL_LIVE_USER_GROUPS']:
            if not k in d or not d[k]:
                self.log.critical("%s' is required in 'distro' section " % k +
                                  "of build conf")
                raise Error

        for k in ['FLL_DISTRO_NAME', 'FLL_IMAGE_DIR', 'FLL_IMAGE_FILE',
                  'FLL_LIVE_USER', 'FLL_DISTRO_CODENAME_SAFE',
                  'FLL_DISTRO_CODENAME_REV_SAFE']:
            if k not in d or not d[k]:
                continue
            if not d[k].isalnum():
                self.log.critical("'%s' is not alphanumeric: %s" % (k, d[k]))
                raise Error
            elif d[k].find(' ') >= 0:
                self.log.critical("'%s' contains whitespace: %s" % (k, d[k]))
                raise Error

        if 'FLL_DISTRO_VERSION' in d and d['FLL_DISTRO_VERSION'] and \
            d['FLL_DISTRO_VERSION'] != 'snapshot':
            for k in ['FLL_DISTRO_CODENAME', 'FLL_DISTRO_CODENAME_REV']:
                safe = k + '_SAFE'
                if safe in d and d[safe]:
                    if k not in d or not d[k]:
                        d[k] = d[safe]
                else:
                    self.log.critical("'FLL_DISTRO_VERSION' is set, but " +
                                      "'%s' was not specified" % safe)
                    raise Error
        else:
            d['FLL_DISTRO_VERSION'] = 'snapshot'


        dd = {}
        for k, v in d.items():
            if k == 'FLL_IMAGE_FILE':
                dd[k] = '.'.join([v, arch])
            else:
                dd[k] = v

        dd['FLL_IMAGE_LOCATION'] = os.path.join(dd['FLL_IMAGE_DIR'],
                                                dd['FLL_IMAGE_FILE'])

        return dd


    def _processConf(self):
        """Process configuration options."""
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

        if not 'apt' in self.conf:
            self.conf['apt'] = {}
        if not 'recommends' in self.conf['apt']:
            self.conf['apt']['recommends'] = 'no'

        if 'distro' in self.conf:
            self.distro = {}
            for arch in self.conf['archs'].keys():
                self.distro[arch] = self._processDefaults(arch,
                                                          self.conf['distro'])
                self.log.debug("distro-defaults for %s:" % arch)
                self.log.debug(self.distro[arch])
        else:
            self.log.critical("'distro' section not found in build config")
            raise Error

        self.log.debug(self.conf)


    def parseConf(self):
        """Parse build configuration file and return it in a dict."""
        self.log.info("reading configuration file...")

        self.conf = ConfigObj(self.opts.c)
        self._processConf()


    def _processPkgProfile(self, arch, profile, dir):
        """Return a dict, arch string as keys and package list as values."""
        pkgs = {'debconf': [], 'list': []}

        linux_meta = ['linux-image', 'linux-headers']
        kvers = self.conf['archs'][arch]['linux']
        pkgs['list'].extend(['-'.join([l, kvers]) for l in linux_meta])

        self.log.debug("processing package profile for %s: %s" %
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

            self.log.debug("processing dependency file: %s" %
                           os.path.basename(depfile))

            dfile = ConfigObj(depfile)

            if 'desc' in dfile:
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

        self.log.debug("packages + debconf for %s:" % arch)
        self.log.debug(pkgs)

        pkgs['list'] = self.__filterList(pkgs['list'], dup_warn = True)

        return pkgs


    def parsePkgProfile(self):
        """Parse packages profile file(s)."""
        self.log.info("processing package profile...")

        dir = os.path.join(self.opts.s, 'packages')
        file = os.path.join(dir, self.conf['packages']['profile'])

        if not os.path.isfile(file):
            self.log.critical("no such package profile file: %s" % file)
            raise Error

        self.pkgs = {}
        for arch in self.conf['archs'].keys():
            self.pkgs[arch] = self._processPkgProfile(arch, file, dir)


    def stageBuildArea(self):
        """Prepare temporary directory to prepare chroots and stage result."""
        self.log.debug('preparing build area...')

        self.temp = tempfile.mkdtemp(prefix = 'fll_', dir = self.opts.b)
        os.chown(self.temp, self.opts.u, self.opts.g)

        if not self.opts.p:
            atexit.register(self.cleanup)

        os.mkdir(os.path.join(self.temp, 'staging'))
        self.log.debug("creating directory: %s" %
                       os.path.join(self.temp, 'staging'))


    def _mount(self, chroot):
        """Mount virtual filesystems in a shoort dir."""
        virtfs = {'devpts': 'dev/pts', 'proc': 'proc'}

        for v in virtfs.items():
            cmd = ['mount', '-t', v[0], 'fll-' + v[0],
                   os.path.join(chroot, v[1])]

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

        umount_list.sort(key=len)
        umount_list.reverse()

        for mpoint in umount_list:
            retv = call(['umount', mpoint])
            if retv != 0:
                self.log.critical("umount failed for: %s" % mpoint)
                raise Error


    def _nuke(self, dir):
        """Nuke directory tree."""
        if os.path.isdir(dir):
            self.log.debug("nuking directory: %s" % dir)
            try:
                shutil.rmtree(dir)
            except:
                self.log.exception("unable to remove %s" % dir)
                raise Error
        else:
            self.log.debug("not nuking directory (does not exist): %s" % dir)


    def _nukeChroot(self, arch):
        """Convenience function to nuke chroot given by arch name."""
        if not self.opts.p:
            self.log.info("nuking %s chroot..." % arch)
            chroot = os.path.join(self.temp, arch)
            self._umount(chroot)
            self._nuke(chroot)


    def cleanup(self):
        """Clean up the build area."""
        self.log.info('cleaning up...')

        for arch in self.conf['archs'].keys():
            dir = os.path.join(self.temp, arch)
            if os.path.isdir(dir):
                self.log.debug("cleaning up %s chroot..." % arch)
                self._umount(dir)
                self._nuke(dir)

        self._nuke(self.temp)


    def _execInChroot(self, arch, args, ignore_nonzero = False):
        """Run command in a chroot."""
        if os.getenv('http_proxy'):
            e['http_proxy'] = os.getenv('http_proxy')
        if os.getenv('ftp_proxy'):
            e['ftp_proxy'] = os.getenv('ftp_proxy')

        chroot = os.path.join(self.temp, arch)
        cmd = ['chroot', chroot]
        cmd.extend(args)

        self._mount(chroot)

        self.log.debug("%s", ' '.join(cmd))
        if self.opts.q:
            retv = call(cmd, stdout = open('/dev/null', 'w'), stderr = STDOUT,
                        env = self.env)
        else:
            retv = call(cmd, env = self.env)

        self._umount(chroot)

        if retv != 0:
            if ignore_nonzero:
                self.log.debug("non zero retval ignored: %d" % retv)
            else:
                self.log.critical("command failed with return value: %d" %
                                  retv)
                raise Error


    def _aptGetInstall(self, arch, pkgs):
        """An apt-get wrapper."""
        aptget = ['apt-get', '--yes']

        if self.conf['apt']['recommends'] == 'no':
            aptget.extend(['-o', 'APT::Install-Recommends=0'])
        if self.opts.d:
            aptget.extend(['-o', 'APT::Get::Show-Versions=1'])

        aptget.append('install')
        aptget.extend(pkgs)

        self._execInChroot(arch, aptget)


    def _bootStrap(self, arch, verbosity = None, dir = None, mirror = None,
                   flavour = 'minimal', suite = 'sid', ):
        """Bootstrap a debian system with cdebootstrap."""
        if self.opts.d:
            verbosity = '--debug'
        elif self.opts.v:
            verbosity = '--verbose'
        elif self.opts.q:
            verbosity = '--quiet'

        debian = self.conf['repos']['debian']
        if 'cached' in debian and debian['cached']:
            mirror = debian['cached']
        else:
            mirror = debian['uri']

        dir = os.path.join(self.temp, arch)
        cmd = ['cdebootstrap', "--arch=%s" % arch, '--include=apt-utils',
               "--flavour=%s" % flavour, suite, dir, mirror]

        if verbosity:
            cmd.append(verbosity)

        self.log.info("bootstrapping debian %s..." % arch)
        self.log.debug(' '.join(cmd))

        retv = call(cmd)
        if retv != 0:
            self.log.critical("failed to bootstrap %s" % arch)
            raise Error

        cmd = 'dpkg --purge cdebootstrap-helper-diverts'
        self._execInChroot(arch, cmd.split())


    def _writeAptLists(self, arch, cached = False, src_uri = False):
        """Write apt source lists to /etc/apt/sources.list.d/*."""
        chroot = os.path.join(self.temp, arch)
        for repo in self.conf['repos'].keys():
            r = self.conf['repos'][repo]
            file = os.path.join(chroot, 'etc/apt/sources.list.d',
                                r['label'] + '.list')
            self.log.debug("creating %s" % file)

            line = []
            if cached and 'cached' in r and r['cached']:
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
            if not src_uri or self.opts.B:
                list.write('#deb-src ' + l)
            else:
                list.write('deb-src ' + l)
            list.close()


    def _primeApt(self, arch):
        """Prepare apt for work in each build chroot."""
        chroot = os.path.join(self.temp, arch)

        self.log.debug("removing sources.list from %s chroot" % arch)
        list = os.path.join(chroot, 'etc/apt/sources.list')
        if os.path.isfile(list):
            os.unlink(list)

        self._writeAptLists(arch, cached = True, src_uri = True)

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
                self.log.debug("importing gpg key for '%s'" % r['label'])
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
            if d.endswith('policy-rc.d'):
                self._writeFile(arch, d)
                os.chmod(os.path.join(chroot, d.lstrip('/')), 0700)
            else:
                shutil.copy(os.path.join(chroot, 'bin/true'),
                            os.path.join(chroot, d.lstrip('/')))


    def _dpkgUnDivert(self, arch):
        """Divert some facilities and replace temporaily with /bin/true (or
        some other more appropiate facility."""
        chroot = os.path.join(self.temp, arch)
        for d in self.diverts:
            self.log.debug("undoing diversion: %s" % d)
            os.unlink(os.path.join(chroot, d.lstrip('/')))
            cmd = 'dpkg-divert --remove --rename ' + d
            self._execInChroot(arch, cmd.split())


    def _writeFile(self, arch, file):
        """Some file templates."""
        chroot = os.path.join(self.temp, arch)
        try:
            f = open(os.path.join(chroot, file.lstrip('/')), 'w')
            self.log.debug("writing file: %s" % file)
        except:
            self.log.exception("failed to open file for writing: %s" % file)
            raise Error

        if file == '/etc/default/distro':
            d = self.distro[arch].keys()
            d.sort()
            for k in d:
                f.write("%s=\"%s\"\n" % (k, self.distro[arch][k]))
        elif file == '/etc/fstab':
            f.write("# /etc/fstab: static file system information\n")
        elif file == '/etc/hostname':
            hostname = self.distro[arch]['FLL_DISTRO_NAME']
            f.write(hostname + "\n")
        elif file == '/etc/hosts':
            hostname = self.distro[arch]['FLL_DISTRO_NAME']
            f.write("127.0.0.1\tlocalhost\n")
            f.write("127.0.0.1\t" + hostname + "\n\n")
            f.write("# The following lines are for IPv6 capable hosts\n")
            f.write("::1     ip6-localhost ip6-loopback\n")
            f.write("fe00::0 ip6-localnet\n")
            f.write("ff00::0 ip6-mcastprefix\n")
            f.write("ff02::1 ip6-allnodes\n")
            f.write("ff02::2 ip6-allrouters\n")
            f.write("ff02::3 ip6-allhosts\n")
        elif file == '/etc/kernel-img.conf':
            f.write("do_bootloader = No\n")
            f.write("warn_initrd   = No\n")
        elif file == '/etc/network/interfaces':
            f.write("# /etc/network/interfaces - ")
            f.write("configuration file for ifup(8), ifdown(8)\n\n")
            f.write("# The loopback interface\n")
            f.write("auto lo\n")
            f.write("iface lo inet loopback\n")
        elif file == '/etc/resolv.conf':
            pass
        elif file == '/usr/sbin/policy-rc.d':
            f.write("#!/bin/sh\n")
            f.write("exit 101\n")

        f.close()


    def _defaultEtc(self, arch):
        """Initial creation of conffiles required in chroot."""
        self._writeFile(arch, '/etc/fstab')
        self._writeFile(arch, '/etc/kernel-img.conf')
        self._writeFile(arch, '/etc/network/interfaces')


    def _finalEtc(self, arch):
        """Final editing of conffiles in chroot."""
        self._writeFile(arch, '/etc/default/distro')
        self._writeFile(arch, '/etc/hostname')
        self._writeFile(arch, '/etc/hosts')
        self._writeFile(arch, '/etc/resolv.conf')

        self._writeAptLists(arch)

        self.log.debug('add grub hooks to /etc/kernel-img.conf')
        f = open(os.path.join(self.temp, arch, 'etc/kernel-img.conf'), 'a')
        f.write("postinst_hook = /usr/sbin/update-grub\n")
        f.write("postrm_hook   = /usr/sbin/update-grub\n")
        f.close()


    def _preseedDebconf(self, arch):
        """Preseed debcong with values read from package lists."""
        chroot = os.path.join(self.temp, arch)

        if 'debconf' in self.pkgs[arch]:
            self.log.info("preseeding debconf in %s chroot..." % arch)
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


    def _detectLinuxVersion(self, arch):
        """Return version string of a singularly installed linux-image."""
        chroot = os.path.join(self.temp, arch)

        kvers = [f.lstrip('vmlinuz-') for f in
                 os.listdir(os.path.join(chroot, 'boot'))
                 if f.startswith('vmlinuz-')]

        if len(kvers) > 0:
            return kvers

        self.debug.critical("failed to detect linux version installed in " +
                            "%s chroot" % arch)
        raise Error


    def _detectLinuxModules(self, arch, kvers):
        """Detect available linux extra modules."""
        listsdir = os.path.join(self.temp, arch, 'var/lib/apt/lists')
        lists = [os.path.join(listsdir, l) for l in os.listdir(listsdir)
                 if l.endswith('_Packages')]

        modules = []
        for list in lists:
            modules.extend([pkg['Package'] for pkg in
                            deb822.Packages.iter_paragraphs(file(list))
                            if pkg['Package'].endswith('-modules-' + kvers)])

        return modules


    def _installPkgs(self, arch):
        """Install packages."""
        self.log.info("installing packages in %s chroot..." % arch)

        pkgs = self.pkgs[arch]['list']

        linux_meta = self.conf['archs'][arch]['linux']
        pkgs.extend(self._detectLinuxModules(arch, linux_meta))

        self._aptGetInstall(arch, pkgs)


    def _collectManifest(self, arch):
        """Collect package and source package URI information from each
        chroot."""
        chroot = os.path.join(self.temp, arch)
        status = os.path.join(chroot, 'var/lib/dpkg/status')

        self.log.info("collecting package manifest for %s..." % arch)
        try:
            manifest = dict([(p['Package'], p['Version']) for p in
                             deb822.Packages.iter_paragraphs(file(status))
                             if p['Status'].endswith('install ok installed')])
        except:
            self.conf.exception("failed to collect manifest for %s", arch)
            raise Error
        else:
            self.pkgs[arch]['manifest'] = manifest

        if not self.opts.B:
            self.log.info("querying src package uri's for %s..." % arch)

            source = []
            kvers = self._detectLinuxVersion(arch)
            packages = manifest.keys()
            packages.sort()

            self._mount(chroot)
            for p in packages:
                for k in kvers:
                    if p.endswith('-modules-' + k):
                        if p.startswith('virtualbox-ose-guest'):
                            p = 'virtualbox-ose'
                        else:
                            p = p[:p.find('-modules-' + k)]

                if not self.opts.q:
                    self.log.info(p)

                cmd = 'chroot ' + chroot
                cmd += ' apt-get -qq --print-uris source ' + p
                try:
                    q = Popen(cmd.split(), env = self.env, stdout = PIPE,
                              stderr = open('/dev/null', 'w'))
                except:
                    self.log.exception("failed to query src uri's for %s" % p)
                    raise Error
                else:
                    uris = q.communicate()[0].splitlines()
                    if len(uris) > 0:
                        for u in uris:
                            uri = u.split()[0].strip("'")
                            self.log.debug(uri)
                            source.append(uri)
                    else:
                        self.log.critical("no source uri's for %s" % p)
                        raise Error
            self._umount(chroot)

            self.pkgs[arch]['source'] = self.__filterList(source)

    def _rebuildInitRamfs(self, arch):
        """Rebuild the chroot live initramfs after all packages have been
        installed."""
        kvers = self._detectLinuxVersion(arch)
        for k in kvers:
            self.log.info("creating an initial ramdisk for linux %s..." % k)
            cmd = 'update-initramfs -d -k ' + k
            self._execInChroot(arch, cmd.split())

            if self.opts.v:
                cmd = 'update-initramfs -v -c -k ' + k
            else:
                cmd = 'update-initramfs -c -k ' + k
            self._execInChroot(arch, cmd.split())


    def _initBlackList(self, arch):
        """Blacklist a group of initscripts present in chroot that should not
        be executed during live boot per default."""
        self.log.info("calculating initscript blacklist...")
        chroot = os.path.join(self.temp, arch)
        initd = '/etc/init.d/'
        
        init_glob = os.path.join(chroot, 'etc/init.d/*')
        try:
            initscripts = [i[i.index(initd):] for i in glob.glob(init_glob)
                           if self.__isexecutable(i)]
        except:
            log.self.exception("failed to build dict of chroot initscripts")
            raise Error
        else:
            initscripts.sort()
        
        bd = {}
        for line in open(os.path.join(self.opts.s, 'data/fll_init_blacklist')):
            if line.startswith('#'):
                continue
            files = []
            if line.startswith(initd):
                file_glob = os.path.join(chroot, line.lstrip('/').rstrip())
                try:
                    files = [f[f.index(initd):]
                             for f in glob.glob(file_glob)
                             if self.__isexecutable(f)]
                except:
                    log.self.exception("failed to glob initscript: %s" %
                                       file_glob)
                    raise Error
                else:
                    for file in files:
                        self.log.debug("blacklisting: %s (glob)" % file)
                        bd[file] = True
            else:
                cmd = 'chroot ' + chroot + ' dpkg-query --listfiles ' + line
                self._mount(chroot)
                p = Popen(cmd.split(), env = self.env, stdout = PIPE,
                          stderr = open('/dev/null', 'w'))
                p.wait()
                self._umount(chroot)
                for file in p.communicate()[0].splitlines():
                    file = file.strip().split()[0]
                    if file.startswith(initd):
                        self.log.debug("blacklisting: %s (%s)" %
                                       (file, line.rstrip()))
                        bd[file] = True

        wd = {}
        for line in open(os.path.join(self.opts.s, 'data/fll_init_whitelist')):
            if line.startswith('#'):
                continue
            files = []
            if line.startswith(initd):
                file_glob = os.path.join(chroot, line.lstrip('/').rstrip())
                try:
                    files = [f[f.index(initd):]
                             for f in glob.glob(file_glob)
                             if self.__isexecutable(f)]
                except:
                    log.self.exception("failed to glob initscript: %s" %
                                       file_glob)
                    raise Error
                else:
                    for file in files:
                        self.log.debug("whitelisting: %s (glob)" % file)
                        wd[file] = True
            else:
                cmd = 'chroot ' + chroot + ' dpkg-query --listfiles ' + line
                self._mount(chroot)
                p = Popen(cmd.split(), env = self.env, stdout = PIPE,
                          stderr = open('/dev/null', 'w'))
                p.wait()
                self._umount(chroot)
                for file in p.communicate()[0].splitlines():
                    file = file.strip().split()[0]
                    if file.startswith(initd) and file not in bd:
                        self.log.debug("whitelisting: %s (%s)" %
                                       (file, line.rstrip()))
                        wd[file] = True

        try:
            fllinit = open(os.path.join(chroot, 'etc/default/fll-init'), 'a')
        except:
            self.log.exception("failed to open file: %s" %
                               os.path.join(chroot, 'etc/default/fll-init'))
            raise Error
        else:
            self.log.debug('writing /etc/default/fll-init')
            for i in initscripts:
                if i in wd:
                    self.log.debug("whitelisted: %s" % i)
                    fllinit.write("%s\n" % os.path.basename(i))
                else:
                    self.log.debug("blacklisted: %s" % i)
            fllinit.close()


    def _cleanChroot(self, arch):
        """Remove unwanted content from a chroot."""
        chroot = os.path.join(self.temp, arch)

        self.log.debug("purging live initramfs")
        self._execInChroot(arch, 'dpkg --purge fll-live-initramfs'.split())

        self._execInChroot(arch, 'apt-get clean'.split())
        self._execInChroot(arch, 'dpkg --clear-avail'.split())


    def buildChroot(self):
        """Main loop to call all chroot building functions."""
        archs = self.conf['archs'].keys()
        for arch in archs:
            self._bootStrap(arch)
            self._primeApt(arch)
            self._defaultEtc(arch)
            self._preseedDebconf(arch)
            self._dpkgAddDivert(arch)
            self._installPkgs(arch)
            self._dpkgUnDivert(arch)
            self._initBlackList(arch)
            self._finalEtc(arch)
            self._rebuildInitRamfs(arch)
            self._collectManifest(arch)
            self._cleanChroot(arch)
            self._nukeChroot(arch)


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
    except KeyboardInterrupt:
        pass
    except Error:
        sys.exit(1)
