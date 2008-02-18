#!/usr/bin/python -tt

__author__    = 'Kel Modderman'
__copyright__ = '(C) 2008 Kel Modderman <kel@otaku42.de>'
__license__   = 'GPLv2 or any later version'

from configobj import ConfigObj
from optparse import OptionParser
from subprocess import Popen, PIPE

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
    log  = logging.getLogger("log")
    log.setLevel(logging.DEBUG)


    def _initLogger(self, lvl):
        """Set up the logger."""
        fmt = logging.Formatter("%(levelname)-8s - %(message)s")
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
                fmt = logging.Formatter("%(levelname)-8s %(asctime)s " +
                                         "%(message)s")
                out = os.path.abspath(self.opts.l)
                file = logging.FileHandler(filename = out, mode = 'w')
                file.setFormatter(fmt)
                file.setLevel(logging.DEBUG)
                self.log.addHandler(file)
            except:
                self.log.exception("failed to setup logfile")
                raise Error

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

        p.set_defaults(d = False, b = os.getcwd(), g = os.getgid(), l = None, 
                       n = False, o = os.getcwd(), p = False,
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


    def _processPkgProfile(self, archs, profile, dir):
        """Return a dict, arch string as keys and package list as values."""
        list = {}
        for arch in archs:
            list[arch] = {'debconf': [], 'list': []}

        self.log.info("processing package profile: %s" %
                      os.path.basename(profile))

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
            for arch in archs:
                for d in lines2list(pfile['debconf']):
                    list[arch]['debconf'].append(d)
                    self.log.debug("  %s", d)

        if 'debconf' in self.conf['packages']:
            self.log.debug("debconf (config):")
            for arch in archs:
                for d in lines2list(self.conf['packages']['debconf']):
                    list[arch]['debconf'].append(d)
                    self.log.debug("  %s" % d)

        if 'packages' in pfile:
            self.log.debug("packages:")
            for arch in archs:
                for p in lines2list(pfile['packages']):
                    list[arch]['list'].append(p)
                    self.log.debug("  %s" % p)

        if 'packages' in self.conf['packages']:
            self.log.debug("packages (config):")
            for arch in archs:
                for p in lines2list(self.conf['packages']['packages']):
                    list[arch]['list'].append(p)
                    self.log.debug("  %s" % p)

        for arch in archs:
            if arch in pfile:
                self.log.debug("packages (%s):" % arch)
                for p in lines2list(pfile[arch]):
                    list[arch]['list'].append(p)
                    self.log.debug("  %s" % p)

        deps = []
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
                for arch in archs:
                    for d in lines2list(dfile['debconf']):
                        list[arch]['debconf'].append(d)
                        self.log.debug("  %s" % d)

            if 'packages' in dfile:
                self.log.debug("packages:")
                for arch in archs:
                    for p in lines2list(dfile['packages']):
                        list[arch]['list'].append(p)
                        self.log.debug("  %s" % p)

            for arch in archs:
                if arch in dfile:
                    self.log.debug("packages (%s):" % arch)
                    for p in lines2list(dfile[arch]):
                        list[arch]['list'].append(p)
                        self.log.debug("  %s" % p)

        return list


    def parsePkgProfile(self):
        """Parse packages profile file(s)."""
        dir = os.path.join(self.opts.s, 'packages')
        file = os.path.join(dir, self.conf['packages']['profile'])

        if not os.path.isfile(file):
            self.log.critical("no such package profile file: %s" % file)
            raise Error

        self.pkgs = self._processPkgProfile(self.conf['archs'].keys(),
                                            file, dir)


    def stageBuildArea(self):
        """Prepare temporary directory to prepare chroots and stage result."""
        self.log.info('Staging build area...')

        self.temp = tempfile.mkdtemp(prefix = 'fll_', dir = self.opts.b)
        if not self.opts.p:
            atexit.register(self.cleanup)

        for arch in self.conf['archs'].keys():
            os.mkdir(os.path.join(self.temp, arch))
            self.log.debug("creating directory: %s" %
                           os.path.join(self.temp, arch))

        os.mkdir(os.path.join(self.temp, 'staging'))
        self.log.debug("creating directory: %s" %
                       os.path.join(self.temp, 'staging'))


    def _umount(self, chrootdir):
        """Umount any mount points in a given chroot directory."""
        umount_list = []
        for line in open("/proc/mounts"):
            self.log.debug("/proc/mounts: %s" % line.rstrip())
            (dev, mnt, fs, options, d, p) = line.split()
            if mnt.startswith(chrootdir):
                umount_list.append(mnt)

        umount_list.sort(key=len)
        umount_list.reverse()

        for mpoint in umount_list:
            self.log.debug("umount %s" % mpoint)
            retv = call(["umount", mpoint])
            if retv != 0:
                self.log.critical("umount failed for: %s" % mpoint)
                raise Error


    def _nuke(self, dir):
        """Nuke directory tree."""
        self.log.info("nuking directory: %s" % dir)
        try:
            shutil.rmtree(dir)
        except:
            self.log.exception("unable to remove %s" % dir)
            raise Error


    def cleanup(self):
        """Clean up the build area."""
        for arch in self.conf['archs'].keys():
            self.log.info("cleaning up %s chroot..." % arch)
            self._umount(os.path.join(self.temp, arch))
            self._nuke(os.path.join(self.temp, arch))

        self.log.info('Cleaning up temp dir...')
        self._nuke(self.temp)


if __name__ == "__main__":
    try:
        fll = FLLBuilder()
        fll.parseOpts()
        fll.parseConf()
        fll.parsePkgProfile()
        fll.stageBuildArea()
    except Error:
        sys.exit(1)
