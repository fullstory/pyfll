#!/usr/bin/python -tt

__author__    = 'Kel Modderman'
__copyright__ = '(C) 2008 Kel Modderman <kel@otaku42.de>'
__license__   = 'GPLv2 or any later version'

from configobj import ConfigObj
from optparse import OptionParser
from subprocess import Popen, PIPE

import atexit
import os
import sys
import shutil
import tempfile


class FLLBuilder:
    def __init__(self):
        self.conf = None
        self.opts = None
        self.pkgs = None
        self.temp = None


    def processOpts(self):
        """Process options."""
        if self.opts.v:
            print 'Processing options...'

        if self.opts.c:
            if not os.path.isfile(self.opts.c):
                raise Exception("configuration file does not exist: %s"
                                % self.opts.c)
            self.opts.c = os.path.abspath(self.opts.c)
        else:
            raise Exception("no configuration files specified on command line")

        if not os.path.isdir(self.opts.b):
            if self.opts.v:
                print " * creating build dir: %s" % self.opts.b
            try:
                os.makedirs(self.opts.b)
            except:
                raise Exception("failed to create build dir: %s" %
                                self.opts.b)
        self.opts.b = os.path.abspath(self.opts.b)

        if not os.path.isdir(self.opts.o):
            if self.opts.v:
                print " * creating output dir: %s" % self.opts.o
            try:
                os.makedirs(self.opts.o)
            except:
                raise Exception("failed to create output dir: %s" %
                                self.opts.o)
        self.opts.o = os.path.abspath(self.opts.o)


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

        p.add_option('-o', '--output', dest = 'o', action = 'store',
                     type = 'string', metavar = '<directory>',
                     help = 'Output directory, where the product of this ' +
                     'program will be generated.')

        p.add_option('-p', '--preserve', dest = 'p', action = 'store_true',
                     help = 'Preserve build directory. Disable automatic ' +
                     'cleanup of the build area at exit.')

        p.add_option('-n', '--non-root', dest = 'n', action = 'store_true',
                     help = 'Start as noon root user (for debugging).')

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

        p.set_defaults(d = False, b = os.getcwd(), g = os.getgid(), n = False,
                       o = os.getcwd(), p = False, s = '/usr/share/fll/',
                       u = os.getuid(), v = True)

        self.opts = p.parse_args()[0]
        self.processOpts()

        if self.opts.d:
            print "opts: ", self.opts


    def processConf(self):
        """Process configuration options."""
        if self.opts.v:
            print 'Processing configuration options...'

        if len(self.conf['chroot'].keys()) < 1:
            raise Exception("no chroots configured in configuarion file")

        for chroot in self.conf['chroot'].keys():
            if not self.conf['chroot'][chroot]:
                raise Exception("no kernel version given for '%s'" % chroot)

        if len(self.conf['apt'].keys()) < 2:
            raise Exception("at least two apt repos must be specified")

        for repo in self.conf['apt'].keys():
            for word in ['label', 'uri', 'suite', 'components']:
                if word not in self.conf['apt'][repo]:
                    raise Exception("no '%s' for apt repo '%s'" % (word, repo))

        if 'profile' not in self.conf['packages']:
            self.conf['packages']['profile'] = 'kde-lite'



    def parseConf(self):
        """Parse build configuration file and return it in a dict."""
        if self.opts.v:
            print "Parsing configuration file..."
            print " * configuration file: %s" % self.opts.c

        self.conf = ConfigObj(self.opts.c, interpolation = 'Template')
        self.processConf()

        if self.opts.d:
            print "conf:", self.conf


    def _profileToLists(self, archs, profile, depdir):
        """Return a dict, arch string as keys and package list as values."""
        list = {}
        for arch in archs:
            list[arch] = []

        if self.opts.v:
            print " * processing profile: %s" % profile

        pfile = ConfigObj(profile)
        if 'packages' in pfile:
            for arch in archs:
                list[arch] = [p.strip() for p in
                              pfile['packages'].splitlines() if p]
                if arch in pfile:
                    list[arch].extend([p.strip() for p in
                                       pfile[arch].splitlines() if p])

        if 'deps' in pfile:
            for dep in [d.strip() for d in pfile['deps'].splitlines() if d]:
                depfile = os.path.join(depdir, dep)
                if not os.path.isfile(depfile):
                    raise Exception("no such dep file: %s" % depfile)
                elif self.opts.v:
                    print " * processing depfile: %s" % depfile

                dfile = ConfigObj(depfile)
                for arch in archs:
                    list[arch].extend([p.strip() for p in
                                       dfile['packages'].splitlines() if p])
                    if arch in dfile:
                        list[arch].extend([p.strip() for p in
                                           dfile[arch].splitlines() if p])

        for arch in archs:
            list[arch].sort()
            if self.opts.v:
                print " * package list for arch: %s" % arch
                for p in list[arch]:
                    print "   > %s" % p

        return list


    def parsePkgs(self):
        """Parse packages profile file(s)."""
        dir = os.path.join(self.opts.s, 'packages')
        deps = os.path.join(dir, 'packages.d')
        file = os.path.join(dir, self.conf['packages']['profile'])

        if not os.path.isfile(file):
            raise Exception("no such package profile file: %s" % file)

        if self.opts.v:
            print "Processing package profile..."

        a = self.conf['chroot'].keys()
        self.pkgs = self._profileToLists(a, file, deps)


    def stageBuildArea(self):
        """Prepare temporary directory to prepare chroots and stage result."""
        if self.opts.v:
            print 'Staging build area...'

        self.temp = tempfile.mkdtemp(prefix = 'fll_', dir = self.opts.b)
        if not self.opts.p:
            atexit.register(self.cleanup)

        for arch in self.conf['chroot'].keys():
            os.mkdir(os.path.join(self.temp, arch))
            if self.opts.v:
                print " * creating directory: %s" % \
                      os.path.join(self.temp, arch)

        os.mkdir(os.path.join(self.temp, 'staging'))
        if self.opts.v:
            print " * creating directory: %s" % \
                  os.path.join(self.temp, 'staging')


    def _umount(self, chrootdir):
        """Umount any mount points in a given chroot directory."""
        # Thanks to update-manager authours for the _umount function
        # http://ftp.ubuntu.com/ubuntu/pool/main/u/update-manager/
        umount_list = []
        for line in open("/proc/mounts"):
            (dev, mnt, fs, options, d, p) = line.split()
            if mnt.startswith(chrootdir):
                umount_list.append(mnt)

        # Reverse sort the mount points based on path length and
        # umount longest -> shortest
        umount_list.sort(key=len)
        umount_list.reverse()

        for mpoint in umount_list:
            if self.opts.v:
                print " * umount %s" % mpoint
            retv = call(["umount", mpoint])
            if retv != 0:
                raise Exception("umount failed for: %s" % mpoint)


    def _nukeDir(self, dir):
        """Nuke directory tree."""
        if self.opts.v:
            print " * nuking directory: %s" % dir
        try:
            shutil.rmtree(dir)
        except:
            raise Exception("unable to remove dir: %s" % dir)


    def cleanup(self):
        """Clean up the build area."""
        for arch in self.conf['chroot'].keys():
            if self.opts.v:
                print "Cleaning up %s chroot..." % arch
            self._umount(os.path.join(self.temp, arch))
            self._nukeDir(os.path.join(self.temp, arch))

        if self.opts.v:
            print 'Cleaning up temp dir...'
        self._nukeDir(self.temp)


if __name__ == "__main__":
    fll = FLLBuilder()
    
    fll.parseOpts()
    fll.parseConf()
    fll.parsePkgs()

    fll.stageBuildArea()
