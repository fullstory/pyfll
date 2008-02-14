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


def ensureUmounted(chroot, verbose = False):
    """Umount common mount points in a chroot dir."""
    for dir in ['proc/sys/fs/binfmt_misc/status', 'proc', 'dev/pts', 'dev',
                'sys']:
        if os.path.ismount(os.path.join(chroot, dir)):
            if verbose:
                print " * umounting: %s" % os.path.join(chroot, dir)
            retv = call(["umount", os.path.join(chroot, dir)])
            if retv != 0:
                raise Exception("umount failed for dir: %s" %
                                os.path.join(chroot, dir))


def nukeDir(dir, verbose = False):
    """Nuke dir tree."""
    if not os.path.isdir(dir):
        return

    for d in os.listdir(dir):
        if not os.path.isdir(os.path.join(dir, d)):
            continue
        try:
            ensureUmounted(os.path.join(dir, d), verbose = verbose)
        except:
            raise Exception("failed to umount virtual filesystems in dir: %s" %
                            os.path.join(dir, d))

    if verbose:
        print " * nuking directory: %s" % dir
    try:
        shutil.rmtree(dir)
    except:
        raise Exception("unable to remove dir: %s" % dir)


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
        p = OptionParser(usage = '%prog -c <config file> [-b <directory> ' +
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

        p.add_option('-v', '--verbose', dest = 'v', action = 'store_true',
                     help = 'Enable verbose mode. All messages will be ' +
                     'generated, such as announcing current operation.')

        p.set_defaults(d = False, b = os.getcwd(), o = os.getcwd(), p = False,
                       s = '/usr/share/fll/', v = True)

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


    def parsePkgs(self):
        """Parse packages profile file(s)."""
        pass


    def stageBuildArea(self):
        self.temp = tempfile.mkdtemp(prefix = 'fll_', dir = self.opts.b)
        if not self.opts.p:
            atexit.register(self.cleanup)
        if self.opts.v:
            print " * creating directory: %s" % self.temp

        for arch in self.conf['chroot'].keys():
            os.mkdir(os.path.join(self.temp, arch))

        os.mkdir(os.path.join(self.temp, 'staging'))


    def cleanup(self):
        if self.opts.v:
            print 'Cleaning up...'
        nukeDir(self.temp, verbose = self.opts.v)


    def main(self):
        # Init()
        self.parseOpts()
        self.parseConf()
        self.parsePkgs()
        # Build()
        self.stageBuildArea()


if __name__ == "__main__":
    try:
        FLLBuilder().main()
    except SystemExit:
        pass
    except Exception, e:
        print >>sys.stderr, 'Error:', str(e)
        sys.exit(1)
