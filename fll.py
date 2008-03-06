#!/usr/bin/python -tt

__author__    = 'Kel Modderman'
__copyright__ = '(C) 2008 Kel Modderman <kel@otaku42.de>'
__license__   = 'GPLv2 or any later version'

from configobj import ConfigObj
from optparse import OptionParser
from subprocess import *

import apt_pkg
import atexit
import fileinput
import glob
import logging
import os
import sys
import shutil
import tempfile
import time


class Error(Exception):
    '''A generic error handler that does nothing.'''
    pass


class FLLBuilder:
    conf = None
    opts = None
    pkgs = None
    temp = None

    stamp = None
    stamp_safe = None

    log = logging.getLogger('log')
    log.setLevel(logging.DEBUG)

    env = {'LANGUAGE': 'C', 'LC_ALL': 'C', 'LANG' : 'C', 'HOME': '/root',
           'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'SHELL': '/bin/bash',
           'DEBIAN_FRONTEND': 'noninteractive', 'DEBIAN_PRIORITY': 'critical',
           'DEBCONF_NOWARNINGS': 'yes'}

    diverts = ['/sbin/modprobe', '/usr/sbin/update-initramfs']


    def __filterList(self, list, dup_warn = True):
        '''Return a list containing no duplicate items given a list that
        may have duplicate items.'''

        d = {}
        for l in list:
            if l in d and dup_warn:
                self.log.debug('duplicate: %s' % l)
            else:
                d[l] = True

        list = d.keys()
        list.sort()

        return list


    def __lines2list(self, lines):
        '''Return a list of stripped strings given a group of line
        separated strings'''
        return [s.strip() for s in lines.splitlines()
                if s and not s.lstrip().startswith('#')]


    def __isexecutable(self, file):
        '''Return True is file is executable, False otherwise.'''
        if os.access(file, os.X_OK) and not os.path.isdir(file):
            return True
        else:
            return False


    def __prepDir(self, dir):
        '''Set up working directories.'''
        if not os.path.isdir(dir):
            try:
                os.makedirs(dir)
                os.chown(dir, self.opts.u, self.opts.g)
            except:
                self.log.exception('failed to create dir: %s' % dir)
                raise Error

        return os.path.abspath(dir)


    def __initLogger(self, lvl):
        '''Set up the logger.'''
        fmt = logging.Formatter('%(asctime)s %(levelname)-5s - %(message)s')
        out = logging.StreamHandler()
        out.setFormatter(fmt)
        out.setLevel(lvl)
        self.log.addHandler(out)


    def __initLogFile(self, file):
        '''Set up a log file.'''
        file = os.path.abspath(file)
        dir = os.path.dirname(file)
        self.__prepDir(dir)

        try:
            fmt = logging.Formatter('%(asctime)s %(levelname)-5s ' +
                                     '%(message)s')
            logfile = logging.FileHandler(filename = file, mode = 'w')
            logfile.setFormatter(fmt)
            logfile.setLevel(logging.DEBUG)
            self.log.addHandler(logfile)
            os.chown(file, self.opts.u, self.opts.g)
        except:
            self.log.exception('failed to setup logfile')
            raise Error


    def _processOpts(self):
        '''Process options.'''
        if self.opts.d:
            self.__initLogger(logging.DEBUG)
        else:
            self.__initLogger(logging.INFO)

        if self.opts.l:
            self.__initLogFile(self.opts.l)

        if self.opts.c:
            if os.path.isfile(self.opts.c):
                self.opts.c = os.path.abspath(self.opts.c)
            else:
                self.log.critical('configuration file does not exist: %s' %
                                  self.opts.c)
                raise Error
        else:
            self.log.critical('no config file specified on command line')
            raise Error

        if self.opts.s:
            if not os.path.isdir(self.opts.s):
                self.log.critical('share directory not exist: %s' %
                                  self.opts.s)
                raise Error

        self.opts.s = os.path.abspath(self.opts.s)

        if self.opts.o:
            self.opts.o = self.__prepDir(self.opts.o)

        if self.opts.b:
            self.opts.b = self.__prepDir(self.opts.b)


    def parseOpts(self):
        '''Parse command line arguments.'''
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
                     help = 'Log debug output to file. Note that when ' +
                     'logging is enabled, output to the console is buffered.')

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

        p.set_defaults(b = None, B = False, d = False, g = os.getgid(),
                       l = None, n = False, o = None, p = False,
                       q = False, s = '/usr/share/fll/', u = os.getuid(),
                       v = False)

        self.opts = p.parse_args()[0]
        self._processOpts()


    def _processDefaults(self, d):
        '''Form a distro-defaults data structure to be written to
        /etc/default/distro of each chroot, and used for release name.'''
        for k in ['FLL_DISTRO_NAME', 'FLL_IMAGE_DIR', 'FLL_IMAGE_FILE',
                  'FLL_MEDIA_NAME', 'FLL_MOUNTPOINT', 'FLL_LIVE_USER',
                  'FLL_LIVE_USER_GROUPS']:
            if not d.get(k):
                self.log.critical("%s' is required in 'distro' section " % k +
                                  "of build conf")
                raise Error

        for k in ['FLL_DISTRO_NAME', 'FLL_IMAGE_DIR', 'FLL_IMAGE_FILE',
                  'FLL_LIVE_USER', 'FLL_DISTRO_CODENAME_SAFE',
                  'FLL_DISTRO_CODENAME_REV_SAFE']:
            if not d.get(k):
                continue
            if not d[k].isalnum():
                self.log.critical("'%s' is not alphanumeric: %s" % (k, d[k]))
                raise Error
            elif d[k].find(' ') >= 0:
                self.log.critical("'%s' contains whitespace: %s" % (k, d[k]))
                raise Error

        if d.get('FLL_DISTRO_VERSION') and \
           d['FLL_DISTRO_VERSION'] != 'snapshot':
            if d.get('FLL_DISTRO_CODENAME_SAFE'):
                self.log.critical("'FLL_DISTRO_VERSION' is set, but " +
                                  "'FLL_DISTRO_CODENAME_SAFE' is not")
                raise Error

            for k in ['FLL_DISTRO_CODENAME', 'FLL_DISTRO_CODENAME_REV']:
                safe = k + '_SAFE'
                if d.get(safe) and not d.get(k):
                    d[k] = d[safe]

            self.stamp = self.stamp_safe = ' '.join([d['FLL_DISTRO_NAME'],
                                                     d['FLL_DISTRO_VERSION']])
            if d['FLL_DISTRO_CODENAME_REV']:
                self.stamp += ' - %s' % d['FLL_DISTRO_CODENAME']
                self.stamp += ' %s -' % d['FLL_DISTRO_CODENAME_REV']
                self.stamp_safe += ' %s' % d['FLL_DISTRO_CODENAME_SAFE']
                self.stamp_safe += '_%s ' % d['FLL_DISTRO_CODENAME_REV_SAFE']
            else:
                self.stamp += ' %s -' % d['FLL_DISTRO_CODENAME']
                self.stamp_safe += ' %s' % d['FLL_DISTRO_CODENAME_SAFE']

            self.stamp += ' %s' % self.conf['packages']['profile']
            self.stamp_safe += ' %s' % self.conf['packages']['profile']
        else:
            d['FLL_DISTRO_VERSION'] = 'snapshot'

            self.stamp = self.stamp_safe = ' '.join([d['FLL_DISTRO_NAME'],
                                                     d['FLL_DISTRO_VERSION']])
            self.stamp += ' - %s' % self.conf['packages']['profile']
            self.stamp_safe += ' %s' % self.conf['packages']['profile']

        self.stamp_safe = '-'.join(self.stamp_safe.split())


    def _processConf(self):
        '''Process configuration options.'''
        if not self.conf.get('archs'):
            host_arch = Popen(['dpkg', '--print-architecture'],
                              stdout=PIPE).communicate()[0].rstrip()
            self.conf['archs'] = {host_arch: dict()}
            self.log.debug('arch: %s' % host_arch)

        for arch in self.conf['archs'].keys():
            if 'linux' not in self.conf['archs'][arch]:
                if arch == 'i386':
                    cpu = '686'
                else:
                    cpu = arch

                if os.path.isfile('/etc/sidux-version'):
                    linux = '2.6-sidux-' + cpu
                else:
                    linux = '2.6-' + cpu

                self.conf['archs'][arch].setdefault('linux', linux)
            self.log.debug("linux: %s" % self.conf['archs'][arch]['linux'])

        if len(self.conf['repos'].keys()) < 1:
            self.log.critical('no apt repos were specified in build config')
            raise Error

        if 'debian' not in self.conf['repos']:
            self.log.critical('debian repo not configured in build config')
            raise Error

        for repo in self.conf['repos'].keys():
            for word in ['label', 'uri', 'suite', 'components']:
                if word not in self.conf['repos'][repo]:
                    self.log.critical("no '%s' for apt repo '%s'" %
                                     (word, repo))
                    raise Error

        if 'profile' not in self.conf['packages']:
            self.conf['packages']['profile'] = 'kde-lite'
        self.log.debug('profile: %s' %
                       self.conf['packages']['profile'])

        if 'i18n' not in self.conf['packages'] or \
           not self.__lines2list(self.conf['packages']['i18n']):
            self.conf['packages']['i18n'] = 'en_US'
        i18n = self.__lines2list(self.conf['packages']['i18n'])
        self.log.debug('i18n: %s' % ' '.join(i18n))

        if not 'options' in self.conf:
            self.conf['options'] = {}

        if self.conf['options'].get('build_dir'):
            if not self.opts.b:
                dir = self.conf['options']['build_dir']
                self.opts.b = self.__prepDir(dir)
        else:
            if not self.opts.b:
                self.opts.b = self.__prepDir(os.getcwd())

        if self.conf['options'].get('output_dir'):
            if not self.opts.o:
                dir = self.conf['options']['output_dir']
                self.opts.o = self.__prepDir(dir)
        else:
            if not self.opts.o:
                self.opts.o = self.__prepDir(os.getcwd())

        if self.conf['options'].get('build_log'):
            if not self.opts.l:
                self.opts.l = self.conf['options']['build_log']
                self.__initLogFile(self.opts.l)

        if self.conf['options'].get('http_proxy'):
            self.env['http_proxy'] = self.conf['options']['http_proxy']

        if self.conf['options'].get('ftp_proxy'):
            self.env['ftp_proxy'] = self.conf['options']['ftp_proxy']

        self.conf['options'].setdefault('apt_recommends', 'no')
        self.conf['options'].setdefault('media_include', None)

        if 'distro' in self.conf:
                self._processDefaults(self.conf['distro'])
                self.log.debug('distro-defaults:')
                for k, v in self.conf['distro'].items():
                    self.log.debug('%s="%s"' % (k, v))
        else:
            self.log.critical('distro section not found in build config')
            raise Error


    def parseConf(self):
        '''Parse build configuration file and return it in a dict.'''
        self.log.info('reading configuration file...')

        self.conf = ConfigObj(self.opts.c)
        self._processConf()


    def _processPkgProfile(self, arch, profile, dir):
        '''Return a dict, arch string as keys and package list as values.'''
        pkgs = {'debconf': [], 'list': []}

        linux_meta = ['linux-image', 'linux-headers']
        kvers = self.conf['archs'][arch]['linux']
        pkgs['list'].extend(['-'.join([l, kvers]) for l in linux_meta])

        self.log.debug('processing package profile for %s: %s' %
                       (arch, os.path.basename(profile)))

        pfile = ConfigObj(profile)

        if 'desc' in pfile:
            for l in self.__lines2list(pfile['desc']):
                self.log.debug('  %s' % l)

        if 'repos' in pfile:
            for r in self.__lines2list(pfile['repos']):
                if r not in self.conf['repos']:
                    self.log.critical("'%s' repo is required " % r +
                                      "by package module '%s'" %
                                      os.path.basename(profile))
                    raise Error

        if 'debconf' in pfile:
            self.log.debug("debconf:")
            for d in self.__lines2list(pfile['debconf']):
                pkgs['debconf'].append(d)
                self.log.debug('  %s', d)

        if 'debconf' in self.conf['packages']:
            self.log.debug("debconf (config):")
            for d in self.__lines2list(self.conf['packages']['debconf']):
                pkgs['debconf'].append(d)
                self.log.debug('  %s' % d)

        if 'packages' in pfile:
            self.log.debug("packages:")
            for p in self.__lines2list(pfile['packages']):
                pkgs['list'].append(p)
                self.log.debug('  %s' % p)

        if 'packages' in self.conf['packages']:
            self.log.debug("packages (config):")
            for p in self.__lines2list(self.conf['packages']['packages']):
                pkgs['list'].append(p)
                self.log.debug('  %s' % p)

        if arch in pfile:
            self.log.debug("packages (%s):" % arch)
            for p in self.__lines2list(pfile[arch]):
                pkgs['list'].append(p)
                self.log.debug('  %s' % p)

        deps = ['essential']
        if 'deps' in pfile:
            self.log.debug("deps:")
            for dep in self.__lines2list(pfile['deps']):
                deps.append(dep)
                self.log.debug('  %s' % dep)

        if 'deps' in self.conf['packages']:
            self.log.debug("deps (config):")
            for dep in self.__lines2list(self.conf['packages']['deps']):
                deps.append(dep)
                self.log.debug('  %s' % dep)

        self.log.debug('---')

        for dep in deps:
            depfile = os.path.join(dir, 'packages.d', dep)

            if not os.path.isfile(depfile):
                self.log.critical("no such dep file: %s" % depfile)
                raise Error

            self.log.debug('processing dependency file: %s' %
                           os.path.basename(depfile))

            dfile = ConfigObj(depfile)

            if 'desc' in dfile:
                for l in self.__lines2list(dfile['desc']):
                    self.log.debug('  %s' % l)

            if 'repos' in dfile:
                for repo in self.__lines2list(dfile['repos']):
                    if repo not in self.conf['repos']:
                        self.log.critical("'%s' repo is required " % r +
                                          "by package module '%s'" %
                                          os.path.basename(depfile))
                        raise Error

            if 'debconf' in dfile:
                self.log.debug("debconf:")
                for d in self.__lines2list(dfile['debconf']):
                    pkgs['debconf'].append(d)
                    self.log.debug('  %s' % d)

            if 'packages' in dfile:
                self.log.debug("packages:")
                for p in self.__lines2list(dfile['packages']):
                    pkgs['list'].append(p)
                    self.log.debug('  %s' % p)

            if arch in dfile:
                self.log.debug("packages (%s):" % arch)
                for p in self.__lines2list(dfile[arch]):
                    pkgs['list'].append(p)
                    self.log.debug('  %s' % p)

            self.log.debug('---')

        self.log.debug('package summary for %s:' % arch)
        pkgs['list'].sort()
        for p in pkgs['list']:
            self.log.debug('  %s' % p)

        self.log.debug('debconf summary for %s:' % arch)
        pkgs['debconf'].sort()
        for d in pkgs['debconf']:
            self.log.debug('  %s' % d)

        pkgs['list'] = self.__filterList(pkgs['list'])

        return pkgs


    def parsePkgProfile(self):
        '''Parse packages profile file(s).'''
        self.log.info('processing package profile (%s)...' %
                      self.conf['packages']['profile'])

        dir = os.path.join(self.opts.s, 'packages')
        file = os.path.join(dir, self.conf['packages']['profile'])

        if not os.path.isfile(file):
            self.log.critical('no such package profile file: %s' % file)
            raise Error

        self.pkgs = {}
        for arch in self.conf['archs'].keys():
            self.pkgs[arch] = self._processPkgProfile(arch, file, dir)


    def _stageMedia(self, point, dir, fnames):
        '''Copy content from a directory to media staging area.'''
        orig, dest = point
        dirname = dir.replace(orig, '', 1).lstrip('/')

        remove = []
        for f in fnames:
            if f.startswith('.') or f.endswith('~'):
                remove.append(f)
            elif os.path.isdir(os.path.join(dir, f)) and \
                 f == 'boot':
                remove.append(f)
            elif os.path.isdir(os.path.join(dir, f)):
                if not os.path.isdir(os.path.join(dest, dirname, f)):
                    os.mkdir(os.path.join(dest, dirname, f))
            else:
                if not os.path.isfile(os.path.join(dest, dirname, f)):
                    shutil.copy(os.path.join(dir, f),
                                os.path.join(dest, dirname))

        for r in remove:
            fnames.remove(r)


    def stageBuildArea(self):
        '''Prepare temporary directory to prepare chroots and stage result.'''
        self.log.debug('preparing build area...')

        self.temp = tempfile.mkdtemp(prefix = 'fll_', dir = self.opts.b)
        os.chown(self.temp, self.opts.u, self.opts.g)

        atexit.register(self.cleanup)

        stage = os.path.join(self.temp, 'staging')
        os.mkdir(stage)
        os.mkdir(os.path.join(stage, 'boot'))
        os.mkdir(os.path.join(stage, self.conf['distro']['FLL_IMAGE_DIR']))

        if self.conf['options']['media_include']:
            media_include = self.conf['options']['media_include']
            if os.path.isdir(media_include):
                try:
                    os.path.walk(media_include, self._stageMedia,
                                 (media_include, stage))
                except:
                    self.log.exception('problem copying media_include ' +
                                       'contents to staging dir')
                    raise Error


    def _mount(self, chroot):
        '''Mount virtual filesystems in a shoort dir.'''
        virtfs = {'devpts': 'dev/pts', 'proc': 'proc'}

        for v in virtfs.items():
            cmd = ['mount', '-t', v[0], 'fll-' + v[0],
                   os.path.join(chroot, v[1])]

            retv = call(cmd)
            if retv != 0:
                self.log.critical('failed to mount chroot %s' % v[0])
                raise Error


    def _umount(self, chrootdir):
        '''Umount any mount points in a given chroot directory.'''
        umount_list = []
        for line in open('/proc/mounts'):
            (dev, mnt, fs, options, d, p) = line.split()
            if mnt.startswith(chrootdir):
                umount_list.append(mnt)

        umount_list.sort(key=len)
        umount_list.reverse()

        for mpoint in umount_list:
            retv = call(['umount', mpoint])
            if retv != 0:
                self.log.critical('umount failed for: %s' % mpoint)
                raise Error


    def _nuke(self, dir):
        '''Nuke directory tree.'''
        if os.path.isdir(dir):
            self.log.debug('nuking directory: %s' % dir)
            try:
                shutil.rmtree(dir)
            except:
                self.log.exception('unable to remove %s' % dir)
                raise Error
        else:
            self.log.debug('not nuking directory (does not exist): %s' % dir)


    def _nukeChroot(self, arch):
        '''Convenience function to nuke chroot given by arch name.'''
        if not self.opts.p:
            self.log.info('nuking %s chroot...' % arch)
            chroot = os.path.join(self.temp, arch)
            self._umount(chroot)
            self._nuke(chroot)


    def cleanup(self):
        '''Clean up the build area.'''
        self.log.info('cleaning up...')

        for arch in self.conf['archs'].keys():
            dir = os.path.join(self.temp, arch)
            if os.path.isdir(dir):
                self.log.debug('cleaning up %s chroot...' % arch)
                self._umount(dir)
                if not self.opts.p:
                    self._nuke(dir)

        if not self.opts.p:
            self._nuke(self.temp)


    def __execLogged(self, cmd, check_returncode):
        self.log.debug(' '.join(cmd))

        try:
            c = Popen(cmd, stdout = PIPE, stderr = STDOUT, env = self.env,
                      close_fds = True)
        except KeyboardInterrupt:
            raise Error
        except:
            self.log.exception('problem executing command')
            raise Error
        else:
            for line in c.communicate()[0].splitlines():
                if self.opts.q:
                    self.log.debug(line.rstrip())
                else:
                    self.log.info(line.rstrip())

            if c.returncode != 0 and check_returncode:
                self.log.critical('command failed with return value: %d' %
                                  c.returncode)
                raise Error


    def __exec(self, cmd, check_returncode):
        '''Execute subprocess without buffering output in a pipe.'''
        self.log.debug(' '.join(cmd))

        try:
            if self.opts.q:
                retv = call(cmd, stdout = open(os.devnull, 'w'),
                            stderr = STDOUT, env = self.env,
                            close_fds = True)
            else:
                retv = call(cmd, env = self.env, close_fds = True)
        except KeyboardInterrupt:
            raise Error
        except:
            self.log.exception('problem executing command')
            raise Error
        else:
            if retv != 0 and check_returncode:
                self.log.critical('command failed with return value: %d' %
                                  retv)
                raise Error


    def _execCmd(self, cmd, check_returncode = True):
        '''Convenience wrapper for subprocess execution.'''
        if self.opts.l:
            self.__execLogged(cmd, check_returncode)
        else:
            self.__exec(cmd, check_returncode)


    def _execInChroot(self, arch, args, check_returncode = True):
        '''Run command in a chroot.'''
        chroot = os.path.join(self.temp, arch)
        cmd = ['chroot', chroot]
        cmd.extend(args)

        self._mount(chroot)

        if self.opts.l:
            self.__execLogged(cmd, check_returncode)
        else:
            self.__exec(cmd, check_returncode)

        self._umount(chroot)


    def _aptGetInstall(self, arch, pkgs):
        '''An apt-get wrapper.'''
        aptget = ['apt-get', '--yes']

        if self.conf['options']['apt_recommends'] == 'no':
            aptget.extend(['-o', 'APT::Install-Recommends=0'])
        if self.opts.d:
            aptget.extend(['-o', 'APT::Get::Show-Versions=1'])

        aptget.append('install')
        aptget.extend(pkgs)

        self._execInChroot(arch, aptget)


    def _bootStrap(self, arch, verbosity = None, dir = None, mirror = None,
                   flavour = 'minimal', suite = 'sid', ):
        '''Bootstrap a debian system with cdebootstrap.'''
        if self.opts.d:
            verbosity = '--debug'
        elif self.opts.v:
            verbosity = '--verbose'

        debian = self.conf['repos']['debian']
        if 'cached' in debian and debian['cached']:
            mirror = debian['cached']
        else:
            mirror = debian['uri']

        dir = os.path.join(self.temp, arch)
        cmd = ['cdebootstrap', '--arch=%s' % arch, '--include=apt-utils',
               '--flavour=%s' % flavour, suite, dir, mirror]

        if verbosity:
            cmd.append(verbosity)

        self.log.info('bootstrapping debian %s...' % arch)
        self._execCmd(cmd)


    def _writeAptLists(self, arch, cached = False, src_uri = False):
        '''Write apt source lists to /etc/apt/sources.list.d/*.'''
        chroot = os.path.join(self.temp, arch)
        for repo in self.conf['repos'].keys():
            r = self.conf['repos'][repo]
            file = os.path.join(chroot, 'etc/apt/sources.list.d',
                                r['label'] + '.list')

            if os.path.isfile(os.path.join(chroot, 'etc/apt/sources.list')):
                s = open(os.path.join(chroot, 'etc/apt/sources.list'), 'a')
                s.write('#   %-74s#\n' % file.replace(chroot, '', 1))
                s.close()

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
            self.log.debug('%s: %s', repo, l.rstrip())

            list = open(file, 'w')
            list.write('deb ' + l)
            if not src_uri or self.opts.B:
                list.write('#deb-src ' + l)
            else:
                list.write('deb-src ' + l)
            list.close()

        if os.path.isfile(os.path.join(chroot, 'etc/apt/sources.list')):
            s = open(os.path.join(chroot, 'etc/apt/sources.list'), 'a')
            s.write('# ' * 39 + '#\n')
            s.close()


    def _primeApt(self, arch):
        '''Prepare apt for work in each build chroot.'''
        self.log.info('preparing apt in %s chroot...' % arch)
        chroot = os.path.join(self.temp, arch)

        self.log.debug('removing sources.list from %s chroot' % arch)
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
            cmd = 'apt-get --allow-unauthenticated --yes install'.split()
            cmd.extend(keyrings)
            self._execInChroot(arch, cmd)

        gpgkeys = []
        for repo in self.conf['repos'].keys():
            r = self.conf['repos'][repo]
            if 'gpgkey' in r:
                self.log.debug('importing gpg key for %s' % r['label'])
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
                                       check_returncode = False)
                else:
                    cmd = 'gpg --keyserver wwwkeys.eu.pgp.net '
                    cmd += '--recv-keys ' + r['gpgkey']
                    self._execInChroot(arch, cmd.split(),
                                       check_returncode = False)

        if len(gpgkeys) > 0:
            cmd = 'apt-key add /root/.gnupg/pubring.gpg'
            self._execInChroot(arch, cmd.split())

        self._execInChroot(arch, 'apt-get update'.split())

        apt_pkg.InitConfig()
        apt_pkg.Config.Set('RootDir', chroot)
        apt_pkg.Config.Set('APT::Architecture', arch)
        apt_pkg.InitSystem()


    def _dpkgAddDivert(self, arch):
        """Divert some facilities and replace temporaily with /bin/true (or
        some other more appropiate facility."""
        chroot = os.path.join(self.temp, arch)
        for d in self.diverts:
            self.log.debug("diverting %s" % d)
            cmd = 'dpkg-divert --add --local --divert ' + d + '.REAL --rename '
            cmd += d
            self._execInChroot(arch, cmd.split())
            os.symlink('/bin/true', os.path.join(chroot, d.lstrip('/')))


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
        '''Some file templates.'''
        chroot = os.path.join(self.temp, arch)
        try:
            f = open(os.path.join(chroot, file.lstrip('/')), 'w')
            self.log.debug('writing file: %s' % file)
        except:
            self.log.exception('failed to open file for writing: %s' % file)
            raise Error

        if file == '/etc/default/distro':
            d = self.conf['distro'].keys()
            d.sort()
            for k in d:
                if k.startswith('FLL_DISTRO_CODENAME'):
                    continue
                elif k == 'FLL_MOUNTPOINT':
                    f.write('%s="%s"\n' % (k, self.conf['distro'][k]))
                    test = '$([ -d "$%s" ] && echo live || echo installed)' % k
                    f.write('%s="%s"\n' % ('FLL_DISTRO_MODE', test))
                elif k == 'FLL_IMAGE_FILE':
                    image_file = self.conf['distro'][k]
                    if arch == 'i386':
                        image_file += '.686'
                    else:
                        image_file += '.%s' % arch
                    f.write('%s="%s"\n' % (k, image_file))
                    f.write('%s="$%s/$%s"\n' % ('FLL_IMAGE_LOCATION',
                                                'FLL_IMAGE_DIR', k))
                else:
                    f.write('%s="%s"\n' % (k, self.conf['distro'][k]))
        elif file == '/etc/fstab':
            f.write('# /etc/fstab: static file system information\n')
        elif file == '/etc/hostname':
            hostname = self.conf['distro']['FLL_DISTRO_NAME']
            f.write(hostname + '\n')
        elif file == '/etc/hosts':
            hostname = self.conf['distro']['FLL_DISTRO_NAME']
            f.write('127.0.0.1\tlocalhost\n')
            f.write('127.0.0.1\t' + hostname + '\n\n')
            f.write('# The following lines are for IPv6 capable hosts\n')
            f.write('::1     ip6-localhost ip6-loopback\n')
            f.write('fe00::0 ip6-localnet\n')
            f.write('ff00::0 ip6-mcastprefix\n')
            f.write('ff02::1 ip6-allnodes\n')
            f.write('ff02::2 ip6-allrouters\n')
            f.write('ff02::3 ip6-allhosts\n')
        elif file == '/etc/kernel-img.conf':
            f.write('do_bootloader = No\n')
            f.write('warn_initrd   = No\n')
        elif file == '/etc/network/interfaces':
            f.write('# /etc/network/interfaces - ')
            f.write('configuration file for ifup(8), ifdown(8)\n\n')
            f.write('# The loopback interface\n')
            f.write('auto lo\n')
            f.write('iface lo inet loopback\n')

        f.close()


    def _defaultEtc(self, arch):
        '''Initial creation of conffiles required in chroot.'''
        self._writeFile(arch, '/etc/fstab')
        self._writeFile(arch, '/etc/hostname')
        self._writeFile(arch, '/etc/kernel-img.conf')
        self._writeFile(arch, '/etc/network/interfaces')


    def _finalEtc(self, arch):
        '''Final editing of conffiles in chroot.'''
        chroot = os.path.join(self.temp, arch)

        self.log.debug('stamping distro version')
        distro_version = '%s-version' % \
                         self.conf['distro']['FLL_DISTRO_NAME'].lower()
        distro_version = os.path.join(chroot, 'etc', distro_version)
        timestamp = time.strftime('%Y%m%d%H%M', time.gmtime())
        f = open(distro_version, 'w')
        f.write('%s - (%s)\n' % (self.stamp, timestamp))
        f.close()
        os.chmod(distro_version, 0444)

        self._writeFile(arch, '/etc/default/distro')
        self._writeFile(arch, '/etc/hosts')
        self._writeFile(arch, '/etc/motd.tail')
        self._writeFile(arch, '/etc/resolv.conf')

        self.log.debug('writing final apt sources.list(s)')
        slist = os.path.join(chroot, 'etc/apt/sources.list')
        slist_new = os.path.join(self.opts.s, 'data/sources.list')
        shutil.copy(slist_new, os.path.dirname(slist))
        self._writeAptLists(arch)

        self.log.debug('add grub hooks to /etc/kernel-img.conf')
        f = open(os.path.join(chroot, 'etc/kernel-img.conf'), 'a')
        f.write('postinst_hook = /usr/sbin/update-grub\n')
        f.write('postrm_hook   = /usr/sbin/update-grub\n')
        f.close()

        self.log.debug('substituting /etc/inittab for passwd-less login')
        inittab = os.path.join(chroot, 'etc/inittab')
        os.unlink(inittab)
        inittab_live = os.path.join(self.opts.s, 'data', 'inittab')
        shutil.copy(inittab_live, os.path.dirname(inittab))


    def _preseedDebconf(self, arch):
        '''Preseed debcong with values read from package lists.'''
        chroot = os.path.join(self.temp, arch)

        if 'debconf' in self.pkgs[arch] and self.pkgs[arch]['debconf']:
            self.log.info('preseeding debconf in %s chroot...' % arch)
            debconf = open(os.path.join(chroot, 'tmp',
                                        'fll_debconf_selections'), 'w')
            debconf.writelines([d + '\n' for d in self.pkgs[arch]['debconf']])
            debconf.close()

            cmd = 'debconf-set-selections '
            if self.opts.v:
                cmd += '--verbose '
            cmd += '/tmp/fll_debconf_selections'

            self._execInChroot(arch, cmd.split())


    def _detectLinuxVersion(self, chroot):
        '''Return version string of a singularly installed linux-image.'''
        kvers = [f.replace('vmlinuz-', '', 1) for f in
                 os.listdir(os.path.join(chroot, 'boot'))
                 if f.startswith('vmlinuz-')]

        if len(kvers) > 0:
            kvers.sort()
            return kvers

        self.log.critical('failed to detect linux version installed in ' +
                          '%s chroot' % arch)
        raise Error


    def _detectLocalePkgs(self, wanted, cache):
        '''Provide automated detection for extra i18n packages.'''
        i18n = self.__lines2list(self.conf['packages']['i18n'])
        self.log.info('detecting i18n packages for %s...' % ' '.join(i18n))

        i18n_module = ConfigObj(os.path.join(self.opts.s, 'packages',
                                             'packages.d', 'i18n'))
        self.log.debug('i18n_module:')
        self.log.debug(i18n_module)

        i18n_dict = {}
        for i in i18n:
            i = i.lower().replace('_', '-')
            i18n_dict[i] = True
            if i.find('-') >= 0:
                i18n_dict[i[i.find('-') + 1:]] = True
                i18n_dict[i[:i.find('-')]] = True
                if not i.startswith('en'):
                    i18n_dict['i18n'] = True
        self.log.debug('i18n_dict:')
        self.log.debug(i18n_dict)

        i18n_pkgs_list = []
        for p in i18n_module.keys():
            if p not in wanted:
                continue
            for pkg in self.__lines2list(i18n_module[p]):
                i18n_pkgs_list.extend([('-'.join([pkg, i]), True)
                                       for i in i18n_dict.keys()])

        i18n_pkgs_dict = dict(i18n_pkgs_list)
        self.log.debug('i18n_pkgs_dict:')
        self.log.debug(i18n_pkgs_dict)

        i18n_list = [p.Name for p in cache.Packages
                     if p.Name in i18n_pkgs_dict and p.VersionList]
        self.log.debug('i18n_list:')
        self.log.debug(i18n_list)
        return i18n_list


    def _detectRecommendedPkgs(self, wanted, cache):
        '''Provide automated detection for packages in recommends whitelist.'''
        if self.conf['options']['apt_recommends'] == 'yes':
            return []

        self.log.info('detecting whitelisted recommended packages...')
        rec_module = ConfigObj(os.path.join(self.opts.s, 'packages',
                                            'packages.d', 'recommends'))
        rec_dict = dict([(p, True) for p in
                         self.__lines2list(rec_module['packages'])])
        self.log.debug('rec_dict:')
        self.log.debug(rec_dict)

        rec_list = []
        for p in wanted.keys():
            if not p in rec_dict:
                continue
            package = cache[p]
            current = package.CurrentVer
            if not current:
                versions = package.VersionList
                if not versions:
                    continue
                version = versions[0]
                for other_version in versions:
                    if apt_pkg.VersionCompare(version.VerStr,
                                              other_version.VerStr) < 0:
                        version = other_version
                current = version

            depends = current.DependsList
            list = depends.get('Recommends', [])
            for dependency in list:
                name = dependency[0].TargetPkg.Name
                dep = cache[name]
                if dep.CurrentVer:
                    continue
                rec_list.append(dep.Name)

        self.log.debug('rec_list:')
        self.log.debug(rec_list)
        return rec_list


    def _detectLinuxModulePkgs(self, arch, cache):
        '''Provide automated detection for extra linux module packages.'''
        self.log.debug('detecting linux modules packages')
        kvers = '-modules-' + self.conf['archs'][arch]['linux']
        kvers_list = [p.Name for p in cache.Packages
                      if p.Name.endswith(kvers) and p.VersionList]
        self.log.debug('kvers_list:')
        self.log.debug(kvers_list)
        return kvers_list


    def __getSourcePkg(self, pkg, depcache, records):
        """ get the source package name of a given package """
        version = depcache.GetCandidateVer(pkg)

        if not version:
            return None
        file, index = version.FileList.pop(0)
        records.Lookup((file, index))

        if records.SourcePkg != "":
            srcpkg = records.SourcePkg
        else:
            srcpkg = pkg.Name
        return srcpkg


    def _collectManifest(self, arch):
        '''Collect package and source package URI information from each
        chroot.'''
        chroot = os.path.join(self.temp, arch)
        self.log.info('collecting package manifest for %s...' % arch)

        cache = apt_pkg.GetCache()
        records = apt_pkg.GetPkgRecords(cache)
        depcache = apt_pkg.GetDepCache(cache)
        depcache.Init()

        manifest = dict([(p.Name, p.CurrentVer.VerStr)
                         for p in cache.Packages if p.CurrentVer])
        self.pkgs[arch]['manifest'] = manifest

        if self.opts.B:
            return

        self.log.info('querying source package URIs for %s...' % arch)

        sources = apt_pkg.GetPkgSrcRecords()
        sources.Restart()

        packages = manifest.keys()
        packages.sort()
        srcpkg_seen = {}
        uris = []
        for p in packages:
            for k in self._detectLinuxVersion(chroot):
                if p.endswith('-modules-' + k):
                    if p.startswith('virtualbox-ose-guest'):
                        p = 'virtualbox-ose'
                    else:
                        p = p[:p.find('-modules-' + k)]
                    p += '-source'

            if p.startswith('cdebootstrap-helper'):
                continue

            srcpkg = self.__getSourcePkg(cache[p], depcache, records)
            if not srcpkg:
                self.log.critical('failed to lookup srcpkg name for %s' % p)
                raise Error
            self.log.debug('%s -> %s' % (p, srcpkg))

            if srcpkg in srcpkg_seen:
                self.log.debug('already processed %s, skipping...' % srcpkg)
                continue
            else:
                srcpkg_seen[srcpkg] = True

            u = []
            while sources.Lookup(srcpkg):
                u.extend([sources.Index.ArchiveURI(sources.Files[f][2])
                          for f in range(len(sources.Files))])
            if len(u) > 0:
                self.log.debug(u)
                uris.extend(u)
            else:
                self.log.critical('failed to query source uris for %s' % srcpkg)
                raise Error

        uris.sort()
        self.pkgs[arch]['source'] = uris


    def _installPkgs(self, arch):
        '''Install packages.'''
        cache = apt_pkg.GetCache()

        pkgs_want = self.pkgs[arch]['list']
        pkgs_base = [p.Name for p in cache.Packages if p.CurrentVer]
        pkgs_dict = dict([(p, True) for p in pkgs_base + pkgs_want])

        pkgs_want.extend(self._detectLocalePkgs(pkgs_dict, cache))
        pkgs_want.extend(self._detectRecommendedPkgs(pkgs_dict, cache))
        pkgs_want.extend(self._detectLinuxModulePkgs(arch, cache))

        self.log.info('installing packages in %s chroot...' % arch)
        self._aptGetInstall(arch, self.__filterList(pkgs_want))
        self._collectManifest(arch)


    def _postInst(self, arch):
        '''Perform common post-installation tasks and/or fixups.'''
        chroot = os.path.join(self.temp, arch)

        self.log.info('performing post-install tasks in %s chroot...' % arch)

        postinst = os.path.join(self.opts.s, 'data', 'postinst')
        shutil.copy(postinst, os.path.join(chroot, 'tmp'))
        os.chmod(os.path.join(chroot, 'tmp'), 0700)
        self._execInChroot(arch, '/bin/sh /tmp/postinst'.split())


    def _rebuildInitRamfs(self, arch):
        '''Rebuild the chroot live initramfs after all packages have been
        installed. Copy the vmlinuz and initramfs to staging area.'''
        chroot = os.path.join(self.temp, arch)
        boot_dir = os.path.join(self.temp, 'staging', 'boot')

        kvers = self._detectLinuxVersion(chroot)
        for k in kvers:
            self.log.info('creating an initial ramdisk for linux %s...' % k)
            cmd = 'update-initramfs -d -k ' + k
            self._execInChroot(arch, cmd.split())

            if self.opts.v:
                cmd = 'update-initramfs -v -c -k ' + k
            else:
                cmd = 'update-initramfs -c -k ' + k
            self._execInChroot(arch, cmd.split())


    def _initBlackList(self, arch):
        '''Blacklist a group of initscripts present in chroot that should not
        be executed during live boot per default.'''
        self.log.info('calculating initscript blacklist for %s chroot...' %
                      arch)
        chroot = os.path.join(self.temp, arch)
        initd = '/etc/init.d/'

        init_glob = os.path.join(chroot, 'etc', 'init.d', '*')
        initscripts = set([i.replace(chroot, '', 1)
                           for i in glob.glob(init_glob)
                           if self.__isexecutable(i)])

        blacklist = set()
        for line in open(os.path.join(self.opts.s, 'data',
                                      'fll_init_blacklist')):
            if line.startswith('#'):
                continue
            files = []
            if line.startswith(initd):
                file_glob = os.path.join(chroot, line.lstrip('/').rstrip())
                files = [f.replace(chroot, '', 1) for f in glob.glob(file_glob)
                         if self.__isexecutable(f)]
                for file in files:
                    self.log.debug('blacklisting: %s (glob)' % file)
                    blacklist.add(file)
            else:
                try:
                    cmd = 'chroot %s dpkg-query --listfiles ' % chroot
                    cmd += line
                    self._mount(chroot)
                    p = Popen(cmd.split(), env = self.env, stdout = PIPE,
                              stderr = open(os.devnull, 'w'), close_fds = True)
                except:
                    self.log.exception('failed to query files list for %s' %
                                       line)
                    raise Error
                else:
                    for file in p.communicate()[0].splitlines():
                        file = file.strip().split()[0]
                        if file.startswith(initd):
                            self.log.debug('blacklisting: %s (%s)' %
                                           (file, line.rstrip()))
                            blacklist.add([file])
                    self._umount(chroot)

        whitelist = set()
        for line in open(os.path.join(self.opts.s, 'data',
                                      'fll_init_whitelist')):
            if line.startswith('#'):
                continue
            files = []
            if line.startswith(initd):
                file_glob = os.path.join(chroot, line.lstrip('/').rstrip())
                files = [f.replace(chroot, '', 1) for f in glob.glob(file_glob)
                         if self.__isexecutable(f)]
                for file in files:
                    self.log.debug('whitelisting: %s (glob)' % file)
                    whitelist.add(file)
            else:
                try:
                    cmd = 'chroot %s dpkg-query --listfiles ' % chroot
                    cmd += line
                    self._mount(chroot)
                    p = Popen(cmd.split(), env = self.env, stdout = PIPE,
                              stderr = open(os.devnull, 'w'))
                except:
                    self.log.exception('failed to query files list for %s' %
                                       line)
                    raise Error
                else:
                    for file in p.communicate()[0].splitlines():
                        file = file.strip().split()[0]
                        if file.startswith(initd) and file not in blacklist:
                            self.log.debug('whitelisting: %s (%s)' %
                                           (file, line.rstrip()))
                            whitelist.add(file)
                    self._umount(chroot)

        fllinitblacklist = [os.path.basename(i) + '\n'
                            for i in initscripts.difference(whitelist)]
        fllinitblacklist.sort()

        self.log.debug('fllinitblacklist:')
        for f in fllinitblacklist:
            self.log.debug('  %s' % f.rstrip())
        self.log.debug('---')

        try:
            fllinit = open(os.path.join(chroot, 'etc/default/fll-init'), 'a')
        except:
            self.log.exception('failed to open /etc/default/fll-init')
            raise Error
        else:
            self.log.debug('writing file: /etc/default/fll-init')
            fllinit.writelines(fllinitblacklist)
            fllinit.close()


    def _zerologs(self, arch, dir, fnames):
        '''Truncate all log files.'''
        chroot = os.path.join(self.temp, arch)
        chrootdir = dir.replace(chroot, '', 1)

        for f in fnames:
            if not os.path.isfile(os.path.join(dir, f)):
                continue
            self._writeFile(arch, os.path.join(chrootdir, f))


    def _cleanChroot(self, arch):
        '''Remove unwanted content from a chroot.'''
        self.log.info('purging unwanted content from %s chroot...' % arch)
        chroot = os.path.join(self.temp, arch)

        cmd = 'dpkg --purge fll-live-initramfs'
        cmd += ' cdebootstrap-helper-rc.d'
        self._execInChroot(arch, cmd.split())
        self._execInChroot(arch, 'apt-get clean'.split())
        self._execInChroot(arch, 'dpkg --clear-avail'.split())

        os.path.walk(os.path.join(chroot, 'var/log'), self._zerologs, arch)


    def _chrootSquashfs(self, arch):
        '''Make squashfs filesystem image of chroot.'''
        self.log.info('creating squashfs filesystem of %s chroot...' % arch)
        chroot = os.path.join(self.temp, arch)

        image_file = self.conf['distro']['FLL_IMAGE_FILE']
        if arch == 'i386':
            image_file += '.686'
        else:
            image_file += '.%s' % arch

        cmd = ['mksquashfs', '.', image_file, '-noappend']

        if self.opts.l or self.opts.q:
            cmd.append('-no-progress')

        # sortfile, compression

        exclude_file = os.path.join(self.opts.s, 'data', 'fll_sqfs_exclusion')
        shutil.copy(exclude_file, os.path.join(self.temp, arch, 'tmp'))
        cmd.extend(['-wildcards', '-ef', '/tmp/fll_sqfs_exclusion'])

        cmd.extend(['-e', image_file])
        self._execInChroot(arch, cmd)


    def _stageArch(self, arch):
        '''Stage files for an arch for final genisofs.'''
        self.log.info('staging live %s media...' % arch)
        chroot = os.path.join(self.temp, arch)

        image_file = os.path.join(chroot,
                                  self.conf['distro']['FLL_IMAGE_FILE'])

        if arch == 'i386':
            image_file += '.686'
        else:
            image_file += '.%s' % arch

        image_dir = os.path.join(self.temp, 'staging',
                                 self.conf['distro']['FLL_IMAGE_DIR'])
        try:
            os.chmod(image_file, 0644)
            shutil.move(image_file, image_dir)
        except:
            self.log.exception('failed to set permissions and copy squashfs ' +
                               'image to staging dir')
            raise Error

        boot_dir = os.path.join(self.temp, 'staging', 'boot')

        kvers = self._detectLinuxVersion(chroot)
        for k in kvers:
            try:
                self.log.debug('copying initrd.img-%s to %s' % (k, boot_dir))
                initrd = os.path.join(chroot, 'boot', 'initrd.img-' + k)
                shutil.copy(initrd, boot_dir)

                self.log.debug('copying vmlinuz-%s to %s' % (k, boot_dir))
                vmlinuz = os.path.join(chroot, 'boot', 'vmlinuz-' + k)
                shutil.copy(vmlinuz, boot_dir)
            except:
                self.log.exception('problem copying vmlinux and initrd to ' +
                                   'staging area')
                raise Error

        message = os.path.join(chroot, 'boot', 'message.live')
        if os.path.isfile(message) and \
            not os.path.isfile(os.path.join(boot_dir, 'message')):
            self.log.debug('copying grub-gfxboot message file to boot dir')
            try:
                shutil.copy(message, boot_dir)
                message = os.path.join(boot_dir, 'message.live')
                os.rename(message, os.path.splitext(message)[0])
            except:
                self.log.exception('failed to copy grub message to ' +
                                   'staging dir')
                raise Error

        grub_dir = os.path.join(boot_dir, 'grub')
        if not os.path.isdir(grub_dir):
            os.mkdir(grub_dir, 0755)

        gstage_dir = glob.glob(os.path.join(chroot, 'usr/lib/grub/*-pc'))[0]
        gstages = [s for s in os.listdir(gstage_dir)
                   if s.startswith('stage2') or s.startswith('iso9660')]
        if len(gstages) >= 3:
            self.log.debug('copying grub stage files to boot dir')
            for stage in gstages:
                if not os.path.isfile(os.path.join(grub_dir, stage)):
                    try:
                        shutil.copy(os.path.join(gstage_dir, stage), grub_dir)
                    except:
                        self.log.exception('failed to copy grub stage file ' +
                                           'to staging dir')
                        raise Error
        else:
            self.log.critical('grub stage files not found')
            raise Error

        memtest = os.path.join(chroot, 'boot', 'memtest86+.bin')
        if os.path.isfile(memtest) and \
            not os.path.isfile(os.path.join(boot_dir, 'memtest86+.bin')):
            self.log.debug('copying memtest86+ to boot dir')
            try:
                shutil.copy(memtest, boot_dir)
            except:
                self.log.exception('failed to copy memtest86+.bin to ' +
                                   'staging dir')
                raise Error


    def writeMenuList(self):
        '''Write final menu.lst for live media.'''
        self.log.debug('writing grub menu.lst for live media')
        stage_dir = os.path.join(self.temp, 'staging')
        boot_dir = os.path.join(stage_dir, 'boot')
        grub_dir = os.path.join(boot_dir, 'grub')

        menulst = open(os.path.join(grub_dir, 'menu.lst'), 'w')
        menulst.write('default 0\n')
        menulst.write('timeout 30\n')
        menulst.write('color red/black light-red/black\n')
        menulst.write('foreground EE0000\n')
        menulst.write('background 400000\n')
        menulst.write('gfxmenu /boot/message\n')

        kvers = self._detectLinuxVersion(stage_dir)
        if len(kvers) < 1:
            self.log.critical('failed to find linux kernels to include in ' +
                              'menu.lst')
            raise Error

        distro = self.conf['distro']['FLL_DISTRO_NAME']
        for k in kvers:
            cpu = k[k.rfind('-') + 1:]
            vmlinuz = 'vmlinuz-%s' % k
            initrd = 'initrd.img-%s' % k

            for f in [vmlinuz, initrd]:
                if not os.path.isfile(os.path.join(boot_dir, f)):
                    self.log.critical('%s was not found in %s' % (f, boot_dir))
                    raise Error

            menulst.write('\n')
            menulst.write('title  %s %s\n' % (distro, cpu))
            menulst.write('kernel /boot/%s boot=fll quiet vga=791\n' % vmlinuz)
            menulst.write('initrd /boot/%s\n' % initrd)
            menulst.write('\n')
            menulst.write('title  %s %s Advanced Menu\n' % (distro, cpu))
            menulst.write('configfile /boot/grub/menu.lst.%s\n' % cpu)

            menucpu = open(os.path.join(grub_dir, 'menu.lst.%s' % cpu), 'w')
            for lines in fileinput.input(os.path.join(self.opts.s, 'data',
                                                      'menu.lst.cpu')):
                for line in lines.splitlines():
                    if line.find('@vmlinuz@') >= 0:
                        line = line.replace('@vmlinuz@', vmlinuz)
                    if line.find('@initrd@') >= 0:
                        line = line.replace('@initrd@', initrd)
                    menucpu.write('%s\n' % line)
            menucpu.close()

        if os.path.isfile(os.path.join(boot_dir, 'memtest86+.bin')):
            menulst.write('\n')
            menulst.write('title  memtest86+\n')
            menulst.write('kernel /boot/memtest86+.bin\n')

        menulst.close()


    def _md5sums(self, base, dir, fnames):
        '''Function given to os.path.walk of self.writeMd5Sums().'''
        try:
            md5sums = open(os.path.join(base, 'md5sums'), 'a')
        except:
            self.log.exception('failed to open md5sums file for writing')

        for f in fnames:
            file = os.path.join(dir, f)
            if not os.path.isfile(file) or f == 'md5sums':
                continue
            if dir.endswith('grub') and f.find('stage') >= 0:
                continue
            self.log.debug('md5sum -b %s' % file)
            try:
                p = Popen(['md5sum', '-b', file], stdout = PIPE)
            except:
                self.log.exception('problem calculating/writing md5sum for %s'
                                   % file)
                raise Error

            md5sums.write("%s *%s\n" % (p.communicate()[0].split()[0],
                                        file.replace(base, '', 1).lstrip('/')))

        md5sums.close()


    def writeMd5Sums(self):
        '''Calculate md5sums of major release contents.'''
        self.log.info('calculating md5sums of live media...')
        stage = os.path.join(self.temp, 'staging')
        os.path.walk(stage, self._md5sums, stage)


    def __archManifest(self, arch):
        '''Write manifest information to file.'''
        pkgs = self.pkgs[arch]['manifest'].keys()
        pkgs.sort(key=len)
        l = len(pkgs[-1])
        pkgs.sort()

        return ["%s %s\n" % (p.ljust(l), self.pkgs[arch]['manifest'][p])
                for p in pkgs]


    def _writeManifests(self, file):
        '''Write package manifest lists.'''
        archs = self.conf['archs'].keys()
        for arch in archs:
            manifest_name = '%s.%s.manifest' % (file, arch)

            manifest_file = os.path.join(self.opts.o, manifest_name)
            manifest = open(manifest_file, 'w')
            manifest.writelines(self.__archManifest(arch))
            manifest.close()
            os.chown(manifest_file, self.opts.u, self.opts.g)


    def _writeSources(self, file):
        '''Write source URI lists.'''
        sources_list = []
        archs = self.conf['archs'].keys()
        for arch in archs:
            sources_list.extend(self.pkgs[arch]['source'])
        sources_list = self.__filterList(sources_list, dup_warn = False)

        sources_name = file + '.sources'
        sources_file = os.path.join(self.opts.o, sources_name)
        sources = open(sources_file, 'w')
        sources.writelines(["%s\n" % s for s in sources_list])
        sources.close()
        os.chown(sources_file, self.opts.u, self.opts.g)

        cached = {}
        for r in self.conf['repos']:
            if 'cached' in self.conf['repos'][r] and \
               self.conf['repos'][r]['cached']:
                cached_uri = self.conf['repos'][r]['cached']
                uri = self.conf['repos'][r]['uri']
                cached[cached_uri.rstrip('/')] = uri.rstrip('/')

        if len(cached.keys()) > 0:
            os.rename(sources_file, sources_file + '-cached')
        else:
            return

        sources = open(sources_file, 'w')
        for s in sources_list:
            for c in cached.keys():
                if s.startswith(c):
                    s = s.replace(c, cached[c], 1)
                    break
            sources.write('%s\n' % s)
        sources.close()
        os.chown(sources_file, self.opts.u, self.opts.g)


    def genLiveMedia(self):
        '''Generate live media iso image.'''
        stage = os.path.join(self.temp, 'staging')

        sort = open(os.path.join(stage, 'genisoimage.sort'), 'w')
        sort.write('boot/grub/* 10000\n')
        sort.write('boot/* 1000\n')
        sort.write('%s/* 100\n' % self.conf['distro']['FLL_IMAGE_DIR'])
        sort.close()

        timestamp = time.strftime('%Y%m%d%H%M', time.gmtime())

        distro_name = self.conf['distro']['FLL_DISTRO_NAME']

        iso_name = self.stamp_safe
        iso_name += '-' + '-'.join(self.conf['archs'].keys())
        iso_name += '-' + timestamp
        iso_name += '.iso'

        iso_file = os.path.join(self.opts.o, iso_name)
        sort_file = os.path.join(stage, 'genisoimage.sort')
        md5_file = iso_file + '.md5'

        cmd = 'genisoimage'
        if self.opts.v:
            cmd += ' -v'
        cmd += ' -pad -l -J -r -hide-rr-moved'
        cmd += ' -no-emul-boot -boot-load-size 4 -boot-info-table'
        cmd += ' -b boot/grub/iso9660_stage1_5 -c boot/grub/boot.cat'
        cmd += ' -V %s' % distro_name[:32]
        cmd += ' -sort %s' % sort_file
        cmd += ' -x genisoimage.sort'
        cmd += ' -o %s %s' % (iso_file, stage)

        self.log.info('generating iso image of live media...')
        self._execCmd(cmd.split())
        os.chown(iso_file, self.opts.u, self.opts.g)

        self.log.info('calculating md5sum of live media iso image...')
        md5 = open(md5_file, 'w')
        p = Popen(['md5sum', '-b', iso_file], stdout = PIPE)
        line = "%s *%s\n" % (p.communicate()[0].split()[0],
                             os.path.basename(iso_file))
        md5.write(line)
        md5.close()
        os.chown(md5_file, self.opts.u, self.opts.g)

        self._writeManifests(os.path.splitext(iso_file)[0])
        if not self.opts.B:
            self._writeSources(os.path.splitext(iso_file)[0])


    def buildChroots(self):
        '''Main loop to call all chroot building functions.'''
        archs = self.conf['archs'].keys()
        for arch in archs:
            self._bootStrap(arch)
            self._defaultEtc(arch)
            self._preseedDebconf(arch)
            self._primeApt(arch)
            self._dpkgAddDivert(arch)
            self._installPkgs(arch)
            self._dpkgUnDivert(arch)
            self._finalEtc(arch)
            self._initBlackList(arch)
            self._rebuildInitRamfs(arch)
            self._postInst(arch)
            self._cleanChroot(arch)
            self._chrootSquashfs(arch)
            self._stageArch(arch)
            self._nukeChroot(arch)


    def main(self):
        '''Main loop.'''
        self.parseOpts()
        self.parseConf()
        self.parsePkgProfile()
        self.stageBuildArea()

        if self.opts.n:
            sys.exit(0)

        self.buildChroots()
        self.writeMenuList()
        self.writeMd5Sums()
        self.genLiveMedia()


if __name__ == '__main__':
    try:
        fll = FLLBuilder()
        fll.main()
    except KeyboardInterrupt:
        pass
    except Error:
        sys.exit(1)
