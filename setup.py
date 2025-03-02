#!/usr/bin/python3

from distutils.core import setup
from glob import glob
import os

fll_prog = ['pyfll', 'fll.conf', 'gpthybrid']
fll_data = glob('data/*')
fll_pkgs = [f for f in glob('profiles/*') if os.path.isfile(f)]
fll_deps = glob('profiles/deps/*')

setup(
    name='pyfll',
    author='Kelvin Modderman',
    author_email='kelvmod@gmail.com',
    license='GPL-2',
    description='FULLSTORY live linux media mastering utility',
    url='https://github.com/fullstory/',
    scripts=['fll'],
    data_files=[
        ('/usr/share/fll/', fll_prog),
        ('/usr/share/fll/data', fll_data),
        ('/usr/share/fll/profiles', fll_pkgs),
        ('/usr/share/fll/profiles/deps/', fll_deps),
    ],
)
