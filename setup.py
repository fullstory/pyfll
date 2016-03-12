#!/usr/bin/python

from distutils.core import setup
from glob import glob
import os

fll_prog = ['pyfll', 'fll.conf']
fll_data = glob('data/*')
fll_pkgs = [f for f in glob('packages/*') if os.path.isfile(f)]
fll_pkgs_d = glob('packages/packages.d/*')

setup(
    name='pyfll',
    author='Kelvin Modderman',
    author_email='kel@otaku42.de',
    license='GPL-2',
    description='FULLSTORY live linux media mastering utility',
    url='https://github.com/fullstory/',
    scripts=['fll'],
    data_files=[
        ('/usr/share/fll/', fll_prog),
        ('/usr/share/fll/data', fll_data),
        ('/usr/share/fll/packages', fll_pkgs),
        ('/usr/share/fll/packages/packages.d/', fll_pkgs_d),
    ],
)
