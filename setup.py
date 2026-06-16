import os
from setuptools import setup

data_files = []
for dirpath, dirnames, filenames in os.walk("share"):
    if not filenames:
        continue
    install_dir = os.path.normpath(os.path.join(
        "share", "pyfll", os.path.relpath(dirpath, "share")
    ))
    data_files.append(
        (install_dir, [os.path.join(dirpath, f) for f in filenames])
    )

setup(data_files=data_files)
