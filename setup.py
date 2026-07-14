import os
from setuptools import setup

data_files = []
for dirpath, dirnames, filenames in os.walk("share"):
    # don't descend into or ship bytecode caches / local dev artifacts
    dirnames[:] = [d for d in dirnames if d != "__pycache__"]
    filenames = [
        f for f in filenames if not f.endswith(".pyc") and ".local" not in f
    ]
    if not filenames:
        continue
    install_dir = os.path.normpath(os.path.join(
        "share", "pyfll", os.path.relpath(dirpath, "share")
    ))
    data_files.append(
        (install_dir, [os.path.join(dirpath, f) for f in filenames])
    )

setup(data_files=data_files)
