# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Kel Modderman <kelvmod@gmail.com>

from pyfll.apt import AptMixin

# _parse_apt_problems/_conflict_subjects don't touch self; call unbound.
mixin = AptMixin()


APT_SIMULATE_OUTPUT = """\
Reading package lists...
Building dependency tree...
Some packages could not be installed. This may mean that you have
requested an impossible situation or if you are using the unstable
distribution that some required packages have not yet been created
or been moved out of Incoming.
The following information may help to resolve the situation:

The following packages have unmet dependencies:
 foo : Depends: libbar1 (>= 1.2) but it is not going to be installed
 baz : Depends: libbar1 (>= 1.2) but it is not going to be installed
E: Unable to correct problems, you have held broken packages.
E: Trivial Only specified but this is not a trivial operation.
 1. libbar1:amd64=1.0-1 is selected for install
 2. foo:amd64=2.0-1 is selected for install
"""


def test_parse_apt_problems_splits_cascade_and_diagnosis():
    diagnosis, cascade = mixin._parse_apt_problems(APT_SIMULATE_OUTPUT)

    assert cascade == [
        "foo : Depends: libbar1 (>= 1.2) but it is not going to be installed",
        "baz : Depends: libbar1 (>= 1.2) but it is not going to be installed",
    ]
    assert diagnosis == [
        "E: Unable to correct problems, you have held broken packages.",
        "E: Trivial Only specified but this is not a trivial operation.",
        "1. libbar1:amd64=1.0-1 is selected for install",
        "2. foo:amd64=2.0-1 is selected for install",
    ]


def test_parse_apt_problems_no_problems():
    diagnosis, cascade = mixin._parse_apt_problems("Reading package lists...\nDone\n")
    assert diagnosis == []
    assert cascade == []


def test_conflict_subjects_strips_arch_and_version():
    diagnosis = [
        "E: some error",
        "1. libbar1:amd64=1.0-1 is selected for install",
        "2. foo:amd64=2.0-1 is selected for install",
        "3. foo:amd64=2.0-1 is selected for install",
    ]
    assert mixin._conflict_subjects(diagnosis) == ["libbar1", "foo"]


def test_conflict_subjects_ignores_non_numbered_lines():
    diagnosis = ["E: some error", "not a numbered line"]
    assert mixin._conflict_subjects(diagnosis) == []
