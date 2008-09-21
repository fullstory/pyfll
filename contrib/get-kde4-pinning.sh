#!/bin/sh

BASE_URL="svn://svn.debian.org/svn/pkg-kde/branches/kde4/packages"
SOURCE_PACKAGES="$(svn ls ${BASE_URL})"
unset BINARY_PACKAGES

for i in $SOURCE_PACKAGES; do
	BINARY_PACKAGES="$BINARY_PACKAGES $(svn cat "${BASE_URL}/${i}/debian/control" | awk '/^Package\:/{ print $2 }')"
done

printf "Explanation: this file provides apt-pinning\n"
printf "Explanation: enabling the install of the debian\n"
printf "Explanation: kde4-minimal meta-package in pyfll.\n"
printf "Explanation: Add this files path to apt_preferences in fll.conf\n"

printf "Package: *\nPin: release a=unstable\nPin-Priority: 500\n\n"
printf "Package: *\nPin: release a=testing\nPin-Priority: 200\n\n"
printf "Package: *\nPin: release a=experimental\nPin-Priority: 1\n"

for i in $BINARY_PACKAGES; do
	printf "\nPackage: ${i}\nPin: release a=experimental\nPin-Priority: 500\n"
done
