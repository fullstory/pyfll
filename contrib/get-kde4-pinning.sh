#!/bin/sh

BASE_URL="svn://svn.debian.org/svn/pkg-kde/branches/kde4.2/packages"
SOURCE_PACKAGES="$(svn ls ${BASE_URL} | grep -v -e pkg-kde-tools -e blitz | sed s/\\/$//)"

# Additional packages needed from experimental
WHITELIST="libstreamanalyzer0 kpilot superkaramba" 

printf "Explanation: this file provides apt-pinning\n"
printf "Explanation: enabling the install of the debian\n"
printf "Explanation: kde4-minimal meta-package in pyfll.\n"
printf "Explanation: Add this files path to apt_preferences in fll.conf\n"

printf "Package: *\nPin: release a=unstable\nPin-Priority: 500\n\n"
printf "Package: *\nPin: release a=testing\nPin-Priority: 200\n\n"
printf "Package: *\nPin: release a=experimental\nPin-Priority: 101\n"

for i in $SOURCE_PACKAGES; do
	printf "\nExplanation: ${i}\nPackage: $(svn cat "${BASE_URL}/${i}/debian/control" | awk '/^Package\:/{ print $2 }' | xargs)\nPin: release a=experimental\nPin-Priority: 500\n"
done

# Whitelist entries
printf "\nExplanation: Additional packages\nPackage: "
for i in $WHITELIST; do
	printf "$i "
done
printf "\nPin: release a=experimental\nPin-Priority: 500\n\n"

printf "\n"
