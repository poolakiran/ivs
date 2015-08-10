#!/bin/bash -eux
V=${1?}
PKGV=${V/-/"~"} # replace dash with tilde for package versions
dch -b -v $PKGV "New upstream version" -D unstable -u low
sed -i -e "s/const char \\*ivs_version = \".*\";/const char *ivs_version = \"$V\";/" targets/ivs/main.c
sed -i -e "s/^Version:.*$/Version: $PKGV/" rhel/ivs-7.0.spec
git commit debian/changelog targets/ivs/main.c rhel/ivs-7.0.spec -m "bump version to $V"
