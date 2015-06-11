#!/bin/bash -eux
V=${1?}
PKGV=${V/-/"~"} # replace dash with tilde for package versions
dch -v $PKGV -D unstable -u low
sed -i -e "s/static const char \\*program_version = \"ivs .*\";/static const char *program_version = \"ivs $V\";/" targets/ivs/main.c
sed -i -e "s/^Version:.*$/Version: $PKGV/" rhel/ivs-7.0.spec
git commit debian/changelog targets/ivs/main.c rhel/ivs-7.0.spec -m "bump version to $V"
