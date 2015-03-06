#!/bin/bash -eux
OUTER_UID=$(stat -c '%u' .)
OUTER_GID=$(stat -c '%g' .)
trap "chown -R $OUTER_UID:$OUTER_GID ." EXIT
make deb
