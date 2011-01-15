#!/bin/sh

[ ! -e m4 ] && mkdir m4
autoreconf --verbose --install --force
intltoolize --copy --force --automake
