#!/usr/bin/env bash
# Crappy script to avoid manually dpkg

[ -z $REV ] && { echo "need a revision (REV) to install. e.g: 5" ; exit 1 ; }

dpkg -i linux-image-4.15.0-xxxx-std-ipv6-64_4.15.0-xxxx-std-ipv6-64-${REV}_amd64.deb linux-headers-4.15.0-xxxx-std-ipv6-64_4.15.0-xxxx-std-ipv6-64-${REV}_amd64.deb linux-libc-dev_4.15.0-xxxx-std-ipv6-64-${REV}_amd64.deb
