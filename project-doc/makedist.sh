#!/bin/bash

[ ! -f git-archive-all.sh ] && wget "https://raw.githubusercontent.com/meitar/git-archive-all.sh/master/git-archive-all.sh"
[ ! -x git-archive-all.sh ] && chmod +x git-archive-all.sh
version=`awk '/^set\(PACKAGE_VERSION/{V=$2}
              /^set\(RELEASE_CANDIDATE/{RC=$2}
              END{print V""RC}' CMakeLists.txt | sed 's/[")]//g'`
output_file="getdns-${version}.tar.gz"
./git-archive-all.sh --prefix "getdns-$version/" --format tar.gz --worktree-attributes "getdns-$version.tar.gz"

