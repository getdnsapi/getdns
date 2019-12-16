#!/bin/bash

[ ! -f git-archive-all.sh ] && wget "https://raw.githubusercontent.com/meitar/git-archive-all.sh/master/git-archive-all.sh"
[ ! -x git-archive-all.sh ] && chmod +x git-archive-all.sh
[ ! -f git-archive-all.sh ] && exit 1
GIT_ARCHIVE="`pwd`/git-archive-all.sh"
git submodule update --init
GIT_ROOT=`git rev-parse --show-toplevel`
version=`awk '/^set\(PACKAGE_VERSION/{V=$2}
              /^set\(RELEASE_CANDIDATE/{RC=$2}
              END{print V""RC}' "$GIT_ROOT/CMakeLists.txt" | sed 's/[")]//g'`
output_file="getdns-${version}.tar.gz"
( cd "$GIT_ROOT" \
  && "$GIT_ARCHIVE" --prefix "getdns-$version/" --format tar.gz \
                    --worktree-attributes -- - ) > "$output_file"
openssl md5 "$output_file" > "${output_file}.md5"
openssl sha1 "$output_file" > "${output_file}.sha1"
openssl sha256 "$output_file" > "${output_file}.sha256"
gpg --armor --detach-sig "$output_file"
[ -f "$output_file" -a -f "${output_file}.md5" -a -f "${output_file}.sha1" -a -f "${output_file}.sha256" -a -f "${output_file}.asc" ] \
&& rm git-archive-all.sh
