#!/bin/sh

out="${1:?}"
src="${2:?}"
srcBase="${src##*/}"
tmpDir="$(mktemp -d)"
winCC="${WIN_CC:-x86_64-w64-mingw32-gcc}"

if ! command -v "$winCC" >/dev/null 2>&1
then
	echo "missing Windows cross-compiler: $winCC" >&2
	exit 1
fi

export CC="$winCC"
export CGO_ENABLED=1
export GOOS=windows
export GOARCH=amd64

cp "$src" "$tmpDir/"
cd "$tmpDir" || return 1
go mod init lofloccusdav
go mod tidy
go build -buildmode=c-archive -o "$out" "$srcBase"
rm -rf "$tmpDir"
