#!/bin/sh

arch="${1:?}"
out="${2:?}"
src="${3:?}"
srcBase="${src##*/}"
tmpDir=$(mktemp -d)
sdkPath="$(xcrun --sdk macosx --show-sdk-path)"

case "$arch" in
 arm64) export CC="clang -arch arm64" && export GOARCH="arm64" ;;
x86_64) export CC="clang -arch x86_64" && export GOARCH="amd64" ;;
     *) echo "unknown arch: $arch" >&2 && exit 1 ;;
esac

export CGO_CFLAGS="-mmacosx-version-min=10.13"
export CGO_ENABLED=1
export CGO_LDFLAGS="-mmacosx-version-min=10.13"
export GOOS=darwin
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-10.13}"
export SDKROOT="$sdkPath"

cp "$src" "$tmpDir/"
cd "$tmpDir" || return 1
go mod init lofloccusdav
go mod tidy
go build -buildmode=c-archive -o "$out" "$srcBase"
rm -rf "$tmpDir"
