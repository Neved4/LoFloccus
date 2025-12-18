#!/bin/sh

scriptDir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
output="${1:-${scriptDir}/../assets/icon.icns}"
appDir="${scriptDir%/scripts}"
assetsDir="${appDir}/assets"
iconsetDir="$(mktemp -d "${TMPDIR:-/tmp}/lofloccus.icon.XXXXXX.iconset")"
icon="${ICON_SRC:-${assetsDir}/icon.svg}"
iconInput=""

mkdir -p "$(dirname "$output")"

if [ ! -f "$icon" ]; then
	echo "icon source not found; set ICON_SRC" >&2
	exit 1
fi

iconInput="$icon"

for size in 16 32 64 128 256 512 1024
do
	magick "$iconInput" -resize "${size}x${size}" -background none \
		-gravity center -extent "${size}x${size}" \
		"$iconsetDir/icon_${size}x${size}.png"
	magick "$iconInput" -resize "$((size * 2))x$((size * 2))" \
		-background none -gravity center \
		-extent "$((size * 2))x$((size * 2))" \
		"$iconsetDir/icon_${size}x${size}@2x.png"
done

iconutil -c icns -o "$output" "$iconsetDir"
rm -r "$iconsetDir"
