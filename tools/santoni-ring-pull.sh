#!/bin/sh
# Pull the SANTONI persistent console ring from the GPT "system" partition.
#
#   tools/santoni-ring-pull.sh [OUT_BASENAME]
#
# Writes OUT_BASENAME.bin (8193 x 512 B = 4 MiB + one header sector) and, if the
# SANTONILOG1 header is present, OUT_BASENAME.txt (decoded console text).
#
# Run this from TWRP, or from rooted Android after `adb root`. It never writes
# to the phone and never formats anything.
set -eu

out=${1:-santoni-ring}
cd "$(dirname "$0")/.."

say() { printf '%s\n' "$*" >&2; }

adb wait-for-device

id=$(adb shell id 2>/dev/null | tr -d '\r' || true)
case "$id" in
	*uid=0*) ;;
	*)
		say "adbd is not root ($id); trying adb root..."
		adb root >/dev/null 2>&1 || true
		adb wait-for-device
		id=$(adb shell id 2>/dev/null | tr -d '\r' || true)
		case "$id" in
			*uid=0*) ;;
			*)
				say "ERROR: need root adbd (boot TWRP, or 'adb root' on a rooted Android)."
				exit 1
				;;
		esac
		;;
esac

say "Looking for the GPT 'system' partition..."
dev=$(adb shell '
	for d in /dev/block/bootdevice/by-name/system /dev/block/by-name/system; do
		if [ -e "$d" ]; then readlink -f "$d"; exit 0; fi
	done
	exit 1
' 2>/dev/null | tr -d '\r' || true)

if [ -z "${dev:-}" ]; then
	say "ERROR: no by-name/system symlink found."
	say "Do NOT format anything. Send me the output of:"
	say "  adb shell 'ls -l /dev/block/bootdevice/by-name/'"
	say "  adb shell 'cat /proc/partitions'"
	exit 2
fi

say "system -> $dev"
say "Pulling 8193 x 512 B (4 MiB ring + 512 B header)..."
adb exec-out "dd if=$dev bs=512 count=8193 2>/dev/null" > "$out.bin"

bytes=$(wc -c < "$out.bin" | tr -d ' ')
say "Wrote $out.bin ($bytes bytes)"
if [ "$bytes" != "4194816" ]; then
	say "ERROR: expected exactly 4194816 bytes."
	say "The pull was short or came from the wrong partition."
	say "Do NOT format system. Send me $out.bin and the partition listing."
	exit 3
fi

magic=$(dd if="$out.bin" bs=1 count=12 2>/dev/null || true)
if [ "$magic" = "SANTONILOG1" ]; then
	say "SANTONILOG1 header found; decoding..."
	python3 tools/sweet-log.py "$out.bin" "$out.txt"
	say "Wrote $out.txt"
	say "Send me $out.txt (and $out.bin if the text looks truncated)."
else
	say "No SANTONILOG1 header in the first 12 bytes."
	say "First 64 bytes:"
	od -An -tx1 -N64 "$out.bin" >&2 || true
	say "Do NOT format system. Send me:"
	say "  $out.bin"
	say "  adb shell 'ls -l /dev/block/bootdevice/by-name/'"
	say "  adb shell 'cat /proc/partitions'"
	exit 4
fi
