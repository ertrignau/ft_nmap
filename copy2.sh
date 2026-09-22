#!/bin/bash

LAB_DIR="ft_nmap_lab"
OUT="ft_nmap_lab_context.txt"

if [ ! -d "$LAB_DIR" ]; then
	echo "Error: $LAB_DIR not found" >&2
	exit 1
fi

: > "$OUT"

write_section()
{
	echo "" >> "$OUT"
	echo "================================================================" >> "$OUT"
	echo "$1" >> "$OUT"
	echo "================================================================" >> "$OUT"
	echo "" >> "$OUT"
}

dump_file()
{
	FILE="$1"

	write_section "FILE: $FILE"

	if [ ! -s "$FILE" ]; then
		echo "[EMPTY FILE]" >> "$OUT"
	elif grep -Iq . "$FILE" 2>/dev/null; then
		cat "$FILE" >> "$OUT"
	else
		echo "[BINARY FILE]" >> "$OUT"
		echo "Size: $(stat -c '%s bytes' "$FILE" 2>/dev/null)" >> "$OUT"
		echo "SHA256: $(sha256sum "$FILE" 2>/dev/null | awk '{print $1}')" >> "$OUT"
		file "$FILE" >> "$OUT" 2>&1
	fi

	echo "" >> "$OUT"
}

write_section "FT_NMAP LAB CONTEXT"

echo "Generated from: $(pwd)" >> "$OUT"
echo "Lab directory: $LAB_DIR" >> "$OUT"
echo "Date: $(date)" >> "$OUT"

write_section "GIT STATUS"
git status --short -- "$LAB_DIR" >> "$OUT" 2>&1

write_section "DIRECTORY TREE"
find "$LAB_DIR" -print | sort >> "$OUT"

write_section "ALL FILES"

find "$LAB_DIR" -type f -print | sort >> "$OUT"

while IFS= read -r FILE
do
	dump_file "$FILE"
done < <(
	find "$LAB_DIR" -type f -print | sort
)

echo "Generated: $OUT"
wc -l "$OUT"
du -h "$OUT"