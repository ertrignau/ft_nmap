#!/bin/bash

OUT="dump.txt"

rm -f "$OUT"

add_file() {
	if [ -f "$1" ]; then
		printf "\n===== %s =====\n\n" "$1" >> "$OUT"
		cat "$1" >> "$OUT"
		printf "\n" >> "$OUT"
	fi
}

add_file "./Makefile"

find ./inc ./srcs -type f \( -name "*.c" -o -name "*.h" -o -name "*.mk" \) \
	| sort \
	| while IFS= read -r file; do
		add_file "$file"
	done

echo "Dump créé dans $OUT"