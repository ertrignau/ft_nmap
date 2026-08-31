#!/bin/bash

OUT="ft_nmap_source_context.txt"

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
	cat "$FILE" >> "$OUT"
	echo "" >> "$OUT"
}

write_section "FT_NMAP SOURCE CONTEXT"

echo "Generated from: $(pwd)" >> "$OUT"
echo "Date: $(date)" >> "$OUT"

write_section "GIT STATUS"
git status --short >> "$OUT" 2>&1

write_section "GIT LOG"
git log --graph --oneline --decorate -20 >> "$OUT" 2>&1

write_section "PROJECT FILES"

find . \
	-type f \
	-not -path './.git/*' \
	-not -path './objs/*' \
	-not -path './objs_debug/*' \
	-not -path './objs_profile/*' \
	-not -name 'ft_nmap' \
	-not -name "$OUT" \
	-not -name 'copy.sh' \
	-not -name 'parsing_review.txt' \
	-not -name 'parsing_review_2.txt' \
	-not -name '*.o' \
	-not -name '*.d' \
	-not -name '*.zip' \
	-not -name '*.tar.gz' \
	| sort >> "$OUT"

if [ -f Makefile ]; then
	dump_file "Makefile"
fi

while IFS= read -r FILE
do
	dump_file "$FILE"
done < <(
	find inc srcs \
		-type f \
		\( -name '*.h' -o -name '*.c' \) \
		2>/dev/null \
		| sort
)

for FILE in \
	ARCHITECTURE.md \
	VALIDATION.md \
	README.md \
	README \
	targets.txt
do
	if [ -f "$FILE" ]; then
		dump_file "$FILE"
	fi
done

echo "Generated: $OUT"
wc -l "$OUT"
du -h "$OUT"