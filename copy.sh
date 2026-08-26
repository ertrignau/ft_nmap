#!/usr/bin/env bash

OUT="ft_nmap_context.txt"

: > "$OUT"

add_file()
{
	file="$1"

	if [ ! -f "$file" ]; then
		return
	fi

	{
		echo
		echo "================================================================================"
		echo "FILE: $file"
		echo "================================================================================"
		echo
		cat "$file"
		echo
	} >> "$OUT"
}

{
	echo "FT_NMAP SOURCE CONTEXT"
	echo
	echo "TREE:"
	echo "--------------------------------------------------------------------------------"
	tree \
		-I 'objs|ft_nmap_lab|ft_nmap|debug|*.strace|tot.py|tot.sh|ft_nmap_context.txt' \
		2>/dev/null
	echo
} >> "$OUT"

add_file "Makefile"

for file in inc/*.h
do
	[ -f "$file" ] && add_file "$file"
done

find srcs -type f \( -name '*.c' -o -name '*.h' \) \
	| sort \
	| while IFS= read -r file
	do
		add_file "$file"
	done

add_file "srcs/packet/README.md"
add_file "srcs/runtime/README.md"

add_file "PlanGlobal.md"
add_file "PLanMoteur.md"

echo "Generated: $OUT"
wc -l "$OUT"
wc -c "$OUT"