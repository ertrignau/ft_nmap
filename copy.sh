#!/usr/bin/env bash

set -euo pipefail

# Toujours travailler depuis le dossier contenant ce script.
cd "$(dirname "$(realpath "$0")")"

OUTPUT="ft_nmap_snapshot.txt"

# Aucun backup : le snapshot précédent est écrasé.
: > "$OUTPUT"

{
    # Makefile principal uniquement.
    if [[ -f Makefile ]]; then
        printf '%s\0' './Makefile'
    fi

    # Tous les fichiers sources et documents, récursivement.
    find . \
        \( -type d \( \
            -name '.git' \
            -o -name 'objs' \
            -o -name 'objs_debug' \
            -o -name 'objs_profile' \
            -o -name 'build' \
            -o -name '*backup*' \
            -o -name '*payload*' \
        \) -prune \) \
        -o \
        \( -type f \( \
            -name '*.c' \
            -o -name '*.h' \
            -o -name '*.md' \
            -o -name '*.MD' \
        \) -print0 \)

} | LC_ALL=C sort -z |
while IFS= read -r -d '' file; do

    printf '\n' >> "$OUTPUT"
    printf '==================================================\n' >> "$OUTPUT"
    printf 'FILE: %s\n' "${file#./}" >> "$OUTPUT"
    printf '==================================================\n\n' >> "$OUTPUT"

    cat -- "$file" >> "$OUTPUT"

    printf '\n' >> "$OUTPUT"

done

echo "Snapshot generated: $OUTPUT"
wc -c < "$OUTPUT" | xargs printf 'Size: %s bytes\n'
