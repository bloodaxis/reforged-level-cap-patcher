#!/usr/bin/env bash
# Interactive launcher; keep beside uncap_reforged.py and its support files.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

if ! command -v python3 >/dev/null 2>&1; then
    printf 'Python 3 is required but was not found.\n' >&2
    exit 1
fi
for dependency in uncap_reforged.py hks_patch.py experimental_patterns.py inspect_esd.py uncap-signatures.json \
    esdtool-v0.5.1/dist/ESDScriptingDocumentation_TalkER.xml \
    esdtool-v0.5.1/dist/ESDScriptingDocumentation_Talk.json; do
    if [[ ! -f "$script_dir/$dependency" ]]; then
        printf 'Missing support file: %s\n' "$script_dir/$dependency" >&2
        exit 1
    fi
done

printf 'Reforged level-cap removal and menu fix\n\n'
printf '%s\n' \
    'Analyzed versions: Reforged 2.1.2.2, 2.3.3.2, and 2.3.4.0.' \
    'For every other version, use the experimental cap options 4/5.' \
    'Experimental patches may or may not work; unsupported patterns are refused.' \
    'Choose a check first. Checks do not change files; apply actions create backups.' \
    '' \
    '1) Check level-cap patch - Reforged 2.1.2.2 / 2.3.3.2 / 2.3.4.0' \
    '   Checks the talk archive and c0000.hks without changing them.' \
    '2) Remove level cap - Reforged 2.1.2.2 / 2.3.3.2 / 2.3.4.0' \
    '   Backs up and patches both files. Keeps weapon-level scaling unchanged.' \
    '3) Cancel' \
    '4) Experimental level-cap check - every other Reforged version' \
    '   Looks for compatible code patterns and validates a candidate in memory.' \
    '5) Experimental level-cap removal - every other Reforged version' \
    '   Asks for confirmation before patching. In-game compatibility is unverified.' \
    '6) Check weapon-level scaling patch only - separate optional action' \
    '   Analyzed for 2.1.2.2 / 2.3.3.2 / 2.3.4.0; other versions offer experimental analysis.' \
    '7) Disable weapon-level enemy scaling only - separate optional action' \
    '   Edits only c0000.hks; keeps the level cap unchanged.' \
    '   Analyzed for 2.1.2.2 / 2.3.3.2 / 2.3.4.0; other versions require experimental consent.' \
    ''
extra=()
while true; do
    read -r -p 'Choose [1/2/3/4/5/6/7]: ' choice || exit 0
    case "$choice" in
        1) mode=--check; break ;;
        2) mode=--in-place; break ;;
        3|q|Q) exit 0 ;;
        4) mode=--check; extra=(--experimental); break ;;
        5) mode=--in-place; extra=(--experimental); break ;;
        6) mode=--check; extra=(--weapon-scaling-only); break ;;
        7) mode=--in-place; extra=(--weapon-scaling-only); break ;;
        *) printf 'Enter a number from 1 to 7.\n' ;;
    esac
done

if [[ "$choice" == 6 || "$choice" == 7 ]]; then
    printf '\nPaste the Reforged/mod folder or c0000.hks path. This action changes weapon-level enemy scaling only.\n'
else
    printf '\nPaste the Reforged/mod folder or talk archive path. This action checks the level-cap patches in ESD and c0000.hks.\n'
fi
while true; do
    read -r -e -p 'Folder or file (blank to cancel): ' source_path || exit 0
    [[ -n "$source_path" ]] || exit 0
    # Accept a pasted path with one matching pair of surrounding quotes.
    if [[ "$source_path" == \"*\" || "$source_path" == \'*\' ]]; then
        source_path=${source_path:1:${#source_path}-2}
    fi
    if [[ "$source_path" == '~/'* ]]; then
        source_path="$HOME/${source_path:2}"
    fi
    if [[ ( -f "$source_path" || -d "$source_path" ) && -r "$source_path" ]]; then
        break
    fi
    printf 'Not a readable folder or file: %s\n' "$source_path" >&2
done

printf '\n'
python3 "$script_dir/uncap_reforged.py" "$mode" "${extra[@]}" -- "$source_path"
