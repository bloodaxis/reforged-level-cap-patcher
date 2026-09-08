# Reforged level-cap patcher

Removes the Reforged level cap by patching the talk archive and the `c0000.hks` stat-total check.
Extract the entire directory before running. Keep its contents and subdirectories together; it can be moved or renamed. No game archives or saves are included.

## Requirements

Python 3.8 or newer, including its standard library. No pip packages, Wine, .NET, or ESDLang executable are required. Linux launchers require Bash. On Windows, install Python with the Python launcher (`py`) or add Python to PATH.

## Windows

Double-click `uncap_reforged.bat`. Choose check, apply, cancel, experimental check, or apply with experimental fallback, then paste or drag the Reforged folder, its `mod` folder, or the talk archive. The program locates `mod/action/script/c0000.hks` automatically. Weapon-level scaling has its own separate check/apply menu entries (6 and 7). Apply backs up each changed file and patches both inputs. The window pauses to display the result.

## Linux

Run `bash uncap_reforged.sh` from this directory, or launch it by its full path. Choose check, apply, cancel, experimental check, or apply with experimental fallback, then enter the Reforged folder, its `mod` folder, or the talk archive path. The matching `action/script/c0000.hks` is located automatically. Weapon-level scaling has its own separate check/apply menu entries (6 and 7). Spaces and surrounding quotes are supported.

## Choosing a launcher option

Start with a read-only check:

- **Reforged 2.1.2.2, 2.3.3.2, or 2.3.4.0:** option **1** checks the level-cap patches; option **2** applies them with backups.
- **Every other Reforged version:** option **4** checks experimentally; option **5** offers experimental cap removal with confirmation. This is the route to try, not a guarantee of compatibility. Unsupported patterns are refused.
- **Separate optional weapon-level scaling:** option **6** checks; option **7** disables it without changing the level cap. These edits were analyzed for **2.1.2.2, 2.3.3.2, and 2.3.4.0**; unrecognized versions offer experimental analysis/confirmation.
- **3** cancels.

Recognition is based on code structure. Even in experimental mode, a matching analyzed structure uses the known patch. Experimental changes may or may not work in-game.

## Command line

From this directory (on Windows, use `py -3` instead of `python3` if needed):

```sh
python3 uncap_reforged.py "/path/to/m00_00_00_00.talkesdbnd.dcx" --check
python3 uncap_reforged.py "/path/to/m00_00_00_00.talkesdbnd.dcx" --in-place
python3 uncap_reforged.py "/path/to/m00_00_00_00.talkesdbnd.dcx" --output "/existing/output/directory/m00_00_00_00.talkesdbnd.dcx"
```

You can select the Reforged folder or its `mod` folder directly. A talk archive is normally under Reforged's `mod/script/talk/` directory; its companion HKS is under `mod/action/script/c0000.hks`. If either file is missing or unrecognized, neither file is patched. Relative input/output paths are resolved against your terminal's current directory. Support files are always found relative to the Python scripts, independent of the current directory.

Without a mode option, separate `.uncapped.dcx` and `c0000.uncapped.hks` outputs are written beside their respective source files. With `--output`, the talk archive is written to the specified path and `c0000.hks` is written beside that output; use `--hks-output` to choose a different HKS destination. Copy those outputs into their respective `script/talk` and `action/script` folders when installing manually. Existing output files are not overwritten.

For an archive stored outside the normal mod layout, supply `--hks "/path/to/c0000.hks"`. The explicit `--esd-only` option retains the earlier archive-only behavior. By default both files are required.

Both candidates are validated before any write. In-place mode backs up every changed input, stages the files, and attempts to restore originals if a later write fails. The JSON report contains a `files` array with each file's source/output paths, method, changes, hashes and backup path. A new dated report is used when an earlier report exists. An already-patched talk archive does not prevent the HKS fix from being applied. When both files are already patched, nothing is written.

To undo an in-place patch, restore each changed file from its corresponding `.before-uncap-*.bak` backup.

## HKS level-cap edit

The HKS edit reproduces the earlier change in `ERR_StatPointEffects`: comment out the branch that sums all eight stats, checks a total of at least 356 and event flag 9969, and applies effect 9658. The rest of the file, including its newline style, is preserved. By default this includes only the level-cap edit. Weapon-level scaling is a separate optional component.

Recognized guard/sum patterns from 2.1.2.2, 2.3.3.2, and 2.3.4.0 are stored alongside the ESD signatures. Different variable names or arithmetic can be analyzed experimentally, provided the full eight-stat/flag/effect relationship is recognizable. The code only parses integer arithmetic; it never executes Lua/HKS. Ambiguous, missing, or unsupported branches are refused. The prior `--[[...]]` commented form is detected as already patched.

An unknown HKS pattern triggers the same experimental confirmation as an unknown ESD, even when the other file uses a known patch. Declining leaves both inputs untouched.

## Separate optional action: disable weapon-level enemy scaling

Both launchers provide independent actions:

- **6: Check weapon-level scaling patch only** — read-only.
- **7: Disable weapon-level enemy scaling only** — backs up and edits only `c0000.hks`.

These actions preserve the level-cap code and do not require or inspect the talk archive. Select the Reforged folder, its `mod` folder, or `c0000.hks` itself. Cap-removal actions never apply the scaling change or ask about it.

This applies the previous `ERR_WeaponLevel` edit: use neutral effect `109800` instead of `109800 + weapon level`. It disables the weapon-level component of enemy level scaling; it does not rewrite other difficulty or scaling systems.

Command-line equivalent:

```sh
python3 uncap_reforged.py "/path/to/Reforged" --weapon-scaling-only --check
python3 uncap_reforged.py "/path/to/c0000.hks" --weapon-scaling-only --in-place
```

You can use it before or after removing the level cap. Existing scaling edits are preserved by cap-only actions. To restore scaling, use the HKS backup from before the scaling change. Already-applied scaling patches are detected.

Known weapon-function patterns from 2.1.2.2, 2.3.3.2, and 2.3.4.0 are recognized. Unknown but recognizable patterns require experimental confirmation before writing; `--experimental --weapon-scaling-only --check` allows a read-only experimental check. Missing or ambiguous weapon-level patterns are refused.

The earlier `--disable-enemy-scaling` CLI option remains available for explicitly combining cap removal and scaling in one operation; the launchers use the independent action instead.

## Compatibility

Recognizes the relevant structures from Reforged 2.1.2.2, 2.3.3.2, and 2.3.4.0. It checks script structures and exact expression bytecode, not version numbers or whole-archive hashes. In the normal verified path, unrelated changes may be accepted; changed target logic or IDs are rejected unless experimental fallback is selected. Unsupported formats and incomplete/ambiguous patterns are still rejected. Future versions are not guaranteed to work.

The 2.3.3.2 output exactly reproduces a user-tested working cap removal and frozen-menu fix. The 2.1.2.2 output has passed structural checks but has not been tested in-game. Windows batch execution has not been tested on Windows.

## Experimental fallback for unrecognized versions

Known ESD structures and known HKS cap patterns always use their analyzed paths, even when `--experimental` is supplied. The signature database is still required.

For an unrecognized archive, experimental mode identifies linked eligibility, rune-withholding, and level-menu routines by their command expressions and relationships. It discovers script names, machine/state IDs and event-flag IDs from the archive. It then bypasses the discovered cap/cost routines, uses the existing direct OpenSoul transition, and removes effects 49/9658 only from recognized level-guarded branches. Other commands and states are preserved and checked after patching.

It still depends on recognizable ESD patterns, engine opcodes, stat IDs, Binding Rune item 807000 and known effect IDs. It cannot recognize arbitrary rewritten code or prove that an unfamiliar version works in-game. Missing, ambiguous, partially patched, or unsupported patterns are refused. It does not simply replace all occurrences of a number or effect.

The launchers provide experimental check/apply options. With an ordinary interactive apply, an unknown archive also gets experimental analysis and a confirmation offer if complete patterns are found. An ordinary interactive check asks before attempting experimental analysis. Noninteractive callers must explicitly supply `--experimental` to enable fallback.

```sh
# Read-only experimental analysis and in-memory candidate validation
python3 uncap_reforged.py "/path/to/m00_00_00_00.talkesdbnd.dcx" --experimental --check

# Known inputs use the verified path; unknown inputs ask before experimental writes
python3 uncap_reforged.py "/path/to/m00_00_00_00.talkesdbnd.dcx" --experimental --in-place
```

Before writing any experimental patch, the program shows its findings, destination and planned edit count, then asks:

> Apply experimental patching? It may or may not work in-game. [y/N]:

Only `y` or `yes` proceeds. No, blank input, or end-of-input leaves the archive untouched and creates no backup/output/report. `--experimental` does not skip this confirmation. Check mode never writes game files. Reports identify the ESD and HKS methods independently and include their findings.

Validation covers exact reproduction of the confirmed working 2.3.3.2 archive, structural checks on 2.1.2.2, and synthetic changes to script names, machine/state/flag IDs and rune costs. It also covers rejection of broken/ambiguous/partial patterns, repeat runs, confirmation decline/EOF, backups, reports and the Bash launcher. Synthetic compatibility tests are not in-game tests.

## Package contents

- `uncap_reforged.py`: verified patcher and experimental fallback/confirmation flow.
- `experimental_patterns.py`: experimental ESD structural recognizer and patcher.
- `hks_patch.py`: known/experimental HKS cap and optional weapon-level-scaling recognition and patching.
- `uncap_reforged.sh` / `uncap_reforged.bat`: interactive launchers.
- `inspect_esd.py`: archive inspector used by the patcher.
- `uncap-signatures.json`: recognized original/patched ESD structures and HKS cap/weapon-function fingerprints.
- `esdtool-v0.5.1/dist/ESDScriptingDocumentation_TalkER.xml` and `ESDScriptingDocumentation_Talk.json`: required command/function documentation, preserved from the ESDLang v0.5.1 tool bundle (https://github.com/thefifthmatt/ESDLang).

HKS integration checks cover both analyzed versions, reproduction of the prior cap-branch comment, already-patched ESD completion, missing/invalid HKS refusal, experimental decline/EOF, paired backups, copy outputs, and rollback after an injected second-file write failure. No new in-game validation or Windows execution was performed.

Optional-scaling validation covers both analyzed versions, opt-in after cap removal, repeated runs, backup preservation, Bash separate scaling check/apply actions, experimental confirmation for changed weapon functions, and reproduction of the previous combined HKS edits (while preserving the input newline style).

Separate-action validation confirms that scaling-only works on both versions without a talk archive, preserves the HKS cap branch, creates a backup, and detects repeated runs.

## Reforged 2.3.4.0 analysis

2.3.4.0 now uses the analyzed path for original and already-patched ESD/HKS files, including the optional weapon-scaling action. Its main level-triggered effects moved from state 44 to state 86; the known patch uses the profile-specific state location and verifies the complete resulting signatures. The experimental path remains available for other unrecognized structures.

The original ESD was reconstructed from the saved byte-change audit, with all 14 inspection dumps matching the saved original inspection exactly. Original HKS reconstruction matched its saved SHA-256. Known-path outputs are checked against the previously validated 2.3.4.0 patched files. This is structural validation; successful in-game behavior has not been confirmed in this conversation.
