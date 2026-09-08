@echo off
setlocal DisableDelayedExpansion
 title Reforged level-cap removal and menu fix

rem Keep this launcher beside uncap_reforged.py and its support files.
set "tool_dir=%~dp0"
set "python_cmd="
py -3 -c "import sys; sys.exit(sys.version_info.major != 3)" >nul 2>&1
if not errorlevel 1 goto use_py
python -c "import sys; sys.exit(sys.version_info.major != 3)" >nul 2>&1
if not errorlevel 1 goto use_python
python3 -c "import sys; sys.exit(sys.version_info.major != 3)" >nul 2>&1
if not errorlevel 1 goto use_python3
echo Python 3 was not found. Install Python 3 with the Python launcher or add it to PATH.
goto failure

:use_py
set "python_cmd=py -3"
goto dependencies
:use_python
set "python_cmd=python"
goto dependencies
:use_python3
set "python_cmd=python3"

:dependencies
for %%F in ("uncap_reforged.py" "hks_patch.py" "experimental_patterns.py" "inspect_esd.py" "uncap-signatures.json" "esdtool-v0.5.1\dist\ESDScriptingDocumentation_TalkER.xml" "esdtool-v0.5.1\dist\ESDScriptingDocumentation_Talk.json") do (
    if not exist "%tool_dir%%%~F" (
        echo Missing support file: "%tool_dir%%%~F"
        goto failure
    )
)

echo Reforged level-cap removal and menu fix
echo.
echo Analyzed versions: Reforged 2.1.2.2, 2.3.3.2, and 2.3.4.0.
echo For every other version, use the experimental cap options 4/5.
echo Experimental patches may or may not work; unsupported patterns are refused.
echo Choose a check first. Checks do not change files; apply actions create backups.
echo.
echo 1) Check level-cap patch - Reforged 2.1.2.2 / 2.3.3.2 / 2.3.4.0
echo    Checks the talk archive and c0000.hks without changing them.
echo 2) Remove level cap - Reforged 2.1.2.2 / 2.3.3.2 / 2.3.4.0
echo    Backs up and patches both files. Keeps weapon-level scaling unchanged.
echo 3) Cancel
echo 4) Experimental level-cap check - every other Reforged version
echo    Looks for compatible code patterns and validates a candidate in memory.
echo 5) Experimental level-cap removal - every other Reforged version
echo    Asks for confirmation before patching. In-game compatibility is unverified.
echo 6) Check weapon-level scaling patch only - separate optional action
echo    Analyzed for 2.1.2.2 / 2.3.3.2 / 2.3.4.0; other versions offer experimental analysis.
echo 7) Disable weapon-level enemy scaling only - separate optional action
echo    Edits only c0000.hks; keeps the level cap unchanged.
echo    Analyzed for 2.1.2.2 / 2.3.3.2 / 2.3.4.0; other versions require experimental consent.
echo.
set "patch_extra="
set "patch_scaling="
choice /c 1234567 /n /m "Choose [1/2/3/4/5/6/7]: "
if errorlevel 8 goto failure
if errorlevel 7 goto scaling_apply
if errorlevel 6 goto scaling_check
if errorlevel 5 goto experimental_apply
if errorlevel 4 goto experimental_check
if errorlevel 3 goto cancelled
if errorlevel 2 goto apply
if errorlevel 1 goto check
goto failure

:scaling_check
set "patch_scaling=--weapon-scaling-only"
goto check
:scaling_apply
set "patch_scaling=--weapon-scaling-only"
goto apply
:experimental_check
set "patch_extra=--experimental"
goto check
:experimental_apply
set "patch_extra=--experimental"
goto apply
:check
set "patch_mode=--check"
goto ask_file
:apply
set "patch_mode=--in-place"

:ask_file
echo.
if defined patch_scaling (
    echo Paste or drag the Reforged/mod folder, or c0000.hks. This action changes weapon-level enemy scaling only.
) else (
    echo Paste or drag the Reforged/mod folder, or its talk archive. This action checks the level-cap patches in both files.
)
echo Spaces and surrounding double quotes are supported.
set "ERR_UNCAP_INPUT="
set /p "ERR_UNCAP_INPUT=Folder or file (blank to cancel): "
if not defined ERR_UNCAP_INPUT goto cancelled
rem Pass user input through the environment, never interpolate it into a command.
rem Python removes drag-and-drop quotes and passes the path as a single argument.
%python_cmd% -c "import os,sys,subprocess; from pathlib import Path; p=os.environ['ERR_UNCAP_INPUT'].strip().strip(chr(34)); f=Path(p).expanduser(); sys.exit(subprocess.call([sys.executable,sys.argv[1],sys.argv[2]]+([sys.argv[3]] if sys.argv[3] else [])+([sys.argv[4]] if sys.argv[4] else [])+['--',str(f)]) if (f.is_file() or f.is_dir()) else 3)" "%tool_dir%uncap_reforged.py" "%patch_mode%" "%patch_extra%" "%patch_scaling%"
if errorlevel 4 goto failure
if errorlevel 3 goto invalid_file
if errorlevel 1 goto failure
echo.
pause
exit /b 0

:invalid_file
echo Folder or file not found. Please try again.
goto ask_file

:failure
echo.
echo The operation failed. See the message above.
pause
exit /b 1

:cancelled
exit /b 0
