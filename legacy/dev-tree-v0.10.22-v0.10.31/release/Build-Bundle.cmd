@echo off
rem Bundles every Python package NodeWatch needs, for Windows and Mac (v0.10.22).
rem Double-click on a Windows PC with internet access. No Python install is needed: it uses the
rem interpreter shipped in runtime\python. Afterwards run release\generate_integrity.py --update-launcher,
rem build and sign NodeWatch.exe (docs\RELEASE_PROCESS.md) - or send the zip it makes to whoever builds it.
setlocal
cd /d "%~dp0.."
if not exist "runtime\python\python.exe" (
  echo runtime\python\python.exe is missing - run this from a complete NodeWatch _internal folder.
  goto :fail
)
"runtime\python\python.exe" -s tools\bundle_site_packages.py --platforms all || goto :fail
powershell -NoProfile -Command "Compress-Archive -Force -Path 'runtime\site-packages','runtime-macos' -DestinationPath '..\nodewatch-site-packages.zip'; Copy-Item -Force '..\nodewatch-site-packages.zip' ([Environment]::GetFolderPath('Desktop'))" || goto :fail
echo.
echo Done. runtime\site-packages is ready; nodewatch-site-packages.zip is next to NodeWatch.exe and on your Desktop.
pause
exit /b 0
:fail
echo.
echo FAILED - see the messages above (internet access to PyPI or your pip mirror is required).
pause
exit /b 1
