@echo off
REM BlackSilk RandomX Windows Build Script for Visual Studio 2022
REM This script automatically builds RandomX library for Windows

echo BlackSilk RandomX Windows Build Script
echo =====================================

REM Check if we're in the right directory
if not exist "RandomX" (
    echo Error: RandomX directory not found. Please run this script from the BlackSilk root directory.
    pause
    exit /b 1
)

REM Find Visual Studio 2022
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo Error: Visual Studio Installer not found. Please install Visual Studio 2022.
    pause
    exit /b 1
)

echo Finding Visual Studio 2022...
for /f "delims=" %%i in ('"%VSWHERE%" -latest -property installationPath') do set "VSINSTALLPATH=%%i"

if "%VSINSTALLPATH%"=="" (
    echo Error: Visual Studio 2022 not found. Please install Visual Studio 2022.
    pause
    exit /b 1
)

set "VCVARS=%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo Error: vcvars64.bat not found. Please check Visual Studio 2022 installation.
    pause
    exit /b 1
)

echo Found Visual Studio 2022 at: %VSINSTALLPATH%
echo Setting up build environment...

REM Set up Visual Studio environment
call "%VCVARS%"

echo Building RandomX...
cd RandomX

if not exist build mkdir build
cd build

echo Running CMake configuration...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
if %ERRORLEVEL% neq 0 (
    echo CMake configuration failed
    pause
    exit /b 1
)

echo Building RandomX library...
cmake --build . --config Release
if %ERRORLEVEL% neq 0 (
    echo CMake build failed
    pause
    exit /b 1
)

cd ..\..

echo Copying files to miner directory...
if exist "RandomX\build\Release\randomx.lib" (
    copy "RandomX\build\Release\randomx.lib" "miner\" >nul
    echo Successfully copied randomx.lib
) else (
    echo Error: randomx.lib not found in RandomX\build\Release\
    pause
    exit /b 1
)

if exist "RandomX\build\Release\randomx.dll" (
    copy "RandomX\build\Release\randomx.dll" "miner\" >nul
    echo Successfully copied randomx.dll
) else (
    echo Warning: randomx.dll not found in RandomX\build\Release\
)

echo.
echo SUCCESS! RandomX libraries have been built and copied to miner directory.
echo You can now run: cargo build --release -p blacksilk-miner
echo.
echo Files in miner directory:
dir miner\randomx.* /B

pause
