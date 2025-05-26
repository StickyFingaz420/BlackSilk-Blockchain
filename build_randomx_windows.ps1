# BlackSilk RandomX Windows Build Script for Visual Studio 2022
# This script automatically builds RandomX library for Windows using Visual Studio 2022

param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

Write-Host "BlackSilk RandomX Windows Build Script" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Green

# Check if we're in the right directory
if (!(Test-Path "RandomX")) {
    Write-Host "Error: RandomX directory not found. Please run this script from the BlackSilk root directory." -ForegroundColor Red
    exit 1
}

# Check for Visual Studio 2022
$vsPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"
if (!(Test-Path $vsPath)) {
    $vsPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe"
    if (!(Test-Path $vsPath)) {
        $vsPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe"
        if (!(Test-Path $vsPath)) {
            Write-Host "Error: Visual Studio 2022 not found. Please install Visual Studio 2022." -ForegroundColor Red
            exit 1
        }
    }
}

Write-Host "Found Visual Studio 2022 at: $vsPath" -ForegroundColor Green

# Set up Visual Studio environment
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsInstallPath = & $vswhere -latest -property installationPath
    $vcvarsPath = "$vsInstallPath\VC\Auxiliary\Build\vcvars64.bat"
    
    if (Test-Path $vcvarsPath) {
        Write-Host "Setting up Visual Studio 2022 environment..." -ForegroundColor Yellow
        
        # Create a temporary batch file to set up environment and run cmake
        $tempBat = Join-Path $env:TEMP "build_randomx.bat"
        
        $batContent = @"
@echo off
call "$vcvarsPath"
cd /d "$PWD\RandomX"
if not exist build mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=$Configuration
if %ERRORLEVEL% neq 0 (
    echo CMake configuration failed
    exit /b 1
)
cmake --build . --config $Configuration
if %ERRORLEVEL% neq 0 (
    echo CMake build failed
    exit /b 1
)
echo Build completed successfully
"@
        
        $batContent | Out-File -FilePath $tempBat -Encoding ASCII
        
        Write-Host "Building RandomX with Visual Studio 2022..." -ForegroundColor Yellow
        $process = Start-Process -FilePath $tempBat -Wait -PassThru -NoNewWindow
        
        Remove-Item $tempBat -Force
        
        if ($process.ExitCode -eq 0) {
            Write-Host "RandomX build completed successfully!" -ForegroundColor Green
            
            # Check for output files
            $buildDir = "RandomX\build\$Configuration"
            $libFile = "$buildDir\randomx.lib"
            $dllFile = "$buildDir\randomx.dll"
            
            if (Test-Path $libFile) {
                Write-Host "Found randomx.lib at: $libFile" -ForegroundColor Green
                
                # Copy to miner directory
                Write-Host "Copying randomx.lib to miner directory..." -ForegroundColor Yellow
                Copy-Item $libFile "miner\" -Force
                
                if (Test-Path $dllFile) {
                    Write-Host "Found randomx.dll at: $dllFile" -ForegroundColor Green
                    Write-Host "Copying randomx.dll to miner directory..." -ForegroundColor Yellow
                    Copy-Item $dllFile "miner\" -Force
                } else {
                    Write-Host "Warning: randomx.dll not found. You may need to copy it manually." -ForegroundColor Yellow
                }
                
                Write-Host "" -ForegroundColor Green
                Write-Host "SUCCESS! RandomX libraries have been built and copied to miner directory." -ForegroundColor Green
                Write-Host "You can now run: cargo build --release -p blacksilk-miner" -ForegroundColor Green
                
            } else {
                Write-Host "Error: randomx.lib not found in expected location: $libFile" -ForegroundColor Red
                Write-Host "Please check the build output above for errors." -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Host "Error: RandomX build failed with exit code $($process.ExitCode)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "Error: vcvars64.bat not found at expected location: $vcvarsPath" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Error: vswhere.exe not found. Please ensure Visual Studio 2022 is properly installed." -ForegroundColor Red
    exit 1
}

Write-Host "" -ForegroundColor Green
Write-Host "Build completed! Files in miner directory:" -ForegroundColor Green
Get-ChildItem "miner\randomx.*" | ForEach-Object {
    Write-Host "  $($_.Name) - $([math]::Round($_.Length / 1KB, 2)) KB" -ForegroundColor Cyan
}
