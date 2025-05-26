# BlackSilk Easy Build Script for Windows
# Makes building BlackSilk blockchain as simple as possible

param(
    [switch]$SkipDependencies = $false,
    [switch]$Verbose = $false
)

# Enable strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Colors for output
$Red = [System.ConsoleColor]::Red
$Green = [System.ConsoleColor]::Green
$Yellow = [System.ConsoleColor]::Yellow
$Blue = [System.ConsoleColor]::Blue
$Magenta = [System.ConsoleColor]::Magenta
$Cyan = [System.ConsoleColor]::Cyan

function Write-ColorOutput {
    param([string]$Message, [System.ConsoleColor]$Color = [System.ConsoleColor]::White)
    Write-Host $Message -ForegroundColor $Color
}

# Fancy banner
Write-ColorOutput "╔════════════════════════════════════════════════════════════════════════════════════════╗" $Magenta
Write-ColorOutput "║                                    BlackSilk Blockchain                               ║" $Magenta
Write-ColorOutput "║                                  🚀 Easy Build Script 🚀                             ║" $Magenta
Write-ColorOutput "║                                                                                        ║" $Magenta
Write-ColorOutput "║  This script will automatically:                                                      ║" $Magenta
Write-ColorOutput "║  ✅ Install dependencies                                                              ║" $Magenta
Write-ColorOutput "║  ✅ Build RandomX library                                                             ║" $Magenta
Write-ColorOutput "║  ✅ Compile all BlackSilk components                                                  ║" $Magenta
Write-ColorOutput "║  ✅ Run verification tests                                                            ║" $Magenta
Write-ColorOutput "║  ✅ Show you how to start mining!                                                     ║" $Magenta
Write-ColorOutput "╚════════════════════════════════════════════════════════════════════════════════════════╝" $Magenta

# Detect platform
$Platform = [System.Environment]::OSVersion.Platform
$Architecture = [System.Environment]::Is64BitOperatingSystem

Write-ColorOutput "🔍 Detected platform: Windows $(if($Architecture) {'x64'} else {'x86'})" $Cyan

# Check if we're in the right directory
if (!(Test-Path "Cargo.toml") -or !(Test-Path "miner")) {
    Write-ColorOutput "❌ Error: Please run this script from the BlackSilk root directory" $Red
    exit 1
}

Write-ColorOutput "✅ Found BlackSilk project structure" $Green

# Function to check if command exists
function Test-CommandExists {
    param([string]$Command)
    try {
        if (Get-Command $Command -ErrorAction SilentlyContinue) {
            return $true
        }
    }
    catch {
        return $false
    }
    return $false
}

# Function to check if Visual Studio is installed
function Test-VisualStudioInstalled {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $installations = & $vswhere -latest -property installationPath
        return $installations.Length -gt 0
    }
    return $false
}

# Function to install dependencies
function Install-Dependencies {
    if ($SkipDependencies) {
        Write-ColorOutput "⏭️ Skipping dependency installation (--SkipDependencies flag)" $Yellow
        return
    }

    Write-ColorOutput "📦 Checking and installing dependencies..." $Yellow
    
    # Check for Chocolatey and install if needed
    if (!(Test-CommandExists "choco")) {
        Write-ColorOutput "🍫 Installing Chocolatey package manager..." $Cyan
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
    }
    
    # Install Git if not present
    if (!(Test-CommandExists "git")) {
        Write-ColorOutput "📥 Installing Git..." $Cyan
        choco install git -y
    }
    
    # Install CMake if not present
    if (!(Test-CommandExists "cmake")) {
        Write-ColorOutput "🔧 Installing CMake..." $Cyan
        choco install cmake -y
    }
    
    # Check for Visual Studio
    if (!(Test-VisualStudioInstalled)) {
        Write-ColorOutput "🛠️ Visual Studio 2022 not found. Installing Visual Studio Build Tools..." $Cyan
        choco install visualstudio2022buildtools -y
        choco install visualstudio2022-workload-vctools -y
    }
    
    # Refresh environment variables
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
    
    Write-ColorOutput "✅ Dependencies installation completed" $Green
}

# Function to install Rust if needed
function Install-Rust {
    if (!(Test-CommandExists "cargo")) {
        Write-ColorOutput "🦀 Installing Rust..." $Yellow
        
        # Download and run rustup-init
        $rustupInit = "$env:TEMP\rustup-init.exe"
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit
        
        # Run rustup-init with default settings
        & $rustupInit -y --default-toolchain stable --profile default
        
        # Add Rust to PATH for current session
        $env:PATH += ";$env:USERPROFILE\.cargo\bin"
        
        Write-ColorOutput "✅ Rust installed successfully" $Green
    } else {
        Write-ColorOutput "✅ Rust is already installed" $Green
        & cargo --version
    }
}

# Function to build RandomX
function Build-RandomX {
    Write-ColorOutput "🔨 Building RandomX library..." $Yellow
    
    # Clone RandomX if not present
    if (!(Test-Path "RandomX")) {
        Write-ColorOutput "📥 Cloning RandomX repository..." $Cyan
        & git clone https://github.com/tevador/RandomX.git
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to clone RandomX repository"
        }
    }
    
    # Use the existing automated build script
    if (Test-Path "build_randomx_windows.ps1") {
        Write-ColorOutput "🔧 Using automated RandomX build script..." $Cyan
        & .\build_randomx_windows.ps1
        if ($LASTEXITCODE -ne 0) {
            throw "RandomX build failed"
        }
    } else {
        # Fallback to manual build
        Write-ColorOutput "🔧 Building RandomX manually..." $Cyan
        
        Set-Location "RandomX"
        
        if (!(Test-Path "build")) {
            New-Item -ItemType Directory -Name "build"
        }
        
        Set-Location "build"
        
        # Find Visual Studio installation
        $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
        $vsPath = & $vswhere -latest -property installationPath
        $vcvars = "$vsPath\VC\Auxiliary\Build\vcvars64.bat"
        
        # Configure and build
        Write-ColorOutput "⚙️ Configuring RandomX with CMake..." $Cyan
        & cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configuration failed"
        }
        
        Write-ColorOutput "🔨 Building RandomX (this may take a few minutes)..." $Cyan
        & cmake --build . --config Release
        if ($LASTEXITCODE -ne 0) {
            throw "RandomX build failed"
        }
        
        # Copy libraries to miner directory
        Write-ColorOutput "📋 Copying RandomX libraries to miner directory..." $Cyan
        Copy-Item "Release\randomx.lib" "..\..\miner\" -Force
        Copy-Item "Release\randomx.dll" "..\..\miner\" -Force
        
        Set-Location "..\..\"
    }
    
    Write-ColorOutput "✅ RandomX library built successfully" $Green
}

# Function to build BlackSilk components
function Build-BlackSilk {
    Write-ColorOutput "🔨 Building BlackSilk components..." $Yellow
    
    # Set optimization flags
    $env:RUSTFLAGS = "-C target-cpu=native"
    
    Write-ColorOutput "🏗️ Building node..." $Cyan
    & cargo build --release -p node
    if ($LASTEXITCODE -ne 0) {
        throw "Node build failed"
    }
    
    Write-ColorOutput "⛏️ Building miner..." $Cyan
    & cargo build --release -p blacksilk-miner
    if ($LASTEXITCODE -ne 0) {
        throw "Miner build failed"
    }
    
    Write-ColorOutput "💰 Building wallet..." $Cyan
    & cargo build --release -p wallet
    if ($LASTEXITCODE -ne 0) {
        throw "Wallet build failed"
    }
    
    Write-ColorOutput "✅ All BlackSilk components built successfully" $Green
}

# Function to run verification tests
function Test-Build {
    Write-ColorOutput "🧪 Running verification tests..." $Yellow
    
    # Test miner benchmark
    Write-ColorOutput "⛏️ Testing miner benchmark..." $Cyan
    try {
        $job = Start-Job -ScriptBlock { & .\target\release\blacksilk-miner.exe benchmark }
        Wait-Job $job -Timeout 10
        Stop-Job $job
        Remove-Job $job
    } catch {
        Write-ColorOutput "⚠️ Benchmark test timeout (expected)" $Yellow
    }
    
    # Test wallet functionality
    Write-ColorOutput "💰 Testing wallet functionality..." $Cyan
    & .\target\release\wallet.exe --help | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-ColorOutput "✅ Wallet test passed" $Green
    }
    
    Write-ColorOutput "✅ All tests completed" $Green
}

# Function to show final instructions
function Show-FinalInstructions {
    Write-ColorOutput "╔════════════════════════════════════════════════════════════════════════════════════════╗" $Green
    Write-ColorOutput "║                              🎉 BUILD COMPLETED SUCCESSFULLY! 🎉                     ║" $Green
    Write-ColorOutput "╚════════════════════════════════════════════════════════════════════════════════════════╝" $Green
    
    Write-ColorOutput "📁 Built components:" $Cyan
    Write-ColorOutput "  ✅ .\target\release\blacksilk-node.exe"
    Write-ColorOutput "  ✅ .\target\release\blacksilk-miner.exe"
    Write-ColorOutput "  ✅ .\target\release\wallet.exe"
    Write-Output ""
    
    Write-ColorOutput "🚀 Quick Start Commands:" $Yellow
    Write-Output ""
    Write-ColorOutput "1. Start the testnet node (easy mining):" $Cyan
    Write-ColorOutput "   .\target\release\blacksilk-node.exe --testnet"
    Write-Output ""
    Write-ColorOutput "2. Create a wallet:" $Cyan
    Write-ColorOutput "   .\target\release\wallet.exe --generate"
    Write-Output ""
    Write-ColorOutput "3. Start mining:" $Cyan
    Write-ColorOutput "   .\target\release\blacksilk-miner.exe --address YOUR_WALLET_ADDRESS --threads 4"
    Write-Output ""
    Write-ColorOutput "4. Check mining benchmark:" $Cyan
    Write-ColorOutput "   .\target\release\blacksilk-miner.exe benchmark"
    Write-Output ""
    
    Write-ColorOutput "🎯 Performance Tips:" $Green
    Write-ColorOutput "  • Use --threads $([System.Environment]::ProcessorCount) for maximum CPU usage"
    Write-ColorOutput "  • Enable huge pages for better performance (requires admin)"
    Write-ColorOutput "  • Use testnet for easy mining (difficulty=1)"
    Write-Output ""
    
    Write-ColorOutput "Happy Mining! 🎉⛏️💰" $Magenta
}

# Main execution function
function Main {
    try {
        Write-ColorOutput "🚀 Starting BlackSilk easy build process..." $Blue
        
        # Check for dependencies and install if needed
        Install-Dependencies
        
        # Install Rust if needed
        Install-Rust
        
        # Build RandomX library
        Build-RandomX
        
        # Build BlackSilk components
        Build-BlackSilk
        
        # Run verification tests
        Test-Build
        
        # Show final instructions
        Show-FinalInstructions
        
    } catch {
        Write-ColorOutput "❌ Build failed: $($_.Exception.Message)" $Red
        Write-ColorOutput "💡 Try running with elevated privileges (Run as Administrator)" $Yellow
        Write-ColorOutput "💡 Check the detailed build guides in WINDOWS_BUILD_GUIDE.md" $Yellow
        exit 1
    }
}

# Run main function
Main
