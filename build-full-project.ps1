# BlackSilk Complete Build Script for Windows
# Builds all components of the BlackSilk blockchain project

param(
    [switch]$SkipFrontend,
    [switch]$Debug,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
BlackSilk Build Script for Windows

Usage: .\build-full-project.ps1 [OPTIONS]

OPTIONS:
    -SkipFrontend    Skip building frontend components (Node.js not required)
    -Debug           Build in debug mode instead of release mode
    -Help            Show this help message

Examples:
    .\build-full-project.ps1                # Build everything in release mode
    .\build-full-project.ps1 -Debug         # Build in debug mode
    .\build-full-project.ps1 -SkipFrontend  # Build only Rust components
"@
    exit 0
}

# Configuration
$BuildMode = if ($Debug) { "debug" } else { "release" }
$BuildFlags = if ($Debug) { "--bins" } else { "--release", "--bins" }

Write-Host "🏗️  BlackSilk Complete Build Script for Windows" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor Green
}

function Write-Error-Log {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

# Check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    # Check Rust
    try {
        $rustVersion = & rustc --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Rust not found"
        }
        
        $versionMatch = $rustVersion -match '(\d+)\.(\d+)'
        if ($versionMatch) {
            $major = [int]$matches[1]
            $minor = [int]$matches[2]
            
            if ($major -lt 1 -or ($major -eq 1 -and $minor -lt 77)) {
                Write-Error-Log "Rust version $($matches[0]) found. BlackSilk requires Rust 1.77+ for Cargo.lock v4 support"
                Write-Host "Please update Rust: https://rustup.rs/" -ForegroundColor Yellow
                exit 1
            }
        }
        
        Write-Info "✓ Rust detected: $rustVersion"
    }
    catch {
        Write-Error-Log "Rust not found. Please install Rust 1.77+ from https://rustup.rs/"
        exit 1
    }
    
    # Check Cargo
    try {
        $cargoVersion = & cargo --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "Cargo not found"
        }
        Write-Info "✓ Cargo detected: $cargoVersion"
    }
    catch {
        Write-Error-Log "Cargo not found. Please ensure Rust is properly installed."
        exit 1
    }
    
    # Check Node.js (optional)
    if (-not $SkipFrontend) {
        try {
            $nodeVersion = & node --version 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Node.js not found"
            }
            
            $nodeVersionNumber = ($nodeVersion -replace 'v', '') -split '\.' | Select-Object -First 1
            if ([int]$nodeVersionNumber -lt 18) {
                Write-Warning "Node.js version $nodeVersion found. Recommended: 18+"
            }
            
            Write-Info "✓ Node.js detected: $nodeVersion"
        }
        catch {
            Write-Warning "Node.js not found. Frontend services will be skipped."
            Write-Warning "Install Node.js 18+ from https://nodejs.org/ to build frontend components"
            $script:SkipFrontend = $true
        }
        
        # Check npm
        try {
            $npmVersion = & npm --version 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "npm not found"
            }
            Write-Info "✓ npm detected: v$npmVersion"
        }
        catch {
            if (-not $SkipFrontend) {
                Write-Warning "npm not found. Frontend builds may fail."
            }
        }
    }
}

# Build Rust components
function Build-RustComponents {
    Write-Log "Building Rust blockchain components..."
    
    Write-Info "Building all binaries in $BuildMode mode..."
    
    try {
        & cargo build @BuildFlags
        if ($LASTEXITCODE -ne 0) {
            throw "Cargo build failed"
        }
        Write-Log "✓ Rust components built successfully"
    }
    catch {
        Write-Error-Log "Failed to build Rust components"
        exit 1
    }
    
    # Verify binaries
    Write-Log "Verifying built binaries..."
    
    $expectedBinaries = @("BlackSilk.exe", "blacksilk-node.exe", "blacksilk-miner.exe", "blacksilk-marketplace.exe", "wallet.exe")
    $missingBinaries = @()
    $binaryPath = "target\$BuildMode"
    
    foreach ($binary in $expectedBinaries) {
        $fullPath = Join-Path $binaryPath $binary
        if (Test-Path $fullPath) {
            $size = (Get-Item $fullPath).Length
            $sizeString = if ($size -gt 1MB) { 
                "{0:N1} MB" -f ($size / 1MB) 
            } else { 
                "{0:N0} KB" -f ($size / 1KB) 
            }
            Write-Info "✓ $binary ($sizeString)"
        } else {
            $missingBinaries += $binary
        }
    }
    
    if ($missingBinaries.Count -gt 0) {
        Write-Error-Log "Missing binaries: $($missingBinaries -join ', ')"
        exit 1
    }
    
    Write-Log "✓ All core blockchain binaries built successfully"
}

# Build frontend components
function Build-FrontendComponents {
    if ($SkipFrontend) {
        Write-Warning "Skipping frontend builds (Node.js not available or -SkipFrontend specified)"
        return
    }
    
    Write-Log "Building frontend components..."
    
    $frontendDirs = @(
        @{Name="Testnet Faucet"; Path="testnet-faucet"},
        @{Name="Block Explorer"; Path="block-explorer"},
        @{Name="Web Wallet"; Path="web-wallet"},
        @{Name="Marketplace Frontend"; Path="marketplace\frontend"}
    )
    
    foreach ($dir in $frontendDirs) {
        if (Test-Path $dir.Path) {
            Write-Info "Building $($dir.Name)..."
            
            Push-Location $dir.Path
            try {
                # Install dependencies
                & npm install --silent 2>$null
                if ($LASTEXITCODE -eq 0) {
                    # Try to build
                    & npm run build --silent 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Info "✓ $($dir.Name) built successfully"
                    } else {
                        Write-Warning "$($dir.Name) build failed or no build script available"
                    }
                } else {
                    Write-Warning "Failed to install dependencies for $($dir.Name)"
                }
            }
            catch {
                Write-Warning "Error building $($dir.Name): $($_.Exception.Message)"
            }
            finally {
                Pop-Location
            }
        }
    }
    
    Write-Log "✓ Frontend components build completed"
}

# Display build summary
function Show-BuildSummary {
    Write-Log "Build Summary"
    Write-Host "=============" -ForegroundColor Cyan
    
    Write-Host "📦 Core Blockchain Binaries:" -ForegroundColor Yellow
    $binaryPath = "target\$BuildMode"
    
    $coreFiles = @("BlackSilk.exe", "blacksilk-node.exe", "blacksilk-miner.exe", "blacksilk-marketplace.exe", "wallet.exe")
    foreach ($file in $coreFiles) {
        $fullPath = Join-Path $binaryPath $file
        if (Test-Path $fullPath) {
            $size = (Get-Item $fullPath).Length
            $sizeString = if ($size -gt 1MB) { 
                "{0:N1} MB" -f ($size / 1MB) 
            } else { 
                "{0:N0} KB" -f ($size / 1KB) 
            }
            Write-Host "  ✓ $fullPath ($sizeString)" -ForegroundColor Green
        }
    }
    
    if (-not $SkipFrontend) {
        Write-Host ""
        Write-Host "🌐 Frontend Services:" -ForegroundColor Yellow
        $frontendDirs = @("testnet-faucet", "block-explorer", "web-wallet", "marketplace\frontend")
        foreach ($dir in $frontendDirs) {
            if (Test-Path "$dir\node_modules") {
                Write-Host "  ✓ $dir (dependencies installed)" -ForegroundColor Green
            }
        }
    }
    
    Write-Host ""
    Write-Host "🚀 Next Steps:" -ForegroundColor Yellow
    Write-Host "  1. Run '.\target\$BuildMode\blacksilk-node.exe --testnet' to start the blockchain" -ForegroundColor White
    Write-Host "  2. Run '.\target\$BuildMode\blacksilk-miner.exe --testnet' to start mining" -ForegroundColor White
    Write-Host "  3. Run '.\target\$BuildMode\wallet.exe --help' for wallet commands" -ForegroundColor White
    Write-Host "  4. Check README.md for complete launch instructions" -ForegroundColor White
    
    if (-not $SkipFrontend) {
        Write-Host "  5. Use 'npm run start' in frontend directories to launch services" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "📝 Windows-specific notes:" -ForegroundColor Yellow
    Write-Host "  • Use PowerShell or Command Prompt to run binaries" -ForegroundColor White
    Write-Host "  • Add .exe extension when running binaries manually" -ForegroundColor White
    Write-Host "  • Use .\quick-launch.ps1 for easy startup" -ForegroundColor White
}

# Main execution
function Main {
    try {
        Test-Prerequisites
        Build-RustComponents
        Build-FrontendComponents
        Show-BuildSummary
        
        Write-Log "🎉 BlackSilk build completed successfully!"
    }
    catch {
        Write-Error-Log "Build failed: $($_.Exception.Message)"
        exit 1
    }
}

# Run main function
Main
