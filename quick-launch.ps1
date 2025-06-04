# BlackSilk Quick Launch Script for Windows
# Launches all BlackSilk blockchain components

param(
    [switch]$Testnet,
    [switch]$Mainnet,
    [switch]$NodeOnly,
    [switch]$NoFrontend,
    [switch]$Debug,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
BlackSilk Quick Launch Script for Windows

Usage: .\quick-launch.ps1 [OPTIONS]

OPTIONS:
    -Testnet      Launch in testnet mode (default)
    -Mainnet      Launch in mainnet mode
    -NodeOnly     Launch only the blockchain node
    -NoFrontend   Skip frontend services
    -Debug        Use debug binaries instead of release
    -Help         Show this help message

Examples:
    .\quick-launch.ps1                    # Launch full testnet
    .\quick-launch.ps1 -Mainnet           # Launch full mainnet
    .\quick-launch.ps1 -NodeOnly          # Launch only the node
    .\quick-launch.ps1 -Testnet -NoFrontend  # Launch backend only
"@
    exit 0
}

# Configuration
$IsTestnet = if ($Mainnet) { $false } else { $true }  # Default to testnet
$NetworkFlag = if ($IsTestnet) { "--testnet" } else { "--mainnet" }
$NetworkName = if ($IsTestnet) { "testnet" } else { "mainnet" }
$BuildMode = if ($Debug) { "debug" } else { "release" }
$BinaryPath = "target\$BuildMode"

Write-Host "🚀 BlackSilk Quick Launch Script for Windows" -ForegroundColor Cyan
Write-Host "===========================================" -ForegroundColor Cyan
Write-Host "Network: $NetworkName | Build: $BuildMode" -ForegroundColor Yellow

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

# Check if binaries exist
function Test-Binaries {
    Write-Log "Checking for built binaries..."
    
    $requiredBinaries = @("blacksilk-node.exe", "blacksilk-miner.exe", "wallet.exe")
    if (-not $NodeOnly) {
        $requiredBinaries += "blacksilk-marketplace.exe"
    }
    
    $missingBinaries = @()
    foreach ($binary in $requiredBinaries) {
        $fullPath = Join-Path $BinaryPath $binary
        if (-not (Test-Path $fullPath)) {
            $missingBinaries += $binary
        }
    }
    
    if ($missingBinaries.Count -gt 0) {
        Write-Error-Log "Missing binaries: $($missingBinaries -join ', ')"
        Write-Info "Please run .\build-full-project.ps1 first to build the project"
        exit 1
    }
    
    Write-Info "✓ All required binaries found"
}

# Create directories
function Initialize-Directories {
    Write-Log "Creating data and log directories..."
    
    $directories = @(
        "data\$NetworkName\node",
        "data\$NetworkName\miner", 
        "data\$NetworkName\wallet",
        "data\$NetworkName\marketplace",
        "logs\$NetworkName"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Info "Created directory: $dir"
        }
    }
}

# Launch blockchain node
function Start-BlockchainNode {
    Write-Log "Starting BlackSilk blockchain node..."
    
    $nodeArgs = @(
        $NetworkFlag,
        "--data-dir", "data\$NetworkName\node",
        "--log-level", "info"
    )
    
    # Add config file if it exists
    $configPath = "config\$NetworkName\node_config.toml"
    if (Test-Path $configPath) {
        $nodeArgs += "--config", $configPath
    }
    
    $nodeProcess = Start-Process -FilePath ".\$BinaryPath\blacksilk-node.exe" -ArgumentList $nodeArgs -PassThru -WindowStyle Normal
    
    if ($nodeProcess) {
        Write-Info "✓ Blockchain node started (PID: $($nodeProcess.Id))"
        Write-Info "  RPC: http://localhost:19334"
        Write-Info "  P2P: http://localhost:19333"
        Write-Info "  Metrics: http://localhost:9090"
        
        # Wait a moment for node to initialize
        Start-Sleep -Seconds 3
        return $nodeProcess
    } else {
        Write-Error-Log "Failed to start blockchain node"
        return $null
    }
}

# Launch miner
function Start-Miner {
    param([System.Diagnostics.Process]$NodeProcess)
    
    if (-not $NodeProcess -or $NodeProcess.HasExited) {
        Write-Warning "Node not running, skipping miner start"
        return $null
    }
    
    Write-Log "Starting BlackSilk miner..."
    
    $minerArgs = @(
        $NetworkFlag,
        "--threads", "2",
        "--data-dir", "data\$NetworkName\miner"
    )
    
    # Add config file if it exists
    $configPath = "config\miner_config.toml"
    if (Test-Path $configPath) {
        $minerArgs += "--config", $configPath
    }
    
    $minerProcess = Start-Process -FilePath ".\$BinaryPath\blacksilk-miner.exe" -ArgumentList $minerArgs -PassThru -WindowStyle Normal
    
    if ($minerProcess) {
        Write-Info "✓ Miner started (PID: $($minerProcess.Id))"
        return $minerProcess
    } else {
        Write-Error-Log "Failed to start miner"
        return $null
    }
}

# Launch wallet
function Start-Wallet {
    param([System.Diagnostics.Process]$NodeProcess)
    
    if (-not $NodeProcess -or $NodeProcess.HasExited) {
        Write-Warning "Node not running, skipping wallet start"
        return $null
    }
    
    Write-Log "Starting BlackSilk wallet..."
    
    $walletArgs = @(
        $NetworkFlag,
        "--api-port", "8080",
        "--data-dir", "data\$NetworkName\wallet"
    )
    
    # Add config file if it exists
    $configPath = "config\wallet_config.toml"
    if (Test-Path $configPath) {
        $walletArgs += "--config", $configPath
    }
    
    $walletProcess = Start-Process -FilePath ".\$BinaryPath\wallet.exe" -ArgumentList $walletArgs -PassThru -WindowStyle Normal
    
    if ($walletProcess) {
        Write-Info "✓ Wallet started (PID: $($walletProcess.Id))"
        Write-Info "  API: http://localhost:8080"
        return $walletProcess
    } else {
        Write-Error-Log "Failed to start wallet"
        return $null
    }
}

# Launch marketplace
function Start-Marketplace {
    param([System.Diagnostics.Process]$NodeProcess)
    
    if ($NodeOnly) {
        return $null
    }
    
    if (-not $NodeProcess -or $NodeProcess.HasExited) {
        Write-Warning "Node not running, skipping marketplace start"
        return $null
    }
    
    Write-Log "Starting BlackSilk marketplace..."
    
    $marketplaceArgs = @(
        $NetworkFlag,
        "--port", "3000",
        "--data-dir", "data\$NetworkName\marketplace"
    )
    
    # Add config file if it exists
    $configPath = "config\marketplace_config.toml"
    if (Test-Path $configPath) {
        $marketplaceArgs += "--config", $configPath
    }
    
    $marketplaceProcess = Start-Process -FilePath ".\$BinaryPath\blacksilk-marketplace.exe" -ArgumentList $marketplaceArgs -PassThru -WindowStyle Normal
    
    if ($marketplaceProcess) {
        Write-Info "✓ Marketplace started (PID: $($marketplaceProcess.Id))"
        Write-Info "  Web Interface: http://localhost:3000"
        return $marketplaceProcess
    } else {
        Write-Error-Log "Failed to start marketplace"
        return $null
    }
}

# Launch frontend services
function Start-FrontendServices {
    if ($NoFrontend -or $NodeOnly) {
        return
    }
    
    Write-Log "Starting frontend services..."
    
    # Check if Node.js is available
    try {
        & node --version | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Node.js not found"
        }
    }
    catch {
        Write-Warning "Node.js not found. Skipping frontend services."
        Write-Info "Install Node.js from https://nodejs.org/ to use frontend services"
        return
    }
    
    $frontendServices = @(
        @{Name="Testnet Faucet"; Path="testnet-faucet"; Port="3001"; Script="start"},
        @{Name="Block Explorer"; Path="block-explorer"; Port="3002"; Script="start"}, 
        @{Name="Web Wallet"; Path="web-wallet"; Port="3003"; Script="start"}
    )
    
    foreach ($service in $frontendServices) {
        if (Test-Path $service.Path) {
            Write-Info "Starting $($service.Name)..."
            
            Push-Location $service.Path
            try {
                # Check if start script exists
                $packageJson = Get-Content "package.json" -Raw | ConvertFrom-Json
                if ($packageJson.scripts.PSObject.Properties.Name -contains $service.Script) {
                    $process = Start-Process "npm" -ArgumentList "run", $service.Script -PassThru -WindowStyle Normal
                    if ($process) {
                        Write-Info "✓ $($service.Name) started (PID: $($process.Id), Port: $($service.Port))"
                    }
                } else {
                    Write-Warning "$($service.Name) does not have a '$($service.Script)' script"
                }
            }
            catch {
                Write-Warning "Failed to start $($service.Name): $($_.Exception.Message)"
            }
            finally {
                Pop-Location
            }
        }
    }
}

# Show running services
function Show-ServiceStatus {
    Write-Host ""
    Write-Log "BlackSilk $NetworkName network launched successfully!"
    Write-Host ""
    Write-Host "🌐 Access Points:" -ForegroundColor Yellow
    Write-Host "  • Node RPC API: http://localhost:19334" -ForegroundColor White
    Write-Host "  • Node P2P: http://localhost:19333" -ForegroundColor White  
    Write-Host "  • Node Metrics: http://localhost:9090" -ForegroundColor White
    Write-Host "  • Wallet API: http://localhost:8080" -ForegroundColor White
    
    if (-not $NodeOnly) {
        Write-Host "  • Marketplace: http://localhost:3000" -ForegroundColor White
        
        if (-not $NoFrontend) {
            Write-Host "  • Testnet Faucet: http://localhost:3001" -ForegroundColor White
            Write-Host "  • Block Explorer: http://localhost:3002" -ForegroundColor White
            Write-Host "  • Web Wallet: http://localhost:3003" -ForegroundColor White
        }
    }
    
    Write-Host ""
    Write-Host "📝 Commands:" -ForegroundColor Yellow
    Write-Host "  • Check processes: Get-Process | Where-Object {`$_.ProcessName -like '*blacksilk*'}" -ForegroundColor White
    Write-Host "  • Stop all: Get-Process | Where-Object {`$_.ProcessName -like '*blacksilk*'} | Stop-Process" -ForegroundColor White
    Write-Host "  • View logs: Get-Content logs\$NetworkName\*.log -Tail 50" -ForegroundColor White
    Write-Host ""
    Write-Host "Press Ctrl+C to stop all services" -ForegroundColor Red
}

# Cleanup function
function Stop-AllServices {
    Write-Log "Stopping all BlackSilk services..."
    
    try {
        Get-Process | Where-Object {$_.ProcessName -like "*blacksilk*"} | Stop-Process -Force
        Get-Process | Where-Object {$_.ProcessName -eq "node" -and $_.MainWindowTitle -like "*BlackSilk*"} | Stop-Process -Force
        Write-Info "✓ All services stopped"
    }
    catch {
        Write-Warning "Some processes may still be running"
    }
}

# Handle Ctrl+C
$null = Register-EngineEvent PowerShell.Exiting -Action {
    Stop-AllServices
}

# Main execution
function Main {
    try {
        Test-Binaries
        Initialize-Directories
        
        # Start core services
        $nodeProcess = Start-BlockchainNode
        if (-not $nodeProcess) {
            Write-Error-Log "Failed to start node, aborting launch"
            exit 1
        }
        
        # Wait for node to be ready
        Write-Info "Waiting for node to initialize..."
        Start-Sleep -Seconds 5
        
        if (-not $NodeOnly) {
            $minerProcess = Start-Miner -NodeProcess $nodeProcess
            $walletProcess = Start-Wallet -NodeProcess $nodeProcess  
            $marketplaceProcess = Start-Marketplace -NodeProcess $nodeProcess
            
            # Start frontend services
            Start-FrontendServices
        }
        
        Show-ServiceStatus
        
        # Keep script running
        Write-Host "Services are running. Press Ctrl+C to stop all services." -ForegroundColor Green
        try {
            while ($true) {
                Start-Sleep -Seconds 1
            }
        }
        catch [System.Management.Automation.PipelineStoppedException] {
            # User pressed Ctrl+C
            Stop-AllServices
        }
    }
    catch {
        Write-Error-Log "Launch failed: $($_.Exception.Message)"
        Stop-AllServices
        exit 1
    }
}

# Run main function
Main
