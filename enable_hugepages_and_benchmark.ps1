# This PowerShell script will:
# 1. Grant your user the "Lock pages in memory" privilege (for Huge Pages)
# 2. Instruct you to log off and back in (required for privilege to take effect)
# 3. Open an Administrator PowerShell in the miner directory
# 4. Run the BlackSilk miner benchmark

# Get current username
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Grant "Lock pages in memory" privilege
gpedit = "SeLockMemoryPrivilege"
Write-Host "Granting 'Lock pages in memory' privilege to $user..."
secedit /export /cfg C:\lockpages.cfg
$content = Get-Content C:\lockpages.cfg
if ($content -notmatch $user) {
    $content = $content -replace "(SeLockMemoryPrivilege = .*)", "$1,$user"
    $content | Set-Content C:\lockpages.cfg
    secedit /import /cfg C:\lockpages.cfg /db secedit.sdb /overwrite
    gpupdate /force
    Write-Host "Privilege granted. You must log off and log back in for it to take effect."
    pause
    exit
} else {
    Write-Host "Privilege already granted."
}

# Open Administrator PowerShell in miner directory and run benchmark
$minerDir = "C:\Users\Brega05\Desktop\BlackSilk Blockchain\BlackSilk\target\release"
Start-Process powershell -Verb runAs -ArgumentList "-NoExit", "-Command", "cd '$minerDir'; .\blacksilk-miner.exe benchmark"
