# Runs a command with a time limit and kills only the process tree it started
# (tools/boundary-mutants.sh on Windows; Git Bash's `timeout` does not reach the
# test binaries cargo starts). Exit: the command's exit code, or 124 on timeout.
#
# Usage: run-with-timeout.ps1 -TimeoutSec N -WorkDir DIR -Log FILE -Exe EXE -ArgLine "ARGS"
# (the arguments as one string: PowerShell would read `--locked` and the like as
# its own parameters).
param(
    [Parameter(Mandatory = $true)][int]$TimeoutSec,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [Parameter(Mandatory = $true)][string]$Log,
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$ArgLine = ''
)
$ErrorActionPreference = 'Stop'

function Stop-Tree([int]$ProcessId) {
    Get-CimInstance Win32_Process -Filter "ParentProcessId = $ProcessId" |
        ForEach-Object { Stop-Tree $_.ProcessId }
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

$err = "$Log.stderr"
$p = Start-Process -FilePath $Exe -ArgumentList $ArgLine -WorkingDirectory $WorkDir `
    -NoNewWindow -PassThru -RedirectStandardOutput $Log -RedirectStandardError $err
$null = $p.Handle # keeps the exit code readable after the process ends
if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    Stop-Tree $p.Id
    $p.WaitForExit()
    Add-Content -Path $Log -Value "*** timed out after $TimeoutSec s"
    $code = 124
} else {
    $p.WaitForExit()
    $code = $p.ExitCode
}
if (Test-Path $err) { Get-Content $err | Add-Content -Path $Log; Remove-Item $err }
exit $code
