# W4-RX memory/CPU monitor for the full-mode seed-switch labnet run.
# Samples every $Every seconds: free physical memory, and the working set,
# private bytes and CPU time of every blacksilk process whose command line
# contains $Tag. If free memory stays below $LowMb for 3 samples, the light
# miner (command line with --light) is suspended; it is resumed once free
# memory is above $ResumeMb. Only processes of this run are touched.
param(
    [string]$Tag = "w4-rx\run1",
    [string]$Csv = "C:\bszkeval\w4-rx\monitor-run1.csv",
    [int]$Every = 10,
    [int]$LowMb = 1500,
    [int]$ResumeMb = 2500
)

$sig = @"
using System;
using System.Runtime.InteropServices;
public static class W4Susp {
  [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
  [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
}
"@
Add-Type -TypeDefinition $sig

"unix,free_mb,name,pid,ws_mb,private_mb,cpu_s,suspended" | Out-File -FilePath $Csv -Encoding ascii
$low = 0
$suspended = $null
while ($true) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $free = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024)
    $procs = Get-CimInstance Win32_Process -Filter "Name LIKE 'blacksilk-%'" |
        Where-Object { $_.CommandLine -and $_.CommandLine.Contains($Tag) }
    $light = $null
    $lines = @()
    foreach ($p in $procs) {
        $gp = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
        if (-not $gp) { continue }
        $name = $p.Name
        if ($p.Name -eq "blacksilk-miner.exe") {
            if ($p.CommandLine.Contains("--light")) { $name = "miner-light"; $light = $gp } else { $name = "miner-full" }
        } elseif ($p.Name -eq "blacksilk-node.exe") {
            if ($p.CommandLine -match "node(\d|-late)") { $name = "node" + $Matches[1] }
        }
        $isSusp = ($suspended -ne $null -and $suspended -eq $gp.Id)
        $lines += "$now,$free,$name,$($gp.Id),$([math]::Round($gp.WorkingSet64/1MB)),$([math]::Round($gp.PrivateMemorySize64/1MB)),$([math]::Round($gp.TotalProcessorTime.TotalSeconds,1)),$isSusp"
    }
    if ($lines.Count -eq 0) { $lines += "$now,$free,none,0,0,0,0,False" }
    $lines | Out-File -FilePath $Csv -Append -Encoding ascii
    if ($free -lt $LowMb) { $low++ } else { $low = 0 }
    if ($low -ge 3 -and $light -and -not $suspended) {
        [void][W4Susp]::NtSuspendProcess($light.Handle)
        $suspended = $light.Id
        "$now,$free,SUSPENDED light miner $($light.Id)" | Out-File -FilePath $Csv -Append -Encoding ascii
    }
    if ($suspended -and $free -gt $ResumeMb) {
        $gp = Get-Process -Id $suspended -ErrorAction SilentlyContinue
        if ($gp) { [void][W4Susp]::NtResumeProcess($gp.Handle) }
        "$now,$free,RESUMED light miner $suspended" | Out-File -FilePath $Csv -Append -Encoding ascii
        $suspended = $null
    }
    Start-Sleep -Seconds $Every
}
