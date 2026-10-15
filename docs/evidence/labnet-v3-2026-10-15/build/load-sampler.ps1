# Samples machine load every 30 s into a CSV until the labnet process exits.
# Memory guard: if available memory < 2048 MB, stops the labnet process tree
# (children by parent PID, then the labnet PID) and records it.
param([Parameter(Mandatory)][int]$LabnetPid, [Parameter(Mandatory)][string]$Csv, [int]$IntervalSecs = 30)
"unix,cpu_pct,avail_mb,top5_cpu_secs_in_interval" | Out-File -FilePath $Csv -Encoding utf8
$prev = @{}
foreach ($p in Get-Process) { $prev[$p.Id] = $p.CPU }
while ($true) {
  $lab = Get-Process -Id $LabnetPid -ErrorAction SilentlyContinue
  if (-not $lab) { break }
  $c = Get-Counter '\Processor(_Total)\% Processor Time','\Memory\Available MBytes' -SampleInterval $IntervalSecs -MaxSamples 1
  $cpu = [math]::Round($c.CounterSamples[0].CookedValue, 1)
  $mb = [math]::Round($c.CounterSamples[1].CookedValue, 0)
  $now = @{}; $rows = @()
  foreach ($p in Get-Process) {
    $now[$p.Id] = $p.CPU
    if ($p.CPU -ne $null) { $d = $p.CPU - $(if ($prev.ContainsKey($p.Id) -and $prev[$p.Id] -ne $null) { $prev[$p.Id] } else { 0 }); $rows += [pscustomobject]@{ n = "$($p.ProcessName)#$($p.Id)"; d = $d } }
  }
  $prev = $now
  $top = ($rows | Sort-Object d -Descending | Select-Object -First 5 | ForEach-Object { "{0}={1:N1}" -f $_.n, $_.d }) -join ' '
  "{0},{1},{2},{3}" -f [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(), $cpu, $mb, $top | Out-File -FilePath $Csv -Append -Encoding utf8
  if ($mb -lt 2048) {
    "{0},MEMORY-GUARD,{1},available below 2048 MB: stopping labnet PID {2} and its children" -f [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(), $mb, $LabnetPid | Out-File -FilePath $Csv -Append -Encoding utf8
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$LabnetPid" | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Stop-Process -Id $LabnetPid -Force -ErrorAction SilentlyContinue
    break
  }
}
