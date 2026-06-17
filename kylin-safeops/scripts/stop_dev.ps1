$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$LogsDir = Join-Path $Root "logs"
$PidFiles = @(
  (Join-Path $LogsDir "dev-backend.pid"),
  (Join-Path $LogsDir "dev-frontend.pid")
)

function Get-CommandLine($ProcessId) {
  $entry = Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessId" -ErrorAction SilentlyContinue
  if ($entry) {
    return $entry.CommandLine
  }
  return ""
}

function Test-SafeOpsCommand($CommandLine) {
  if (-not $CommandLine) {
    return $false
  }
  if ($CommandLine -like "*$Root*") {
    return $true
  }
  if ($CommandLine -like "*backend.app.main*") {
    return $true
  }
  if ($CommandLine -like "*vite*--host*") {
    return $true
  }
  return $false
}

function Stop-SafeProcess($ProcessId, $Reason) {
  $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
  if (-not $process) {
    return
  }
  Write-Host "[SafeOps] Stopping PID=$($process.Id) $($process.ProcessName) ($Reason)" -ForegroundColor Cyan
  Stop-Process -Id $process.Id -Force
}

foreach ($PidFile in $PidFiles) {
  if (-not (Test-Path $PidFile)) {
    continue
  }

  $rawPid = Get-Content -Path $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($rawPid) {
    Stop-SafeProcess ([int]$rawPid) "pid-file"
  }

  Remove-Item -Path $PidFile -Force -ErrorAction SilentlyContinue
}

foreach ($Port in @(8000, 5173)) {
  $listeners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
  foreach ($listener in $listeners) {
    $commandLine = Get-CommandLine $listener.OwningProcess
    if (Test-SafeOpsCommand $commandLine) {
      Stop-SafeProcess $listener.OwningProcess "port-$Port"
    } else {
      Write-Host "[SafeOps] Port $Port belongs to PID=$($listener.OwningProcess), but it does not look like SafeOps. Skipped." -ForegroundColor Yellow
    }
  }
}

Write-Host "[SafeOps] Local development services stopped" -ForegroundColor Green
