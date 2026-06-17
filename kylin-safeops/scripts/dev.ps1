param(
  [ValidateSet("check", "install", "start", "backend", "frontend", "status")]
  [string]$Action = "start"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$BackendPython = Join-Path $Root ".venv\Scripts\python.exe"
$BackendRequirements = Join-Path $Root "backend\requirements.txt"
$FrontendDir = Join-Path $Root "frontend"
$LogsDir = Join-Path $Root "logs"
$BackendPid = Join-Path $LogsDir "dev-backend.pid"
$FrontendPid = Join-Path $LogsDir "dev-frontend.pid"

function Write-Step($Message) {
  Write-Host "[SafeOps] $Message" -ForegroundColor Cyan
}

function Test-CommandExists($Command) {
  return [bool](Get-Command $Command -ErrorAction SilentlyContinue)
}

function Get-PythonCommand {
  if (Test-CommandExists "python") {
    return "python"
  }
  if (Test-CommandExists "py") {
    return "py -3"
  }
  throw "Python 3.10+ was not found. Please install Python first."
}

function Ensure-Logs {
  if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir | Out-Null
  }
}

function Ensure-BackendEnv {
  Set-Location $Root
  if (-not (Test-Path $BackendPython)) {
    Write-Step "First run: creating Python venv at .venv"
    $python = Get-PythonCommand
    Invoke-Expression "$python -m venv `"$Root\.venv`""
  }

  Write-Step "Installing/checking backend dependencies"
  & $BackendPython -m pip install -r $BackendRequirements
}

function Ensure-FrontendEnv {
  Set-Location $FrontendDir
  if (-not (Test-Path (Join-Path $FrontendDir "node_modules"))) {
    Write-Step "First run: installing frontend dependencies"
    npm install
  } else {
    Write-Step "Frontend dependencies already exist"
  }
}

function Get-ProcessFromPidFile($PidFile) {
  if (-not (Test-Path $PidFile)) {
    return $null
  }
  $rawPid = (Get-Content -Path $PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
  if (-not $rawPid) {
    return $null
  }
  return Get-Process -Id ([int]$rawPid) -ErrorAction SilentlyContinue
}

function Get-ProcessOnPort($Port) {
  $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $listener) {
    return $null
  }
  return Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
}

function Start-Backend {
  Ensure-Logs
  Ensure-BackendEnv

  $existing = Get-ProcessFromPidFile $BackendPid
  if ($existing) {
    Write-Step "Backend is already running, PID=$($existing.Id)"
    return
  }

  $portProcess = Get-ProcessOnPort 8000
  if ($portProcess) {
    Write-Step "Backend port 8000 already has a listener, reusing PID=$($portProcess.Id)"
    return
  }

  $outLog = Join-Path $LogsDir "backend.out.log"
  $errLog = Join-Path $LogsDir "backend.err.log"
  $args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "cd `"$Root`"; `$env:SAFEOPS_MODE='auto'; & `"$BackendPython`" -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload"
  )
  $process = Start-Process -FilePath "powershell" -ArgumentList $args -RedirectStandardOutput $outLog -RedirectStandardError $errLog -WindowStyle Hidden -PassThru
  Set-Content -Path $BackendPid -Value $process.Id
  Write-Step "Backend started: http://127.0.0.1:8000 PID=$($process.Id)"
}

function Start-Frontend {
  Ensure-Logs
  Ensure-FrontendEnv

  $existing = Get-ProcessFromPidFile $FrontendPid
  if ($existing) {
    Write-Step "Frontend is already running, PID=$($existing.Id)"
    return
  }

  $portProcess = Get-ProcessOnPort 5173
  if ($portProcess) {
    Write-Step "Frontend port 5173 already has a listener, reusing PID=$($portProcess.Id)"
    return
  }

  $outLog = Join-Path $LogsDir "frontend.out.log"
  $errLog = Join-Path $LogsDir "frontend.err.log"
  $args = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "cd `"$FrontendDir`"; `$env:VITE_API_BASE_URL='http://127.0.0.1:8000'; npm run dev -- --host 0.0.0.0"
  )
  $process = Start-Process -FilePath "powershell" -ArgumentList $args -RedirectStandardOutput $outLog -RedirectStandardError $errLog -WindowStyle Hidden -PassThru
  Set-Content -Path $FrontendPid -Value $process.Id
  Write-Step "Frontend started: http://127.0.0.1:5173 PID=$($process.Id)"
}

function Show-Status {
  $backend = Get-ProcessFromPidFile $BackendPid
  $frontend = Get-ProcessFromPidFile $FrontendPid
  if ($backend) {
    Write-Host "Backend: running PID=$($backend.Id) managed" -ForegroundColor Green
  } elseif ($backendPort = Get-ProcessOnPort 8000) {
    Write-Host "Backend: running PID=$($backendPort.Id) port=8000" -ForegroundColor Green
  } else {
    Write-Host "Backend: stopped" -ForegroundColor Yellow
  }
  if ($frontend) {
    Write-Host "Frontend: running PID=$($frontend.Id) managed" -ForegroundColor Green
  } elseif ($frontendPort = Get-ProcessOnPort 5173) {
    Write-Host "Frontend: running PID=$($frontendPort.Id) port=5173" -ForegroundColor Green
  } else {
    Write-Host "Frontend: stopped" -ForegroundColor Yellow
  }
  Write-Host "Frontend URL: http://127.0.0.1:5173/"
  Write-Host "Backend health: http://127.0.0.1:8000/health"
}

switch ($Action) {
  "check" {
    Write-Step "Checking local development environment"
    Write-Host "Root: $Root"
    Write-Host "Python: $(if (Test-Path $BackendPython) { $BackendPython } else { 'will create .venv' })"
    Write-Host "Node: $(if (Test-CommandExists 'node') { (node --version) } else { 'missing' })"
    Write-Host "npm:  $(if (Test-CommandExists 'npm') { (npm --version) } else { 'missing' })"
    Show-Status
  }
  "install" {
    Ensure-BackendEnv
    Ensure-FrontendEnv
    Write-Step "Dependencies are ready"
  }
  "backend" {
    Start-Backend
    Show-Status
  }
  "frontend" {
    Start-Frontend
    Show-Status
  }
  "start" {
    Start-Backend
    Start-Frontend
    Show-Status
  }
  "status" {
    Show-Status
  }
}
