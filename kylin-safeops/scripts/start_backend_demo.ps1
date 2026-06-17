$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
  Write-Host "Creating local Python virtual environment..."
  python -m venv .venv
}

.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
$env:SAFEOPS_MODE = "demo"
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload

