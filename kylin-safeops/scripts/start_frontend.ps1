$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location "$root\frontend"

if (-not (Test-Path ".\node_modules")) {
  npm install
}

$env:VITE_API_BASE_URL = "http://localhost:8000"
npm run dev -- --host 0.0.0.0

