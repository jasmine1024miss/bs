$ErrorActionPreference = "Stop"

Write-Host "== KylinSafeOps local compatibility =="
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"

Write-Host ""
Write-Host "== Node =="
try { node --version } catch { Write-Host "node missing" }

Write-Host ""
Write-Host "== Docker =="
try { docker --version } catch { Write-Host "docker missing" }

Write-Host ""
Write-Host "== Python bundled note =="
Write-Host "Use Codex bundled Python or install Python 3.10+ locally."

