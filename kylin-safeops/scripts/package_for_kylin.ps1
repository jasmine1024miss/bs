$ErrorActionPreference = "Stop"

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$migrationDir = "D:\content\bs\vm\migration"
$stageDir = Join-Path $migrationDir "kylin-safeops"
$zipPath = Join-Path $migrationDir "kylin-safeops-src.zip"

New-Item -ItemType Directory -Force $migrationDir | Out-Null
if (Test-Path $stageDir) {
  Remove-Item -Recurse -Force $stageDir
}
if (Test-Path $zipPath) {
  Remove-Item -Force $zipPath
}

$excludeDirs = @(
  ".venv",
  "node_modules",
  "dist",
  "logs",
  ".git",
  "__pycache__"
)

$excludeFiles = @(
  "*.pyc",
  "*.pyo",
  "*.log",
  "audit_ops_*.json",
  "replay_ops_*.json"
)

New-Item -ItemType Directory -Force $stageDir | Out-Null

$robocopyArgs = @(
  $root,
  $stageDir,
  "/E",
  "/XD"
) + $excludeDirs + @(
  "/XF"
) + $excludeFiles + @(
  "/NFL",
  "/NDL",
  "/NJH",
  "/NJS",
  "/NP"
)

& robocopy @robocopyArgs | Out-Null
$code = $LASTEXITCODE
if ($code -gt 7) {
  throw "robocopy failed with exit code $code"
}

Compress-Archive -Path $stageDir -DestinationPath $zipPath -CompressionLevel Optimal

$hash = Get-FileHash $zipPath -Algorithm SHA256
$sizeMb = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)

@{
  zip = $zipPath
  sha256 = $hash.Hash
  size_mb = $sizeMb
  created_at = (Get-Date).ToString("s")
} | ConvertTo-Json | Set-Content -Encoding UTF8 (Join-Path $migrationDir "kylin-safeops-src.json")

Write-Host "Created: $zipPath"
Write-Host "Size MB: $sizeMb"
Write-Host "SHA256: $($hash.Hash)"
