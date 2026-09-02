#Requires -Version 5.1
<#
.SYNOPSIS
  PentestIQ installer for Windows.

.DESCRIPTION
  Two ways to install:
    (default)  Python path  - creates a virtualenv, installs PentestIQ, and starts
               the API + web console. Needs Python 3.10+ (https://python.org).
    -Docker    Docker path   - builds and runs the full SaaS stack (PentestIQ +
               MobSF) with Docker Desktop (https://www.docker.com/products/docker-desktop).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install.ps1
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Port 9090
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Docker
#>
[CmdletBinding()]
param(
  [int]$Port = 8080,
  [switch]$Docker,
  [switch]$NoServe,
  [switch]$All,
  [switch]$Help
)

$ErrorActionPreference = "Stop"
$RepoDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Info($m) { Write-Host "[PentestIQ] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[ ok ] $m"     -ForegroundColor Green }
function Warn($m) { Write-Host "[warn] $m"     -ForegroundColor Yellow }
function Die($m)  { Write-Host "[fail] $m"     -ForegroundColor Red; exit 1 }

if ($Help) {
  Get-Help $MyInvocation.MyCommand.Path -Detailed
  exit 0
}

Write-Host ""
Write-Host "  PentestIQ - Windows installer" -ForegroundColor Blue
Write-Host ""

# --------------------------------------------------------------- Docker path
if ($Docker) {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Die "Docker not found. Install Docker Desktop (https://www.docker.com/products/docker-desktop), start it, then re-run with -Docker."
  }
  try { docker info | Out-Null } catch { Die "Docker is installed but not running - start Docker Desktop and re-run." }

  $envFile = Join-Path $RepoDir "deploy\.env"
  if (-not (Test-Path $envFile)) {
    $secret = -join ((48..57)+(97..122) | Get-Random -Count 48 | ForEach-Object {[char]$_})
    $mobkey = -join ((48..57)+(97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
    "PENTESTIQ_SECRET_KEY=$secret`nMOBSF_API_KEY=$mobkey`nPENTESTIQ_PORT=$Port" | Set-Content -Path $envFile -Encoding ASCII
    Ok "Generated deploy\.env with fresh secrets."
  }
  Info "Building and starting the stack (docker compose)..."
  docker compose --env-file $envFile -f (Join-Path $RepoDir "deploy\docker-compose.yml") up -d --build
  Ok "Stack is up. Open http://localhost:$Port"
  exit 0
}

# --------------------------------------------------------------- Python path
$py = $null
foreach ($cand in @("py -3", "python", "python3")) {
  $exe = $cand.Split(" ")[0]
  if (Get-Command $exe -ErrorAction SilentlyContinue) { $py = $cand; break }
}
if (-not $py) { Die "Python 3.10+ not found. Install it from https://python.org (check 'Add to PATH'), then re-run." }

# verify version >= 3.10
$verOut = & ([scriptblock]::Create("$py -c `"import sys;print('%d.%d'%sys.version_info[:2])`""))
$maj,$min = $verOut.Trim().Split(".")
if ([int]$maj -lt 3 -or ([int]$maj -eq 3 -and [int]$min -lt 10)) {
  Die "Python $verOut found, but 3.10+ is required."
}
Ok "Python $verOut detected."

$venv = Join-Path $RepoDir ".venv"
if (-not (Test-Path $venv)) {
  Info "Creating virtual environment (.venv)..."
  & ([scriptblock]::Create("$py -m venv `"$venv`""))
}
$vpy = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $vpy)) { Die "venv creation failed (no $vpy)." }

Info "Installing PentestIQ and dependencies (this may take a minute)..."
& $vpy -m pip install --upgrade pip --quiet
$extras = if ($All) { ".[all]" } else { ".[api,reports]" }
& $vpy -m pip install --quiet $extras
Ok "PentestIQ installed."

$pentestiq = Join-Path $venv "Scripts\pentestiq.exe"
& $pentestiq version

if ($NoServe) {
  Write-Host ""
  Info "Skipping server start (-NoServe)."
  Info "To run later:  `"$pentestiq`" serve --host 0.0.0.0 --port $Port"
  exit 0
}

if (-not $env:PENTESTIQ_SECRET_KEY) {
  $env:PENTESTIQ_SECRET_KEY = -join ((48..57)+(97..122) | Get-Random -Count 48 | ForEach-Object {[char]$_})
}
Write-Host ""
Ok "Starting the API + web console on http://localhost:$Port"
Info "Open the console, click Register to create your first tenant, then upload/scan. Ctrl-C to stop."
Write-Host ""
& $pentestiq serve --host 0.0.0.0 --port $Port
