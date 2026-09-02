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
function Test-PythonCandidate($exe, $pre) {
  $cmd = Get-Command $exe -ErrorAction SilentlyContinue
  if (-not $cmd) { return $null }
  # skip the Microsoft Store alias stub (prints "not found", isn't a real interpreter)
  if ($cmd.Source -and $cmd.Source -like "*\WindowsApps\*") { return $null }
  try { $out = (& $cmd.Source @pre "--version" 2>&1 | Out-String) } catch { return $null }
  if ($out -match "Python\s+(\d+)\.(\d+)") {
    $maj = [int]$Matches[1]; $min = [int]$Matches[2]
    if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 10)) {
      return [pscustomobject]@{ Exe = $cmd.Source; Pre = $pre; Ver = "$maj.$min" }
    }
  }
  return $null
}

$Py = $null
foreach ($c in @(,@("py", @("-3"))) + @(,@("python3", @())) + @(,@("python", @()))) {
  $Py = Test-PythonCandidate $c[0] $c[1]
  if ($Py) { break }
}

if (-not $Py) {
  Warn "Python 3.10+ was not found. (The 'python' Windows may offer is a Microsoft Store"
  Warn "placeholder, not a real interpreter.)"
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    Info "Installing Python 3.12 via winget..."
    try {
      winget install --id Python.Python.3.12 -e --source winget --accept-package-agreements --accept-source-agreements
      Write-Host ""
      Warn "Python installed. Close this window, open a NEW PowerShell, and run install.ps1 again"
      Warn "(a fresh shell is required so Windows adds Python to PATH)."
      exit 0
    } catch {
      Die "Automatic install failed. Get Python 3.10+ from https://python.org (tick 'Add python.exe to PATH'), then re-run."
    }
  }
  Die "Install Python 3.10+ from https://python.org (tick 'Add python.exe to PATH') and re-run, or use -Docker with Docker Desktop, or download a prebuilt binary from the Releases page."
}
Ok "Python $($Py.Ver) detected."

$venv = Join-Path $RepoDir ".venv"
if (-not (Test-Path $venv)) {
  Info "Creating virtual environment (.venv)..."
  & $Py.Exe @($Py.Pre) -m venv "$venv"
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
Info "Open the console and sign in with pentestiq / p3nt3st!q (change it after first login). Ctrl-C to stop."
Write-Host ""
& $pentestiq serve --host 0.0.0.0 --port $Port
