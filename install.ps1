#Requires -Version 5.1
<#
.SYNOPSIS
  Corvex-RedOps installer for Windows — one command, never left half-done.

.DESCRIPTION
  ONE command installs everything and brings up the console:

    powershell -ExecutionPolicy Bypass -File .\install.ps1

  It prefers a Docker deployment (Docker Desktop) and falls back to a native Python install
  (its own venv and data under %LOCALAPPDATA%\corvex-redops) if Docker is missing, not
  running, or can't reach the image registry. A read-only preflight (platform, memory,
  disk, Docker, every host port) runs before anything changes, and a stack that doesn't come
  up healthy is stopped again.

  Force an engine or manage the stack:
    .\install.ps1 -Docker             # force Docker (no native fallback)
    .\install.ps1 -Native             # force the native (no-Docker) install
    .\install.ps1 -Ai                 # install the local AI model (Docker only; ~5 GB, 8 GB free memory)
    .\install.ps1 -NoAi               # don't (without either, an interactive window is asked)
    .\install.ps1 -Port 9090          # console port (default 8080; the next free one if taken)
    .\install.ps1 -Listen 0.0.0.0     # reachable from the network (default 127.0.0.1, plain HTTP)
    .\install.ps1 -TrustedProxy 172.18.0.1   # a TLS reverse proxy's IP/CIDR (repeatable; never "*")
    .\install.ps1 -PublishMobile      # also publish the mobile-analysis engine on 127.0.0.1:8000
    .\install.ps1 -Down               # stop whatever is running
    .\install.ps1 -Update             # rebuild/reinstall & redeploy
#>
[CmdletBinding()]
param(
  [int]$Port = 0,
  [string]$Listen = "",
  [string[]]$TrustedProxy = @(),
  [switch]$PublishMobile,
  [int]$MobilePort = 0,
  [switch]$Docker,
  [switch]$Native,
  [switch]$Update,
  [switch]$Down,
  [switch]$Ai,
  [switch]$NoAi,
  [switch]$NoServe,
  [switch]$All,
  [switch]$Help
)

# No hard stop-on-error: the installer must survive a failed step to fall back and clean up.
$ErrorActionPreference = "Continue"
$RepoDir     = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $RepoDir "deploy\docker-compose.yml"
$MobileFile  = Join-Path $RepoDir "deploy\docker-compose.publish-mobile.yml"
$EnvFile     = Join-Path $RepoDir "deploy\.env"
$AiModel     = if ($env:CORVEX_AI_MODEL) { $env:CORVEX_AI_MODEL } elseif ($env:PENTESTIQ_AI_MODEL) { $env:PENTESTIQ_AI_MODEL } else { "qwen2.5:7b-instruct" }
$script:AiOn = $false      # decided by Select-Ai (flags, an existing AI install, or the question)
$script:AiStatus = ""
$AiPrompt = "Install the local AI model? About 5 GB download, needs 8 GB free memory. [y/N]"
$AiMinMemMB = 8192
$PortSet       = ($Port -gt 0)
$ListenSet     = ($Listen -ne "")
$MobilePortSet = ($MobilePort -gt 0)
if (-not $PortSet) { $Port = 8080 }
if (-not $ListenSet) { $Listen = "127.0.0.1" }
if (-not $MobilePortSet) { $MobilePort = 8000 }
# Native install: its own venv and data, outside the checkout.
$NativeHome = if ($env:CORVEX_NATIVE_HOME) { $env:CORVEX_NATIVE_HOME } else { Join-Path $env:LOCALAPPDATA "corvex-redops" }
$NativeVenv = Join-Path $NativeHome "venv"
$NativeData = Join-Path $NativeHome "data"
$NativeLog  = Join-Path $NativeHome "console.log"
$NativePid  = Join-Path $NativeHome "console.pid"
$OurContainers = @("pentestiq-api", "pentestiq-mobsf", "pentestiq-ollama")
$MinMemMB = 1024; $RecMemMB = 2048; $MinDiskDockerMB = 8192; $MinDiskNativeMB = 2048
$script:Started = ""

function Info($m) { Write-Host "[Corvex-RedOps] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[ ok ] $m"     -ForegroundColor Green }
function Warn($m) { Write-Host "[warn] $m"     -ForegroundColor Yellow }
function Die($m)  { Write-Host "[fail] $m"     -ForegroundColor Red; exit 1 }

if ($Help) { Get-Help $MyInvocation.MyCommand.Path -Detailed; exit 0 }

# ---- network exposure: same rules as install.sh --listen / --trusted-proxy ----
if ($Listen -ne "localhost" -and $Listen -notmatch '^[0-9A-Fa-f.:]+$') {
  Die "invalid -Listen address: $Listen (use an IP address, e.g. 127.0.0.1 or 0.0.0.0)"
}
$TrustedProxy = @($TrustedProxy | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
foreach ($tp in $TrustedProxy) {
  if ($tp -notmatch '^[0-9A-Fa-f.:]+(/[0-9]{1,3})?$') {
    Die "invalid -TrustedProxy: $tp (use an IP or CIDR, e.g. 172.18.0.1 or 10.0.0.0/24; never `"*`")"
  }
}
function Test-Loopback([string]$a) { return ($a -like "127.*" -or $a -eq "::1" -or $a -eq "localhost") }
function Get-ComposeListen { if ($Listen -like "*:*") { return "[$Listen]" } else { return $Listen } }
function Get-TrustedList { return (@("127.0.0.1", "::1") + $TrustedProxy) -join "," }
function Get-HealthHost {
  if ($Listen -eq "0.0.0.0" -or $Listen -eq "localhost") { return "127.0.0.1" }
  if ($Listen -like "*:*") { return "[$Listen]" }
  return $Listen
}

# ---- env file helpers ----
function Get-EnvValue([string]$Key) {
  if (-not (Test-Path $EnvFile)) { return "" }
  $line = Get-Content -Path $EnvFile | Where-Object { $_ -match "^$Key=" } | Select-Object -Last 1
  if ($line) { return ($line -replace "^$Key=", "") } else { return "" }
}
function Set-EnvValue([string]$Key, [string]$Value) {
  if (-not (Test-Path $EnvFile)) { return }
  $lines = @(Get-Content -Path $EnvFile | Where-Object { $_ -notmatch "^$Key=" })
  ($lines + "$Key=$Value") -join "`n" | Set-Content -Path $EnvFile -Encoding ASCII
}

# An existing install keeps its port/listen unless this run sets them; 0.0.0.0 (the old
# default) becomes 127.0.0.1, saying so in the summary.
$script:ListenChangedFrom = ""
if (Test-Path $EnvFile) {
  $p = Get-EnvValue "PENTESTIQ_PORT"; if (-not $PortSet -and $p) { $Port = [int]$p }
  $l = (Get-EnvValue "PENTESTIQ_LISTEN").Trim("[", "]")
  if (-not $ListenSet -and $l -and $l -ne $Listen) {
    if ($l -eq "0.0.0.0" -or $l -eq "::") { $script:ListenChangedFrom = $l } else { $Listen = $l }
  }
}

Write-Host ""
Write-Host "  ____ ___  ______     _________  __" -ForegroundColor Blue
Write-Host " / ___/ _ \|  _ \ \   / / ____\ \/ /" -ForegroundColor Blue
Write-Host "| |  | | | | |_) \ \ / /|  _|  \  /"  -ForegroundColor Blue
Write-Host "| |__| |_| |  _ < \ V / | |___ /  \"  -ForegroundColor Blue
Write-Host " \____\___/|_| \_\ \_/  |_____/_/\_\   RedOps - one-command deploy" -ForegroundColor Blue
Write-Host ""

function New-Secret([int]$n = 48) {
  -join ((48..57)+(97..122) | Get-Random -Count $n | ForEach-Object {[char]$_})
}

function Get-Compose {
  try { docker compose version *> $null; if ($LASTEXITCODE -eq 0) { return @("docker","compose") } } catch {}
  if (Get-Command docker-compose -ErrorAction SilentlyContinue) { return @("docker-compose") }
  return $null
}

function Invoke-Compose([string[]]$Rest) {
  $dc = Get-Compose
  if (-not $dc) { $global:LASTEXITCODE = 1; return }
  $a = @()
  if ($dc.Count -gt 1) { $a += $dc[1] }
  $a += @("--env-file", $EnvFile, "-f", $ComposeFile)
  if ($PublishMobile) { $a += @("-f", $MobileFile) }
  if ($script:AiOn) { $a += @("--profile", "ai") }
  $a += $Rest
  $env:CORVEX_MOBILE_PORT = "$MobilePort"
  & $dc[0] @a | Out-Host   # stream to console, keep it out of the function's return value
}

# ---------------------------------------------------------------- preflight (read-only)
function Get-DockerState {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return "missing" }
  try { docker info *> $null; if ($LASTEXITCODE -eq 0) { return "running" } } catch {}
  return "stopped"
}
# Who listens on TCP $p: @{ Desc; Pid; Container } or $null when free.
function Get-PortHolder([int]$p) {
  $c = $null
  try { $c = Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue | Select-Object -First 1 } catch {}
  $cname = ""
  if ((Get-DockerState) -eq "running") {
    $row = docker ps --format "{{.Names}}|{{.Ports}}" 2>$null | Where-Object { $_ -match ":$p->" } | Select-Object -First 1
    if ($row) { $cname = ($row -split '\|')[0] }
  }
  if (-not $c -and -not $cname) { return $null }
  if ($cname) { return @{ Desc = "Docker container '$cname'"; Pid = 0; Container = $cname } }
  $procId = [int]$c.OwningProcess
  $name = "pid $procId"
  try { $name = "$((Get-Process -Id $procId -ErrorAction Stop).ProcessName) (pid $procId)" } catch {}
  return @{ Desc = $name; Pid = $procId; Container = "" }
}
function Test-Ours($h) {
  if ($h.Container) { return ($OurContainers -contains $h.Container) }
  if ((Test-Path $NativePid) -and ((Get-Content $NativePid -ErrorAction SilentlyContinue) -eq "$($h.Pid)")) { return $true }
  return $false
}
function Resolve-Port([int]$p, [bool]$wasSet, [string]$flag) {
  $h = Get-PortHolder $p
  if (-not $h -or (Test-Ours $h)) { return $p }
  if ($wasSet) { Die "port $p is in use by $($h.Desc). Stop it, or choose another port with $flag N." }
  for ($q = $p + 1; $q -le $p + 50; $q++) {
    if (-not (Get-PortHolder $q)) {
      Info "Port $p is in use by $($h.Desc) - using $q instead (choose one with $flag N)."
      return $q
    }
  }
  Die "port $p is in use by $($h.Desc), and no free port was found up to $($p + 50). Choose one with $flag N."
}
function Get-FreeMemMB {
  try { return [int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1024) } catch { return 0 }
}
function Get-FreeDiskMB([string]$path) {
  try {
    $root = [System.IO.Path]::GetPathRoot($path)
    $d = Get-PSDrive -Name $root.Substring(0,1) -ErrorAction Stop
    return [int]($d.Free / 1MB)
  } catch { return 0 }
}
function Invoke-Preflight {
  Info "Preflight - checking this machine before changing anything..."
  $arch = $env:PROCESSOR_ARCHITECTURE
  Ok "Platform: Windows $([System.Environment]::OSVersion.Version), $arch."
  $mem = Get-FreeMemMB
  if ($mem -gt 0 -and $mem -lt $MinMemMB) { Die "only $mem MB of memory is free; Corvex-RedOps needs at least $MinMemMB MB ($RecMemMB MB recommended)." }
  elseif ($mem -gt 0 -and $mem -lt $RecMemMB) { Warn "Memory: $mem MB free ($RecMemMB MB recommended) - large scans may be slow." }
  else { Ok "Memory: $mem MB free." }
  $script:DockerState = Get-DockerState
  Info "Docker: $script:DockerState."
  if (-not $Native) {
    $free = Get-FreeDiskMB $env:ProgramData
    if ($free -gt 0 -and $free -lt $MinDiskDockerMB) {
      if ($Docker) { Die "only $free MB free for Docker; the images need at least $MinDiskDockerMB MB. Free some space, or use -Native." }
      Warn "Disk: $free MB free (Docker needs $MinDiskDockerMB MB) - using the native install instead."
      $script:ForceNative = $true
    } else { Ok "Disk: $free MB free." }
  }
  $nfree = Get-FreeDiskMB $NativeHome
  if (($Native -or $script:ForceNative) -and $nfree -gt 0 -and $nfree -lt $MinDiskNativeMB) {
    Die "only $nfree MB free for the native install; it needs at least $MinDiskNativeMB MB."
  }
  $script:Port = Resolve-Port $Port $PortSet "-Port"
  Ok "Console port: $script:Port."
  if ($PublishMobile -and -not $Native) {
    $script:MobilePort = Resolve-Port $MobilePort $MobilePortSet "-MobilePort"
    Ok "Mobile-analysis engine port: 127.0.0.1:$script:MobilePort."
  }
  if (-not (Test-Loopback $Listen)) { Warn "-Listen ${Listen}: the console will be reachable from your network over plain HTTP - put TLS in front of it." }
  Ok "Preflight passed."
}

function Invoke-ComposeOutput([string[]]$Rest) {
  $dc = Get-Compose
  if (-not $dc) { $global:LASTEXITCODE = 1; return @() }
  $a = @()
  if ($dc.Count -gt 1) { $a += $dc[1] }
  $a += @("--env-file", $EnvFile, "-f", $ComposeFile)
  if ($PublishMobile) { $a += @("-f", $MobileFile) }
  if ($script:AiOn) { $a += @("--profile", "ai") }
  $a += $Rest
  return @(& $dc[0] @a 2>&1 | ForEach-Object { "$_" })
}

function Write-Env {
  $dir = Split-Path -Parent $EnvFile
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  if (-not (Test-Path $EnvFile)) {
    Info "Generating secrets -> $EnvFile"
    "# Corvex-RedOps deployment secrets - generated by install.ps1. Keep private; do not commit.`n" +
    "MOBSF_API_KEY=$(New-Secret 32)`n" +
    "PENTESTIQ_SECRET_KEY=$(New-Secret 48)" | Set-Content -Path $EnvFile -Encoding ASCII
    Ok "Secrets generated."
  } else { Ok "Reusing existing secrets ($EnvFile)." }
  Set-EnvValue "PENTESTIQ_PORT" "$Port"
  Set-EnvValue "PENTESTIQ_LISTEN" (Get-ComposeListen)
  if ($TrustedProxy.Count -gt 0 -or -not (Get-EnvValue "CORVEX_TRUSTED_PROXIES")) { Set-EnvValue "CORVEX_TRUSTED_PROXIES" (Get-TrustedList) }
  # switched on only once the model is proven (Install-Ai); switched off right away
  if (-not $script:AiOn -or -not (Get-EnvValue "PENTESTIQ_AI")) { Set-EnvValue "PENTESTIQ_AI" "0" }
  if (-not (Get-EnvValue "OLLAMA_URL")) { Set-EnvValue "OLLAMA_URL" "http://ollama:11434" }
  if (-not (Get-EnvValue "PENTESTIQ_AI_MODEL")) { Set-EnvValue "PENTESTIQ_AI_MODEL" $AiModel }
}

function Wait-Healthy {
  Info "Waiting for the console to become healthy..."
  for ($i = 0; $i -lt 60; $i++) {
    try {
      $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 4 "http://$(Get-HealthHost):$Port/health"
      if ($r.StatusCode -eq 200) { Ok "Corvex-RedOps is up."; return $true }
    } catch {}
    Start-Sleep -Seconds 3
  }
  return $false
}

function Show-Summary([string]$Engine) {
  Write-Host ""
  Write-Host "============================================================" -ForegroundColor Green
  Write-Host "  Corvex-RedOps is deployed.  (engine: $Engine)" -ForegroundColor Green
  Write-Host "============================================================" -ForegroundColor Green
  if (Test-Loopback $Listen) { Write-Host "  Web console : http://$(Get-HealthHost):$Port   (this host only)" }
  else { Write-Host "  Web console : http://$(Get-HealthHost):$Port   (listening on $Listen)" }
  if ($PublishMobile -and $Engine -eq "docker") { Write-Host "  Mobile engine: http://127.0.0.1:$MobilePort   (-PublishMobile)" }
  if ($Engine -eq "native") { Write-Host "  Data        : $NativeData   (log: $NativeLog)" }
  if ($script:AiStatus -eq "ready") { Write-Host "  AI          : ready - local model $AiModel" -ForegroundColor Green }
  elseif ($script:AiStatus) { Write-Host "  AI          : $script:AiStatus" -ForegroundColor Yellow }
  else { Write-Host "  AI          : off (.\install.ps1 -Ai adds the local model)" -ForegroundColor DarkGray }
  if ($script:ListenChangedFrom) {
    Write-Host "  Note: the console now listens on 127.0.0.1 only (it was on $script:ListenChangedFrom); re-run with -Listen 0.0.0.0 to keep network access." -ForegroundColor Yellow
  }
  if ($Engine -eq "docker") {
    Write-Host "  Sign in as admin - one-time password in the console log:"
    Write-Host "    docker logs pentestiq-api 2>&1 | Select-String -Context 0,3 'first-run admin'"
    Write-Host "  Manage:  logs -> docker compose --env-file `"$EnvFile`" -f `"$ComposeFile`" logs -f"
  } else {
    Write-Host "  Sign in as admin - one-time password in $NativeLog on first run."
  }
  Write-Host "           stop -> .\install.ps1 -Down"
  if (-not (Test-Loopback $Listen)) {
    Write-Host "  [!] The console listens on $Listen over plain HTTP - anyone on your network can reach it; put TLS in front of it." -ForegroundColor Yellow
  }
  if ($TrustedProxy.Count -gt 0 -and -not (Test-Loopback $Listen)) {
    Write-Host "  [!] Trusted proxy $($TrustedProxy -join ',') is set while the console listens on ${Listen}: clients could choose their own X-Forwarded-For. Use -Listen 127.0.0.1." -ForegroundColor Yellow
  }
  Write-Host "============================================================" -ForegroundColor Green
  Write-Host ""
}

# --------------------------------------------------------------- Docker engine
function Test-DockerUsable {
  if ((Get-DockerState) -ne "running") { return $false }
  if (-not (Get-Compose)) { return $false }
  return $true
}

function Test-RegistryReachable {
  Info "Checking image-registry reachability..."
  try { docker pull python:3.11-slim *> $null } catch {}
  if ($LASTEXITCODE -eq 0) { Ok "Registry reachable (base image ready)."; return $true }
  Warn "Docker cannot reach the image registry."
  return $false
}

function Undo-Docker {
  Warn "Taking the stack down again - nothing is left half-started (data volumes are kept)."
  Invoke-Compose @("down", "--remove-orphans")
  $script:Started = ""
}

function Deploy-Docker {
  if (-not (Test-DockerUsable)) { Warn "Docker is not usable (not installed, not running, or no Compose)."; return $false }
  if (-not (Test-RegistryReachable)) { return $false }
  if (-not (Test-Path $ComposeFile)) { Warn "compose file not found: $ComposeFile"; return $false }
  Write-Env
  $env:DOCKER_BUILDKIT = "0"; $env:COMPOSE_DOCKER_CLI_BUILD = "0"
  Info "Building the console image (the first run can take several minutes)..."
  Invoke-Compose @("build")
  if ($LASTEXITCODE -ne 0) { Warn "The image build failed (the running deployment, if any, is untouched)."; return $false }
  Stop-NativeConsole
  Invoke-Compose @("run", "--rm", "--no-deps", "--user", "0", "--entrypoint", "chown", "pentestiq", "-R", "10001:10001", "/app/data")
  Info "Starting the stack..."
  $script:Started = "docker"
  Invoke-Compose @("up", "-d", "--remove-orphans")
  if ($LASTEXITCODE -ne 0) { Warn "The Docker stack didn't start."; Undo-Docker; return $false }
  if (-not (Wait-Healthy)) {
    Warn "The console didn't become healthy. Last log lines:"
    Invoke-Compose @("logs", "--no-color", "--tail", "30", "pentestiq")
    Undo-Docker; return $false
  }
  return $true
}

# --------------------------------------------------------------- local AI model (Docker only)
function Test-Interactive {
  try { return ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and -not [Console]::IsOutputRedirected) } catch { return $false }
}
# -Ai / -NoAi win; an install that already runs the model keeps it; otherwise ask - only interactively.
function Select-Ai {
  if ($Ai) { $script:AiOn = $true; return }
  if ($NoAi) { $script:AiOn = $false; return }
  if ((Get-EnvValue "PENTESTIQ_AI") -eq "1") { $script:AiOn = $true; Info "Keeping the local AI model this install already runs (-NoAi turns it off)."; return }
  if (Test-Interactive) {
    $ans = Read-Host $AiPrompt
    $script:AiOn = ($ans -match '^(y|yes)$')
  } else { $script:AiOn = $false }   # CI, piped: no AI unless -Ai
}
function Disable-Ai([string]$why) {
  $script:AiStatus = "not enabled - $why. Reports still work without AI."
  Warn "AI: not enabled - $why. Reports still work without AI. Re-run with -Ai to try again."
  Set-EnvValue "PENTESTIQ_AI" "0"
  Invoke-Compose @("stop", "ollama")
  $script:AiOn = $false
  Invoke-Compose @("up", "-d", "--no-deps", "pentestiq"); Wait-Healthy | Out-Null
}
# Start the runtime, download the model (visible progress; skipped when present), switch AI on,
# restart the console, then prove it: the /ai/status check plus a real narrative (corvex ai-check).
function Install-Ai {
  if (-not $script:AiOn) { return }
  $mem = Get-FreeMemMB
  if ($mem -gt 0 -and $mem -lt $AiMinMemMB) { $script:AiStatus = "skipped - only $mem MB of memory is free; the local model needs $AiMinMemMB MB"; Warn "AI: $script:AiStatus."; Set-EnvValue "PENTESTIQ_AI" "0"; $script:AiOn = $false; return }
  $disk = Get-FreeDiskMB $env:ProgramData
  if ($disk -gt 0 -and $disk -lt 10240) { $script:AiStatus = "skipped - only $disk MB of disk is free; the local model needs 10240 MB"; Warn "AI: $script:AiStatus."; Set-EnvValue "PENTESTIQ_AI" "0"; $script:AiOn = $false; return }
  Info "Starting the local AI runtime..."
  Invoke-Compose @("up", "-d", "ollama")
  if ($LASTEXITCODE -ne 0) { Disable-Ai "the AI runtime container didn't start"; return }
  $want = if ($AiModel -like "*:*") { $AiModel } else { "${AiModel}:latest" }
  $present = $false
  for ($i = 0; $i -lt 30; $i++) {
    $list = Invoke-ComposeOutput @("exec", "-T", "ollama", "ollama", "list")
    if ($LASTEXITCODE -eq 0) { $present = [bool]($list | Where-Object { ($_ -split '\s+')[0] -eq $want }); break }
    Start-Sleep -Seconds 2
  }
  if ($present) { Ok "The model $AiModel is already downloaded - skipping the download." }
  else {
    Info "Downloading the model $AiModel (about 5 GB for the default model)..."
    Invoke-Compose @("exec", "-T", "ollama", "ollama", "pull", $AiModel)
    if ($LASTEXITCODE -ne 0) { Disable-Ai "the model $AiModel could not be downloaded"; return }
  }
  Set-EnvValue "PENTESTIQ_AI" "1"
  Set-EnvValue "PENTESTIQ_AI_MODEL" $AiModel
  Info "Switching AI on and restarting the console..."
  Invoke-Compose @("up", "-d", "--no-deps", "pentestiq")
  if ($LASTEXITCODE -ne 0 -or -not (Wait-Healthy)) { Disable-Ai "the console didn't come back after switching AI on"; return }
  Info "Checking the AI end to end (status + a test narrative from the model)..."
  $out = Invoke-ComposeOutput @("exec", "-T", "pentestiq", "corvex", "ai-check")
  if ($LASTEXITCODE -eq 0) { $script:AiStatus = "ready"; Ok "AI: ready"; return }
  $why = ($out | Where-Object { $_ -like "AI check failed:*" } | Select-Object -First 1)
  if ($why) { $why = $why.Substring("AI check failed: ".Length) } else { $why = "the end-to-end check failed" }
  Disable-Ai $why
}

# --------------------------------------------------------------- native engine (no Docker)
# Supported for the venv path: Python 3.10 - 3.12 (newer often lacks prebuilt
# wheels for compiled deps, which would force a slow source build).
$MaxMinor = 12
function Get-PyInfo($exe, $pre) {
  $cmd = Get-Command $exe -ErrorAction SilentlyContinue
  if (-not $cmd) { return $null }
  if ($cmd.Source -and $cmd.Source -like "*\WindowsApps\*") { return $null }
  try { $out = (& $cmd.Source @pre "--version" 2>&1 | Out-String) } catch { return $null }
  if ($out -match "Python\s+(\d+)\.(\d+)") {
    $maj = [int]$Matches[1]; $min = [int]$Matches[2]
    if ($maj -eq 3 -and $min -ge 10) {
      return [pscustomobject]@{ Exe = $cmd.Source; Pre = $pre; Ver = "$maj.$min"; Min = $min; Supported = ($min -le $MaxMinor) }
    }
  }
  return $null
}

function Find-Python {
  $candidates = @(
    ,@("py", @("-3.12")), ,@("py", @("-3.11")), ,@("py", @("-3.10")),
    ,@("py", @("-3")),    ,@("python3", @()),    ,@("python", @())
  )
  $tooNew = $null
  foreach ($c in $candidates) {
    $info = Get-PyInfo $c[0] $c[1]
    if ($info) { if ($info.Supported) { return $info } elseif (-not $tooNew) { $tooNew = $info } }
  }
  return $tooNew  # may be $null, or a too-new interpreter we warn about
}

function Stop-NativeConsole {
  if (Test-Path $NativePid) {
    $procId = Get-Content $NativePid -ErrorAction SilentlyContinue
    if ($procId) { Stop-Process -Id ([int]$procId) -Force -ErrorAction SilentlyContinue }
    Remove-Item $NativePid -Force -ErrorAction SilentlyContinue
  }
}

function Test-Elevated {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

function Deploy-Native {
  Info "Using the native install (own venv in $NativeVenv, data in $NativeData)."
  $Py = Find-Python
  if (-not $Py -or -not $Py.Supported) {
    if ($Py -and -not $Py.Supported) {
      Warn "Python $($Py.Ver) is newer than the supported range (3.10-3.12); its compiled deps may lack wheels."
    } else {
      Warn "Python 3.10-3.12 not found (the 'python' Windows offers may be a Store placeholder)."
    }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      Info "Installing Python 3.12 via winget..."
      winget install --id Python.Python.3.12 -e --source winget --accept-package-agreements --accept-source-agreements
      Warn "Python 3.12 installed. Open a NEW PowerShell and run .\install.ps1 again."
      exit 0
    }
    Die "Install Python 3.12 from https://python.org (tick 'Add python.exe to PATH') and re-run, or install Docker Desktop and re-run."
  }
  Ok "Python $($Py.Ver) detected."
  New-Item -ItemType Directory -Force -Path $NativeData | Out-Null
  if (-not (Test-Path (Join-Path $NativeVenv "Scripts\python.exe"))) {
    Info "Creating the virtual environment ($NativeVenv)..."
    & $Py.Exe @($Py.Pre) -m venv "$NativeVenv"
  }
  $vpy = Join-Path $NativeVenv "Scripts\python.exe"
  if (-not (Test-Path $vpy)) { Die "venv creation failed (no $vpy)." }

  Info "Installing Corvex-RedOps and its dependencies (from PyPI)..."
  & $vpy -m pip install --upgrade pip setuptools wheel --quiet
  # Install a copy of the code (not an editable link to the checkout): the console never reads the checkout.
  $src = Join-Path ([System.IO.Path]::GetTempPath()) ("corvex-src-" + [guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Force -Path $src | Out-Null
  Get-ChildItem -Force $RepoDir | Where-Object { @(".git", ".venv", "data", "build", "dist") -notcontains $_.Name -and $_.Name -notlike "*.egg-info" } |
    ForEach-Object { Copy-Item -Recurse -Force $_.FullName $src }
  Remove-Item (Join-Path $src "deploy\.env") -Force -ErrorAction SilentlyContinue
  $extras = if ($All) { "[all]" } else { "[api,reports]" }
  & $vpy -m pip install --prefer-binary "$src$extras"
  $rc = $LASTEXITCODE
  if ($rc -eq 0) { & $vpy -m pip install --prefer-binary scikit-learn | Out-Host }  # self-learning model, best-effort
  Remove-Item -Recurse -Force $src -ErrorAction SilentlyContinue
  if ($rc -ne 0) { Die "Dependency install failed (nothing was started). Use Python 3.10-3.12, or install Docker Desktop and re-run." }
  Ok "Dependencies installed."

  $corvex = Join-Path $NativeVenv "Scripts\corvex.exe"
  if ($NoServe) { Info "Skipping server start (-NoServe). Run later:  `$env:CORVEX_DATA_DIR='$NativeData'; & `"$corvex`" serve --host $Listen --port $Port"; exit 0 }
  if (Test-Elevated) { Warn "This PowerShell runs as administrator, so the console would too. For everyday use, re-run from a normal (non-elevated) window." }
  $secretFile = Join-Path $NativeHome "secret-key"
  if (-not (Test-Path $secretFile)) {
    $sk = Get-EnvValue "PENTESTIQ_SECRET_KEY"; if (-not $sk) { $sk = New-Secret 48 }
    Set-Content -Path $secretFile -Value $sk -Encoding ASCII
  }
  Stop-NativeConsole
  $env:CORVEX_DATA_DIR = $NativeData
  $env:PENTESTIQ_SECRET_KEY = (Get-Content $secretFile -Raw).Trim()
  $env:CORVEX_TRUSTED_PROXIES = Get-TrustedList
  Info "Starting the console on http://$(Get-HealthHost):$Port ..."
  $script:Started = "native"
  $proc = Start-Process -FilePath $corvex -ArgumentList @("serve", "--host", $Listen, "--port", "$Port") `
            -WorkingDirectory $NativeHome -WindowStyle Hidden -PassThru `
            -RedirectStandardOutput $NativeLog -RedirectStandardError (Join-Path $NativeHome "console.err.log")
  Set-Content -Path $NativePid -Value $proc.Id -Encoding ASCII
  if (-not (Wait-Healthy)) {
    Warn "The console didn't become healthy. Last log lines:"
    Get-Content $NativeLog -Tail 30 -ErrorAction SilentlyContinue | Out-Host
    Get-Content (Join-Path $NativeHome "console.err.log") -Tail 30 -ErrorAction SilentlyContinue | Out-Host
    Stop-NativeConsole; $script:Started = ""
    Die "The native console didn't start (nothing was left running)."
  }
  return $true
}

function Stop-All {
  if ((Test-DockerUsable) -and (Test-Path $ComposeFile) -and (Test-Path $EnvFile)) {
    Info "Stopping the Docker stack..."
    Invoke-Compose @("down", "--remove-orphans")
    Ok "Docker stack stopped."
  }
  if (Test-Path $NativePid) { Info "Stopping the native console..."; Stop-NativeConsole; Ok "Native console stopped." }
}

# --------------------------------------------------------------- main
if ($Down) { Stop-All; exit 0 }

Invoke-Preflight
$Port = $script:Port
if ($PublishMobile) { $MobilePort = $script:MobilePort }

$NativeAiNote = "The local AI model needs Docker. To add it later: install Docker Desktop, then run .\install.ps1 -Docker -Ai"
if ($Native -or $script:ForceNative) {
  if ($Ai) { $script:AiStatus = "skipped - $NativeAiNote" }
  if (Deploy-Native) { Show-Summary "native"; if (-not $Ai) { Info $NativeAiNote } }
  exit 0
}

Select-Ai
if ($Docker) {
  if (Deploy-Docker) { Install-Ai; Show-Summary "docker"; exit 0 }
  Die "The Docker install failed and -Docker was forced (no fallback). Nothing was left running."
}

# default: auto - try Docker, fall back to native automatically
if (Deploy-Docker) { Install-Ai; Show-Summary "docker"; exit 0 }
Warn "Docker path unavailable - installing natively instead (no Docker needed)."
if ($script:AiOn) { $script:AiStatus = "skipped - $NativeAiNote" }
$script:AiOn = $false
if (Deploy-Native) { Show-Summary "native" }
