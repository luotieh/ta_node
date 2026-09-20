$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'bin/ta_node.exe'
$running = Get-Process ta_node -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $binary }
if ($running) { Write-Output "Already running: PID $($running.Id)"; return }
New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot 'logs') | Out-Null
$process = Start-Process -FilePath $binary -ArgumentList '--config', './configs/ta_node.yaml', '--config-only' -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $PSScriptRoot 'logs/stdout.log') -RedirectStandardError (Join-Path $PSScriptRoot 'logs/stderr.log') -PassThru
Start-Sleep -Seconds 1
if ($process.HasExited) { throw 'Startup failed. See logs/stderr.log.' }
Write-Output "Started config and intel service: PID $($process.Id). Default URL: http://127.0.0.1:19090/config"
