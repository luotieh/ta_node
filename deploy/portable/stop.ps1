$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'bin/ta_node.exe'
$running = Get-Process ta_node -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $binary }
if ($running) {
    $running | Stop-Process
    $running | Wait-Process -ErrorAction SilentlyContinue
    Write-Output 'Stopped this deployment.'
} else { Write-Output 'This deployment is not running.' }
