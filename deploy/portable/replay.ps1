param([Parameter(Mandatory = $true)][string]$PcapFile)
$ErrorActionPreference = 'Stop'
$pcap = (Resolve-Path -LiteralPath $PcapFile).Path
$binary = Join-Path $PSScriptRoot 'bin/ta_node.exe'
if (Get-Process ta_node -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $binary }) {
    throw 'Run stop.ps1 before replay to avoid sharing the API port and writable IOC store.'
}
Push-Location $PSScriptRoot
try {
    & $binary --config ./configs/ta_node.yaml --pcap-file $pcap
    if ($LASTEXITCODE -ne 0) { throw 'PCAP replay failed.' }
} finally { Pop-Location }
Write-Output 'Replay finished. Events: data/event_queue.db; evidence: data/evidence. Run start.ps1 to reopen the UI.'
