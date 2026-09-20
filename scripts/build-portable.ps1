param(
    [string]$Go = 'go',
    [ValidateSet('windows-amd64', 'linux-amd64', 'linux-arm64')]
    [string[]]$Targets = @('windows-amd64', 'linux-amd64', 'linux-arm64')
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$oldOS, $oldArch, $oldCGO = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED
Push-Location $repo
try {
    foreach ($target in $Targets) {
        $env:GOOS, $env:GOARCH = $target.Split('-')
        $env:CGO_ENABLED = '0'
        $out = Join-Path $repo "dist/$target"
        foreach ($dir in @('bin', 'configs', 'data/ioc', 'data/evidence', 'logs')) {
            New-Item -ItemType Directory -Force -Path (Join-Path $out $dir) | Out-Null
        }
        $binary = if ($env:GOOS -eq 'windows') { 'ta_node.exe' } else { 'ta_node' }
        & $Go build -mod=vendor -trimpath '-ldflags=-s -w' -o (Join-Path $out "bin/$binary") ./cmd/ta_node
        if ($LASTEXITCODE -ne 0) { throw "Build failed: $target" }
        $queueBinary = if ($env:GOOS -eq 'windows') { 'ta_queue.exe' } else { 'ta_queue' }
        & $Go build -mod=vendor -trimpath '-ldflags=-s -w' -o (Join-Path $out "bin/$queueBinary") ./cmd/ta_queue
        if ($LASTEXITCODE -ne 0) { throw "Queue tool build failed: $target" }
        # Preserve writable configuration and IOC data across rebuilds.
        if (-not (Test-Path (Join-Path $out 'configs/ta_node.yaml'))) {
            Copy-Item deploy/portable/ta_node.yaml (Join-Path $out 'configs/ta_node.yaml')
        }
        if (-not (Test-Path (Join-Path $out 'configs/intel.yaml'))) {
            Copy-Item configs/intel.yaml (Join-Path $out 'configs/intel.yaml')
        }
        Copy-Item patterns $out -Recurse -Force
        Copy-Item deploy/portable/README.md $out -Force
        if ($env:GOOS -eq 'windows') {
            Copy-Item deploy/portable/*.ps1 $out -Force
        } else {
            Copy-Item deploy/portable/start.sh,deploy/portable/ta_node.service $out -Force
            $archive = Join-Path $repo "dist/ta_node-$target.tar.gz"
            & tar.exe -czf $archive -C $out .
            if ($LASTEXITCODE -ne 0) { throw "Packaging failed: $target" }
        }
        Write-Output "Built: $out"
    }
} finally {
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED = $oldOS, $oldArch, $oldCGO
    Pop-Location
}
