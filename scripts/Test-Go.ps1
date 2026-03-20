[CmdletBinding()]
param(
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptRoot 'Test-Helpers.ps1')

$repoRoot = Get-RepoRoot -ScriptPath $MyInvocation.MyCommand.Path
$binDirectory = Join-Path $repoRoot 'bin'

New-Item -ItemType Directory -Force -Path $binDirectory | Out-Null

Write-Host 'Running go test...'
Invoke-Go -RepoRoot $repoRoot -Arguments @('test', '-buildvcs=false', './...')

if (-not $SkipBuild) {
    Write-Host 'Building httpc.exe...'
    Invoke-Go -RepoRoot $repoRoot -Arguments @('build', '-buildvcs=false', '-o', '.\bin\httpc.exe', '.\cmd\httpc')

    Write-Host 'Building httpfs.exe...'
    Invoke-Go -RepoRoot $repoRoot -Arguments @('build', '-buildvcs=false', '-o', '.\bin\httpfs.exe', '.\cmd\httpfs')

    Write-Host 'Building router.exe...'
    Invoke-Go -RepoRoot $repoRoot -Arguments @('build', '-buildvcs=false', '-o', '.\bin\router.exe', '.\cmd\router')
}

[pscustomobject]@{
    RepoRoot = $repoRoot
    Tests    = 'PASS'
    Build    = if ($SkipBuild) { 'SKIPPED' } else { 'PASS' }
}
