[CmdletBinding()]
param(
    [int]$ConcurrentRounds = 3,
    [int]$LargeFileBytes = 1048576,
    [int]$TimeoutSeconds = 90,
    [int]$RequestRetries = 3
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host 'Running Go package tests and builds...'
& (Join-Path $scriptRoot 'Test-Go.ps1') | Out-Null

Write-Host 'Running end-to-end transport tests...'
& (Join-Path $scriptRoot 'Test-E2E.ps1') `
    -SkipBuild `
    -ConcurrentRounds $ConcurrentRounds `
    -LargeFileBytes $LargeFileBytes `
    -TimeoutSeconds $TimeoutSeconds `
    -RequestRetries $RequestRetries
