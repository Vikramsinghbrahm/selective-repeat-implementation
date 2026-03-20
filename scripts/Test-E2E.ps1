[CmdletBinding()]
param(
    [int]$ConcurrentRounds = 3,
    [int]$LargeFileBytes = 1048576,
    [int]$TimeoutSeconds = 90,
    [int]$RequestRetries = 3,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptRoot 'Test-Helpers.ps1')

$repoRoot = Get-RepoRoot -ScriptPath $MyInvocation.MyCommand.Path
$binDirectory = Join-Path $repoRoot 'bin'
$httpcPath = Join-Path $binDirectory 'httpc.exe'
$httpfsPath = Join-Path $binDirectory 'httpfs.exe'
$routerPath = Join-Path $binDirectory 'router.exe'
$legacyRouterPath = Join-Path $repoRoot 'dist\router.exe'

if (-not $SkipBuild) {
    & (Join-Path $scriptRoot 'Test-Go.ps1') | Out-Null
}

if (-not (Test-Path $httpcPath)) {
    throw ('Missing client binary: {0}' -f $httpcPath)
}
if (-not (Test-Path $httpfsPath)) {
    throw ('Missing server binary: {0}' -f $httpfsPath)
}
if (-not (Test-Path $routerPath)) {
    if (Test-Path $legacyRouterPath) {
        $routerPath = $legacyRouterPath
    }
    else {
        throw ('Missing router binary: {0}' -f $routerPath)
    }
}

$runDirectory = New-TestRunDirectory -RepoRoot $repoRoot -Prefix 'e2e'
$dataDirectory = Join-Path $runDirectory 'data'
$outputDirectory = Join-Path $runDirectory 'out'
$logDirectory = Join-Path $runDirectory 'logs'
$uploadsDirectory = Join-Path $dataDirectory 'uploads'

New-Item -ItemType Directory -Force -Path $dataDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
New-Item -ItemType Directory -Force -Path $uploadsDirectory | Out-Null

Copy-Item (Join-Path $repoRoot 'examples\data\sample.txt') (Join-Path $dataDirectory 'sample.txt')
Copy-Item (Join-Path $repoRoot 'examples\data\upload.txt') (Join-Path $dataDirectory 'upload.txt')
Copy-Item (Join-Path $repoRoot 'examples\data\large.txt') (Join-Path $dataDirectory 'large.txt')

$largeSourcePath = Join-Path $runDirectory 'big.bin'
New-DeterministicBinaryFile -Path $largeSourcePath -SizeBytes $LargeFileBytes
Copy-Item $largeSourcePath (Join-Path $dataDirectory 'big.bin')

$routerPort = Get-FreePort
do {
    $serverPort = Get-FreePort
} while ($serverPort -eq $routerPort)

$routerProcess = $null
$serverProcess = $null
$timeoutMilliseconds = $TimeoutSeconds * 1000

function Invoke-ClientRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [string]$StderrPath,

        [Parameter(Mandatory = $true)]
        [string]$Label
        ,
        [string[]]$CleanupPaths = @()
    )

    $lastError = $null
    for ($attempt = 1; $attempt -le $RequestRetries; $attempt++) {
        foreach ($path in $CleanupPaths) {
            if ($path -and (Test-Path $path)) {
                Remove-Item -Force $path
            }
        }

        try {
            $process = Start-LoggedProcess `
                -FilePath $httpcPath `
                -Arguments $Arguments `
                -WorkingDirectory $repoRoot `
                -StdoutPath $StdoutPath `
                -StderrPath $StderrPath

            Wait-LoggedProcess -Process $process -TimeoutMs $timeoutMilliseconds -Label $Label
            return
        }
        catch {
            $lastError = $_
            if ($attempt -lt $RequestRetries) {
                Write-Host ('Retrying {0} ({1}/{2})...' -f $Label, ($attempt + 1), $RequestRetries)
                Start-Sleep -Seconds 1
            }
        }
    }

    throw $lastError
}

function Invoke-ConcurrentDownloadRounds {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RemotePath,

        [Parameter(Mandatory = $true)]
        [string]$ExpectedPath,

        [Parameter(Mandatory = $true)]
        [string]$OutputPrefix,

        [Parameter(Mandatory = $true)]
        [string]$LabelPrefix
    )

    Write-Host ('Running {0} concurrent download rounds for {1}...' -f $ConcurrentRounds, $RemotePath)
    for ($round = 1; $round -le $ConcurrentRounds; $round++) {
        $lastError = $null
        $completed = $false

        for ($attempt = 1; $attempt -le $RequestRetries; $attempt++) {
            $client1Output = Join-Path $outputDirectory ('{0}-round-{1}-client-1' -f $OutputPrefix, $round)
            $client2Output = Join-Path $outputDirectory ('{0}-round-{1}-client-2' -f $OutputPrefix, $round)

            foreach ($path in @($client1Output, $client2Output)) {
                if (Test-Path $path) {
                    Remove-Item -Force $path
                }
            }

            $client1 = $null
            $client2 = $null

            try {
                $client1 = Start-LoggedProcess `
                    -FilePath $httpcPath `
                    -Arguments @('get', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-o', $client1Output, ("http://localhost:{0}/{1}" -f $serverPort, $RemotePath)) `
                    -WorkingDirectory $repoRoot `
                    -StdoutPath (Join-Path $logDirectory ('{0}-round-{1}-client-1.stdout.log' -f $OutputPrefix, $round)) `
                    -StderrPath (Join-Path $logDirectory ('{0}-round-{1}-client-1.stderr.log' -f $OutputPrefix, $round))

                $client2 = Start-LoggedProcess `
                    -FilePath $httpcPath `
                    -Arguments @('get', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-o', $client2Output, ("http://localhost:{0}/{1}" -f $serverPort, $RemotePath)) `
                    -WorkingDirectory $repoRoot `
                    -StdoutPath (Join-Path $logDirectory ('{0}-round-{1}-client-2.stdout.log' -f $OutputPrefix, $round)) `
                    -StderrPath (Join-Path $logDirectory ('{0}-round-{1}-client-2.stderr.log' -f $OutputPrefix, $round))

                Wait-LoggedProcess -Process $client1 -TimeoutMs $timeoutMilliseconds -Label ('{0} round {1} client 1' -f $LabelPrefix, $round)
                Wait-LoggedProcess -Process $client2 -TimeoutMs $timeoutMilliseconds -Label ('{0} round {1} client 2' -f $LabelPrefix, $round)

                Assert-HashEqual -ExpectedPath $ExpectedPath -ActualPath $client1Output -Label ('{0} round {1} client 1' -f $LabelPrefix, $round)
                Assert-HashEqual -ExpectedPath $ExpectedPath -ActualPath $client2Output -Label ('{0} round {1} client 2' -f $LabelPrefix, $round)

                $completed = $true
                break
            }
            catch {
                $lastError = $_
                Stop-ProcessIfRunning -Process $client1
                Stop-ProcessIfRunning -Process $client2

                if ($attempt -lt $RequestRetries) {
                    Write-Host ('Retrying {0} round {1} ({2}/{3})...' -f $LabelPrefix, $round, ($attempt + 1), $RequestRetries)
                    Start-Sleep -Seconds 1
                }
            }
        }

        if (-not $completed) {
            throw $lastError
        }
    }
}

try {
    Write-Host ('Starting router on UDP port {0}...' -f $routerPort)
    $routerProcess = Start-LoggedProcess `
        -FilePath $routerPath `
        -Arguments @("--port=$routerPort", '--drop-rate=0', '--max-delay=0s', '--seed=1') `
        -WorkingDirectory $repoRoot `
        -StdoutPath (Join-Path $logDirectory 'router.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'router.stderr.log')

    Start-Sleep -Seconds 1
    $routerProcess.Refresh()
    if ($routerProcess.HasExited) {
        throw 'router exited before tests started'
    }

    Write-Host ('Starting file server on UDP port {0}...' -f $serverPort)
    $serverProcess = Start-LoggedProcess `
        -FilePath $httpfsPath `
        -Arguments @('-p', "$serverPort", '-d', $dataDirectory, '--timeout', '2s', '--session-deadline', ('{0}s' -f $TimeoutSeconds), '--metrics-interval', '5s', '--log-transport') `
        -WorkingDirectory $repoRoot `
        -StdoutPath (Join-Path $logDirectory 'server.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'server.stderr.log')

    Start-Sleep -Seconds 2
    $serverProcess.Refresh()
    if ($serverProcess.HasExited) {
        throw 'httpfs exited before tests started'
    }

    Write-Host 'Running small GET...'
    $smallGetOutput = Join-Path $outputDirectory 'small-get.txt'
    Invoke-ClientRequest `
        -Arguments @('get', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-o', $smallGetOutput, ("http://localhost:{0}/sample.txt" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'small-get.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'small-get.stderr.log') `
        -Label 'small GET' `
        -CleanupPaths @($smallGetOutput)
    Assert-HashEqual -ExpectedPath (Join-Path $dataDirectory 'sample.txt') -ActualPath $smallGetOutput -Label 'small GET'

    Write-Host 'Running small POST round-trip...'
    Invoke-ClientRequest `
        -Arguments @('post', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-f', (Join-Path $dataDirectory 'upload.txt'), ("http://localhost:{0}/uploads/small-posted.txt" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'small-post.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'small-post.stderr.log') `
        -Label 'small POST'

    $smallPostOutput = Join-Path $outputDirectory 'small-posted.txt'
    Invoke-ClientRequest `
        -Arguments @('get', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-o', $smallPostOutput, ("http://localhost:{0}/uploads/small-posted.txt" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'small-post-verify.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'small-post-verify.stderr.log') `
        -Label 'small POST verify' `
        -CleanupPaths @($smallPostOutput)
    Assert-HashEqual -ExpectedPath (Join-Path $dataDirectory 'upload.txt') -ActualPath $smallPostOutput -Label 'small POST round-trip'

    Write-Host 'Running large GET...'
    $largeGetOutput = Join-Path $outputDirectory 'big-get.bin'
    Invoke-ClientRequest `
        -Arguments @('get', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-o', $largeGetOutput, ("http://localhost:{0}/big.bin" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'big-get.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'big-get.stderr.log') `
        -Label 'large GET' `
        -CleanupPaths @($largeGetOutput)
    Assert-HashEqual -ExpectedPath (Join-Path $dataDirectory 'big.bin') -ActualPath $largeGetOutput -Label 'large GET'

    Write-Host 'Running large POST round-trip...'
    Invoke-ClientRequest `
        -Arguments @('post', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-f', $largeSourcePath, ("http://localhost:{0}/uploads/big-posted.bin" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'big-post.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'big-post.stderr.log') `
        -Label 'large POST'

    $largePostOutput = Join-Path $outputDirectory 'big-posted.bin'
    Invoke-ClientRequest `
        -Arguments @('get', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-o', $largePostOutput, ("http://localhost:{0}/uploads/big-posted.bin" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'big-post-verify.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'big-post-verify.stderr.log') `
        -Label 'large POST verify' `
        -CleanupPaths @($largePostOutput)
    Assert-HashEqual -ExpectedPath $largeSourcePath -ActualPath $largePostOutput -Label 'large POST round-trip'

    Write-Host 'Running large text GET...'
    $largeTextGetOutput = Join-Path $outputDirectory 'large-text-get.txt'
    Invoke-ClientRequest `
        -Arguments @('get', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-o', $largeTextGetOutput, ("http://localhost:{0}/large.txt" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'large-text-get.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'large-text-get.stderr.log') `
        -Label 'large text GET' `
        -CleanupPaths @($largeTextGetOutput)
    Assert-HashEqual -ExpectedPath (Join-Path $dataDirectory 'large.txt') -ActualPath $largeTextGetOutput -Label 'large text GET'

    Write-Host 'Running large text POST round-trip...'
    Invoke-ClientRequest `
        -Arguments @('post', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-f', (Join-Path $dataDirectory 'large.txt'), ("http://localhost:{0}/uploads/large-posted.txt" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'large-text-post.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'large-text-post.stderr.log') `
        -Label 'large text POST'

    $largeTextPostOutput = Join-Path $outputDirectory 'large-posted.txt'
    Invoke-ClientRequest `
        -Arguments @('get', '--router-host', 'localhost', '--router-port', "$routerPort", '--deadline', ('{0}s' -f $TimeoutSeconds), '--log-transport', '--metrics', '-o', $largeTextPostOutput, ("http://localhost:{0}/uploads/large-posted.txt" -f $serverPort)) `
        -StdoutPath (Join-Path $logDirectory 'large-text-post-verify.stdout.log') `
        -StderrPath (Join-Path $logDirectory 'large-text-post-verify.stderr.log') `
        -Label 'large text POST verify' `
        -CleanupPaths @($largeTextPostOutput)
    Assert-HashEqual -ExpectedPath (Join-Path $dataDirectory 'large.txt') -ActualPath $largeTextPostOutput -Label 'large text POST round-trip'

    Invoke-ConcurrentDownloadRounds `
        -RemotePath 'big.bin' `
        -ExpectedPath (Join-Path $dataDirectory 'big.bin') `
        -OutputPrefix 'binary' `
        -LabelPrefix 'concurrent binary GET'

    Invoke-ConcurrentDownloadRounds `
        -RemotePath 'large.txt' `
        -ExpectedPath (Join-Path $dataDirectory 'large.txt') `
        -OutputPrefix 'text' `
        -LabelPrefix 'concurrent text GET'

    [pscustomobject]@{
        RunDirectory          = $runDirectory
        RouterPort            = $routerPort
        ServerPort            = $serverPort
        SmallGet              = 'PASS'
        SmallPost             = 'PASS'
        LargeGet              = 'PASS'
        LargePost             = 'PASS'
        LargeTextGet          = 'PASS'
        LargeTextPost         = 'PASS'
        ConcurrentLargeRounds = $ConcurrentRounds
        ConcurrentLargeGet    = 'PASS'
        ConcurrentLargeText   = 'PASS'
        LargeFileBytes        = $LargeFileBytes
    }
}
finally {
    Stop-ProcessIfRunning -Process $serverProcess
    Stop-ProcessIfRunning -Process $routerProcess
}
