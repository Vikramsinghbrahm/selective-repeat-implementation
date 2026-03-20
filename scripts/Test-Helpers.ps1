[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RepoRoot {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    $scriptsDirectory = Split-Path -Parent $ScriptPath
    return Split-Path -Parent $scriptsDirectory
}

function Get-GoExecutable {
    $preferredPath = 'C:\Program Files\Go\bin\go.exe'
    if (Test-Path $preferredPath) {
        return $preferredPath
    }

    $command = Get-Command go -ErrorAction Stop
    return $command.Source
}

function Set-GoWorkspaceEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $env:GOTOOLCHAIN = 'local'
    $env:GOCACHE = Join-Path $RepoRoot '.gocache'
    $env:GOMODCACHE = Join-Path $RepoRoot '.gomodcache'

    New-Item -ItemType Directory -Force -Path $env:GOCACHE | Out-Null
    New-Item -ItemType Directory -Force -Path $env:GOMODCACHE | Out-Null
}

function Invoke-Go {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Set-GoWorkspaceEnvironment -RepoRoot $RepoRoot

    $goExecutable = Get-GoExecutable
    & $goExecutable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw ('go command failed: {0} {1}' -f $goExecutable, ($Arguments -join ' '))
    }
}

function New-TestRunDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runDirectory = Join-Path $RepoRoot ('.tmp-{0}-{1}' -f $Prefix, $timestamp)
    New-Item -ItemType Directory -Force -Path $runDirectory | Out-Null
    return $runDirectory
}

function Get-FreePort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function New-DeterministicBinaryFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [int]$SizeBytes
    )

    $bytes = New-Object byte[] $SizeBytes
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [byte](($index * 31 + 17) % 251)
    }

    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}

function Assert-HashEqual {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedPath,

        [Parameter(Mandatory = $true)]
        [string]$ActualPath,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $expectedHash = Get-Sha256 -Path $ExpectedPath
    $actualHash = Get-Sha256 -Path $ActualPath
    if ($expectedHash -ne $actualHash) {
        throw ('{0} hash mismatch. expected={1} actual={2}' -f $Label, $expectedHash, $actualHash)
    }
}

function Start-LoggedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [string]$StdoutPath,

        [Parameter(Mandatory = $true)]
        [string]$StderrPath
    )

    return Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $StdoutPath `
        -RedirectStandardError $StderrPath `
        -PassThru `
        -WindowStyle Hidden
}

function Wait-LoggedProcess {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory = $true)]
        [int]$TimeoutMs,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if (-not $Process.WaitForExit($TimeoutMs)) {
        try {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
        catch {
        }

        throw ('{0} timed out after {1} ms' -f $Label, $TimeoutMs)
    }

    $Process.Refresh()
    $exitCode = $Process.ExitCode
    if ($exitCode -is [int] -and $exitCode -ne 0) {
        throw ('{0} failed with exit code {1}' -f $Label, $exitCode)
    }
}

function Stop-ProcessIfRunning {
    param(
        [Parameter(Mandatory = $false)]
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process) {
        return
    }

    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
    }
}
