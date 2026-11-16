# Windows entry point for irm .../dev/install.ps1 | iex.
# The full installer comes from a published release and is checked before execution.
[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDirectory,
    [string]$ProfileDirectory,
    [string]$PackagePath,
    [string]$ChecksumPath,
    [switch]$NoStart,
    [switch]$NoShortcut,
    [switch]$Headless,
    [switch]$Uninstall
)
& {
    param([System.Collections.IDictionary]$BoundOptions)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $options = @{}
    foreach ($key in $BoundOptions.Keys) { $options[$key] = $BoundOptions[$key] }
    $work = Join-Path ([IO.Path]::GetTempPath()) ('zaslon-bootstrap-' + [guid]::NewGuid().ToString('N'))
    $scriptFile = Join-Path $work 'install.ps1'
    $sumsFile = Join-Path $work 'SHA256SUMS.txt'
    $null = New-Item -ItemType Directory -Path $work
    try {
        $oldTLS = [Net.ServicePointManager]::SecurityProtocol
        try {
            [Net.ServicePointManager]::SecurityProtocol = $oldTLS -bor [Net.SecurityProtocolType]::Tls12
            $releaseVersion = if ($options.ContainsKey('Version')) { $options.Version } else {
                Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/avazar/zaslon/dev/INSTALL_VERSION' -TimeoutSec 30
            }
            $releaseVersion = ([string]$releaseVersion).Trim() -replace '^v',''
            if ($releaseVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
                throw 'The published installer version must be x.y.z.'
            }
            $base = "https://github.com/avazar/zaslon/releases/download/v$releaseVersion"
            Invoke-WebRequest -UseBasicParsing -Uri "$base/install.ps1" -OutFile $scriptFile -TimeoutSec 30
            Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile $sumsFile -TimeoutSec 30
        } finally {
            [Net.ServicePointManager]::SecurityProtocol = $oldTLS
        }
        $entries = @([IO.File]::ReadAllLines($sumsFile) | Where-Object { $_ -match '^([a-fA-F0-9]{64})  install\.ps1$' })
        if ($entries.Count -ne 1) { throw 'Missing or duplicate installer checksum.' }
        $expected = ($entries[0] -split '  ',2)[0]
        if ((Get-FileHash -LiteralPath $scriptFile -Algorithm SHA256).Hash -ne $expected) { throw 'Installer checksum mismatch.' }
        $options.Version = $releaseVersion
        & ([scriptblock]::Create([IO.File]::ReadAllText($scriptFile))) @options
    } finally {
        # Only our two known files and an empty temporary directory are removed.
        foreach ($file in @($scriptFile,$sumsFile)) {
            if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file -Force }
        }
        if (Test-Path -LiteralPath $work -PathType Container) { Remove-Item -LiteralPath $work }
    }
} $PSBoundParameters
