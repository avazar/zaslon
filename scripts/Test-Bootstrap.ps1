# Download fixtures only; optional real package uses private paths and NoStart.
[CmdletBinding()]
param([string]$WindowsPackage, [string]$BootstrapPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$testRepo = Split-Path $PSScriptRoot -Parent
if (-not $BootstrapPath) { $BootstrapPath = Join-Path $testRepo 'install.ps1' }
$bootstrapText = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $BootstrapPath).Path)
$testRoot = Join-Path $testRepo ('build/audit/bootstrap-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
$oldCapture = $env:ZASLON_BOOTSTRAP_TEST_CAPTURE
$env:ZASLON_BOOTSTRAP_TEST_CAPTURE = Join-Path $testRoot 'capture.json'
$script:bootstrapFixture = @{
    Version = ([IO.File]::ReadAllText((Join-Path $testRepo 'INSTALL_VERSION'))).Trim()
    Mode = 'ok'
    Requests = (New-Object Collections.Generic.List[string])
    Script = (Join-Path $testRoot 'release-installer.ps1')
}
$fakeInstaller = @'
[CmdletBinding()]
param([string]$Version,[string]$InstallDirectory,[string]$ProfileDirectory,
      [string]$PackagePath,[string]$ChecksumPath,[switch]$NoStart,
      [switch]$NoShortcut,[switch]$Headless,[switch]$Uninstall)
@{Version=$Version;InstallDirectory=$InstallDirectory;ProfileDirectory=$ProfileDirectory;
  PackagePath=$PackagePath;ChecksumPath=$ChecksumPath;NoStart=[bool]$NoStart;
  NoShortcut=[bool]$NoShortcut;Headless=[bool]$Headless;Uninstall=[bool]$Uninstall
} | ConvertTo-Json | Set-Content -LiteralPath $env:ZASLON_BOOTSTRAP_TEST_CAPTURE -Encoding UTF8
'@
[IO.File]::WriteAllText($script:bootstrapFixture.Script, $fakeInstaller, (New-Object Text.UTF8Encoding($false)))
function Invoke-RestMethod {
    param([string]$Uri, [int]$TimeoutSec)
    $script:bootstrapFixture.Requests.Add($Uri)
    if ($Uri -eq 'https://raw.githubusercontent.com/avazar/zaslon/dev/install.ps1') { return $bootstrapText }
    if ($Uri -ne 'https://raw.githubusercontent.com/avazar/zaslon/dev/INSTALL_VERSION') { throw "Unexpected request: $Uri" }
    if ($script:bootstrapFixture.Mode -eq 'invalid-version') { return '../../outside' }
    return $script:bootstrapFixture.Version
}
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [int]$TimeoutSec, [switch]$UseBasicParsing)
    $script:bootstrapFixture.Requests.Add($Uri)
    $base = 'https://github.com/avazar/zaslon/releases/download/v' + $script:bootstrapFixture.Version
    if ($Uri -eq "$base/install.ps1") {
        Copy-Item -LiteralPath $script:bootstrapFixture.Script -Destination $OutFile
        if ($script:bootstrapFixture.Mode -eq 'partial-download') { throw 'Injected interrupted download' }
        if ($script:bootstrapFixture.Mode -eq 'tampered') { [IO.File]::AppendAllText($OutFile, 'changed') }
    } elseif ($Uri -eq "$base/SHA256SUMS.txt") {
        $hash = (Get-FileHash -LiteralPath $script:bootstrapFixture.Script -Algorithm SHA256).Hash.ToLowerInvariant()
        $line = $hash + '  install.ps1' + [Environment]::NewLine
        if ($script:bootstrapFixture.Mode -eq 'duplicate') { $line += $line }
        if ($script:bootstrapFixture.Mode -eq 'missing') { $line = $hash + '  unrelated.ps1' }
        [IO.File]::WriteAllText($OutFile, $line, (New-Object Text.UTF8Encoding($false)))
    } else { throw "Unexpected request: $Uri" }
}
function Assert-Bootstrap([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
try {
    # Same pipeline as the public command; backend is a harmless capture fixture.
    $bootstrapText | Invoke-Expression
    $capture = Get-Content -LiteralPath $env:ZASLON_BOOTSTRAP_TEST_CAPTURE -Raw | ConvertFrom-Json
    Assert-Bootstrap ($capture.Version -eq $script:bootstrapFixture.Version -and -not $capture.Uninstall) 'Pipeline install did not select the published version.'
    $script:bootstrapFixture.Requests.Clear()
    $forward = @{
        Version = $script:bootstrapFixture.Version
        InstallDirectory = (Join-Path $testRoot 'program space')
        ProfileDirectory = (Join-Path $testRoot 'profile')
        PackagePath = 'archive path.zip'
        ChecksumPath = 'manifest path.txt'
        NoStart = $true; NoShortcut = $true; Headless = $true
    }
    & ([scriptblock]::Create($bootstrapText)) @forward
    $capture = Get-Content -LiteralPath $env:ZASLON_BOOTSTRAP_TEST_CAPTURE -Raw | ConvertFrom-Json
    Assert-Bootstrap ($capture.NoStart -and $capture.NoShortcut -and $capture.Headless -and $capture.PackagePath -eq $forward.PackagePath -and $capture.ProfileDirectory -eq $forward.ProfileDirectory) 'Installer arguments were not preserved.'
    Assert-Bootstrap ($script:bootstrapFixture.Requests.Count -eq 2) 'Explicit version unexpectedly read the default version.'
    [IO.File]::ReadAllText((Join-Path $testRepo 'uninstall.ps1')) | Invoke-Expression
    $capture = Get-Content -LiteralPath $env:ZASLON_BOOTSTRAP_TEST_CAPTURE -Raw | ConvertFrom-Json
    Assert-Bootstrap $capture.Uninstall 'Uninstall was not forwarded.'
    foreach ($mode in @('invalid-version','tampered','duplicate','missing','partial-download')) {
        if (Test-Path -LiteralPath $env:ZASLON_BOOTSTRAP_TEST_CAPTURE) { Remove-Item -LiteralPath $env:ZASLON_BOOTSTRAP_TEST_CAPTURE }
        $script:bootstrapFixture.Mode = $mode
        $rejected = $false
        try { $bootstrapText | Invoke-Expression } catch { $rejected = $true }
        Assert-Bootstrap ($rejected -and -not (Test-Path -LiteralPath $env:ZASLON_BOOTSTRAP_TEST_CAPTURE)) "Unsafe bootstrap executed backend: $mode"
    }
    $script:bootstrapFixture.Mode = 'ok'
    if ($WindowsPackage) {
        $package = (Resolve-Path -LiteralPath $WindowsPackage).Path
        $packageVersion = [regex]::Match((Split-Path $package -Leaf), '^zaslon-([0-9]+\.[0-9]+\.[0-9]+)-windows-').Groups[1].Value
        $script:bootstrapFixture.Version = $packageVersion
        $fullInstaller = [IO.File]::ReadAllText((Join-Path $testRepo 'scripts/install.ps1')).Replace('__ZASLON_VERSION__', $packageVersion)
        [IO.File]::WriteAllText($script:bootstrapFixture.Script, $fullInstaller, (New-Object Text.UTF8Encoding($false)))
        $privateOptions = @{
            Version=$packageVersion;InstallDirectory=(Join-Path $testRoot 'real package');
            ProfileDirectory=(Join-Path $testRoot 'real profile');
            PackagePath=$package;ChecksumPath=($package + '.sha256');NoStart=$true;NoShortcut=$true
        }
        & ([scriptblock]::Create($bootstrapText)) @privateOptions
        Assert-Bootstrap (Test-Path -LiteralPath (Join-Path $privateOptions.InstallDirectory 'zaslon-recover.exe')) 'Delegated install is incomplete.'
        $config = Join-Path $privateOptions.ProfileDirectory 'config.yaml'
        [IO.File]::WriteAllText($config, 'apps: []')
        $journal = Join-Path $privateOptions.ProfileDirectory 'process-recovery.json'
        [IO.File]::WriteAllText($journal, '{"version":1,"entries":{"123":{"phase":"frozen"}}}')
        $privateOptions.Uninstall = $true
        $rejected = $false
        try { & ([scriptblock]::Create($bootstrapText)) @privateOptions } catch { $rejected = $true }
        Assert-Bootstrap ($rejected -and (Test-Path -LiteralPath (Join-Path $privateOptions.InstallDirectory 'zaslon-recover.exe'))) 'Bootstrap uninstall bypassed recovery checks.'
        [IO.File]::WriteAllText($journal, '{"version":1,"entries":{}}')
        & ([scriptblock]::Create($bootstrapText)) @privateOptions
        Assert-Bootstrap (([IO.File]::ReadAllText($config)) -eq 'apps: []' -and -not (Test-Path -LiteralPath (Join-Path $privateOptions.InstallDirectory 'zaslon.exe'))) 'Delegated uninstall changed settings or left the executable.'
    }
    Write-Host "Bootstrap tests passed: $testRoot"
} finally {
    $env:ZASLON_BOOTSTRAP_TEST_CAPTURE = $oldCapture
}
