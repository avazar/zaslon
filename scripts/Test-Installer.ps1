# Offline regression tests: fresh directories, no shortcuts, no autostart, no guard.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$WindowsPackage, [string]$WindowsChecksums)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$testRepo = Split-Path $PSScriptRoot -Parent
$testPackage = (Resolve-Path -LiteralPath $WindowsPackage).Path
$testSums = if ($WindowsChecksums) { (Resolve-Path -LiteralPath $WindowsChecksums).Path } else { $testPackage + '.sha256' }
$testRoot = Join-Path $testRepo ('build/audit/installer-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot
. (Join-Path $testRepo 'scripts/install.ps1')
$testVersion = [regex]::Match((Split-Path $testPackage -Leaf), '^zaslon-([0-9]+\.[0-9]+\.[0-9]+)-windows-').Groups[1].Value
$testOptions = @{Version=$testVersion;InstallDirectory=(Join-Path $testRoot ('installed space ' + [char]0x0442));ProfileDirectory=(Join-Path $testRoot 'profile');PackagePath=$testPackage;ChecksumPath=$testSums;NoStart=$true;NoShortcut=$true;Headless=$true}
$checks = New-Object Collections.Generic.List[string]
function Assert-Test([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Must-Fail([scriptblock]$Body, [string]$Message) {
    $failed = $false
    try { & $Body } catch { $failed = $true }
    Assert-Test $failed $Message
}
function New-MutatedArchive([string]$Mutation) {
    $file = Join-Path $testRoot ($Mutation + '.zip')
    $inputZip = [IO.Compression.ZipFile]::OpenRead($testPackage)
    $outputZip = [IO.Compression.ZipFile]::Open($file, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($entry in $inputZip.Entries) {
            if ($Mutation -eq 'missing-helper' -and $entry.FullName -eq 'zaslon-recover.exe') { continue }
            $newEntry = $outputZip.CreateEntry($entry.FullName)
            $from = $entry.Open(); $to = $newEntry.Open()
            try { $from.CopyTo($to) } finally { $from.Dispose(); $to.Dispose() }
        }
        if ($Mutation -eq 'zip-slip') {
            $entry = $outputZip.CreateEntry('../outside.txt')
            $writer = New-Object IO.StreamWriter($entry.Open())
            try { $writer.Write('must never be extracted') } finally { $writer.Dispose() }
        }
    } finally { $inputZip.Dispose(); $outputZip.Dispose() }
    $sum = Join-Path $testRoot ($Mutation + '.sha256')
    ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + (Split-Path $testPackage -Leaf)) | Set-Content -LiteralPath $sum -Encoding ASCII
    return @{PackagePath=$file;ChecksumPath=$sum}
}
try {
    Invoke-ZaslonInstaller $testOptions
    $receiptPath = Join-Path $testOptions.InstallDirectory 'install-receipt.json'
    $first = Read-SharedJSON $receiptPath
    Assert-Test (Test-Path -LiteralPath (Join-Path $testOptions.InstallDirectory 'zaslon-recover.exe')) 'Recovery helper missing.'
    Assert-Test (@(Get-InstallProcesses).Count -eq 0) 'NoStart launched protection.'
    $checks.Add('Fresh offline install includes helper and starts no processes.')
    $created = [datetime]::UtcNow.AddMinutes(-1)
    $fakeState = [pscustomobject]@{pid=200;config=(Join-Path $testOptions.ProfileDirectory 'config.yaml');updated=[datetime]::UtcNow}
    $fakeOwned = @(
        [pscustomobject]@{ProcessId=100;ParentProcessId=1;CreationDate=$created;CommandLine='zaslon.exe'},
        [pscustomobject]@{ProcessId=200;ParentProcessId=100;CreationDate=$created;CommandLine='zaslon.exe'},
        [pscustomobject]@{ProcessId=300;ParentProcessId=200;CreationDate=$created;CommandLine='"C:\program path\zaslon.exe" panel'}
    )
    $roles = Get-InstallProcessRoles $fakeOwned $fakeState
    Assert-Test ($roles.panels.Count -eq 1 -and $roles.supervisors.Count -eq 1 -and $roles.worker.Count -eq 1) 'Owned panel classified as another protection instance.'
    $foreign = [pscustomobject]@{ProcessId=400;ParentProcessId=1;CreationDate=$created;CommandLine='zaslon.exe headless'}
    Must-Fail { $null = Get-InstallProcessRoles (@($fakeOwned) + @($foreign)) $fakeState } 'Another instance was treated as an owned panel.'
    $checks.Add('Process grouping accepts owned panel children and refuses unrelated instances without operating on any PID.')
    $config = Join-Path $testOptions.ProfileDirectory 'config.yaml'
    [IO.File]::WriteAllText($config, "apps: []" + [Environment]::NewLine)
    $configHash = (Get-FileHash -LiteralPath $config).Hash
    Invoke-ZaslonInstaller $testOptions
    $second = Read-SharedJSON $receiptPath
    Assert-Test ($second.transaction -ne $first.transaction -and (Test-Path -LiteralPath $second.previous)) 'Previous installation not retained.'
    Assert-Test ((Get-FileHash -LiteralPath $config).Hash -eq $configHash) 'Settings changed during update.'
    Assert-Test (Test-Path -LiteralPath (Join-Path $second.previous 'profile-config-backup.yaml')) 'Settings backup missing.'
    $checks.Add('Update preserves settings and retains the complete previous installation.')
    $badArchive = Join-Path $testRoot 'bad-checksum.zip'
    Copy-Item -LiteralPath $testPackage -Destination $badArchive
    $stream = [IO.File]::OpenWrite($badArchive); try { $stream.WriteByte(0) } finally { $stream.Dispose() }
    $badOptions = $testOptions.Clone(); $badOptions.PackagePath = $badArchive
    Must-Fail { Invoke-ZaslonInstaller $badOptions } 'Corrupted archive accepted.'
    foreach ($mutation in @('zip-slip','missing-helper')) {
        $mutated = New-MutatedArchive $mutation
        $badOptions = $testOptions.Clone()
        $badOptions.PackagePath = $mutated.PackagePath; $badOptions.ChecksumPath = $mutated.ChecksumPath
        Must-Fail { Invoke-ZaslonInstaller $badOptions } "$mutation accepted."
    }
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $testRoot 'outside.txt'))) 'ZIP wrote outside staging.'
    Assert-Test ((Read-SharedJSON $receiptPath).transaction -eq $second.transaction) 'Rejected package changed the install.'
    $checks.Add('Bad checksum, ZIP traversal and incomplete package rejected before replacing installed files.')
    $startFunction = (Get-Item Function:Start-InstallRuntime).ScriptBlock
    try {
        Set-Item Function:Start-InstallRuntime { param([bool]$HeadlessMode) throw 'Injected startup failure' }
        $failing = $testOptions.Clone(); $failing.NoStart = $false
        Must-Fail { Invoke-ZaslonInstaller $failing } 'Startup failure was ignored.'
    } finally { Set-Item Function:Start-InstallRuntime $startFunction }
    Assert-Test ((Read-SharedJSON $receiptPath).transaction -eq $second.transaction) 'Failed startup did not restore previous files.'
    Assert-Test (-not (Test-Path -LiteralPath ($testOptions.InstallDirectory + '.install.json'))) 'Completed rollback left a pending transaction.'
    $checks.Add('Startup failure restores the entire previous installation without editing the recovery journal.')
    $interruptedID = [guid]::NewGuid().ToString('N')
    $interruptedBackup = $testOptions.InstallDirectory + '.backup-' + $interruptedID
    $interruptedStage = $testOptions.InstallDirectory + '.stage-' + $interruptedID
    $null = New-Item -ItemType Directory -Path $interruptedStage
    $pending = @{schema=1;id=$interruptedID;target=$testOptions.InstallDirectory;profile=$testOptions.ProfileDirectory;stage=$interruptedStage;backup=$interruptedBackup;hadInstall=$true;wasRunning=$false;headless=$true;committed=$false}
    Move-InstallDirectory $testOptions.InstallDirectory $interruptedBackup
    Write-InstallJSON ($testOptions.InstallDirectory + '.install.json') $pending
    $invalid = $testOptions.Clone(); $invalid.Version = 'invalid'
    Must-Fail { Invoke-ZaslonInstaller $invalid } 'Invalid version accepted.'
    Assert-Test ((Read-SharedJSON $receiptPath).transaction -eq $second.transaction) 'Interrupted directory swap not recovered on next invocation.'
    $checks.Add('Pending interrupted directory swap is rolled back before a new installation starts.')
    $journal = Join-Path $testOptions.ProfileDirectory 'process-recovery.json'
    [IO.File]::WriteAllText($journal, '{"version":1,"entries":{"123":{"phase":"frozen"}}}')
    $uninstallOptions = $testOptions.Clone(); $uninstallOptions.Uninstall = $true
    Must-Fail { Invoke-ZaslonInstaller $uninstallOptions } 'Uninstall accepted unresolved suspensions.'
    Assert-Test (Test-Path -LiteralPath (Join-Path $testOptions.InstallDirectory 'zaslon-recover.exe')) 'Rejected uninstall removed helper.'
    [IO.File]::WriteAllText($journal, '{"version":1,"entries":{}}')
    $sentinel = Join-Path $testOptions.InstallDirectory 'user-file.txt'
    [IO.File]::WriteAllText($sentinel, 'keep')
    Invoke-ZaslonInstaller $uninstallOptions
    Assert-Test ((Get-FileHash -LiteralPath $config).Hash -eq $configHash -and (Test-Path -LiteralPath $sentinel)) 'Uninstall removed settings or an unrelated file.'
    Assert-Test (-not (Test-Path -LiteralPath (Join-Path $testOptions.InstallDirectory 'zaslon.exe'))) 'Uninstall left installed executable.'
    $checks.Add('Uninstall refuses unresolved suspensions and preserves settings, backups and unrelated files.')
    @{passed=$true;checks=@($checks);root=$testRoot} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot 'result.json') -Encoding UTF8
    Write-Host ('Installer regression tests passed: ' + $testRoot)
} catch {
    @{passed=$false;error=$_.ToString();checks=@($checks);root=$testRoot} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $testRoot 'result.json') -Encoding UTF8
    throw
}
