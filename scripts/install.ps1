# Windows PowerShell 5.1+. Release packaging pins the default version below.
# Run with &, or invoke a downloaded script block with &: no global policy changes.
[CmdletBinding()]
param(
    [string]$Version = '__ZASLON_VERSION__',
    [string]$InstallDirectory,
    [string]$ProfileDirectory,
    [string]$PackagePath,
    [string]$ChecksumPath,
    [switch]$NoStart,
    [switch]$NoShortcut,
    [switch]$Headless,
    [switch]$Uninstall
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Use this host's bundled modules even when launched by a different PowerShell
# edition through another program with an inherited PSModulePath.
foreach ($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','CimCmdlets')) {
    Import-Module (Join-Path (Join-Path $PSHOME 'Modules') $module) -ErrorAction Stop
}

function Get-FullPath([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) { throw 'Use an absolute local path.' }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $part = $full
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            if ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point refused: $part" }
        }
        $next = Split-Path $part -Parent
        if ($next -eq $part) { break }
        $part = $next
    }
    return $full
}
function Write-InstallJSON([string]$Path, $Value) {
    $null = Get-FullPath $Path
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 8))
    $temporary = $Path + '.tmp'
    $null = Get-FullPath $temporary
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
    else { [IO.File]::Move($temporary, $Path) }
}
function Assert-Sibling([string]$Path, [string]$Kind) {
    $full = Get-FullPath $Path
    $prefix = [regex]::Escape($script:install.Leaf + '.' + $Kind + '-')
    if ((Split-Path $full -Parent) -ne $script:install.Parent -or (Split-Path $full -Leaf) -notmatch ('^' + $prefix + '[a-f0-9]{32}$')) {
        throw 'Invalid installer-owned sibling path.'
    }
    return $full
}
function Move-InstallDirectory([string]$Source, [string]$Destination) {
    foreach ($path in @($Source,$Destination)) {
        $full = Get-FullPath $path
        if ($full -ne $script:install.Target) {
            $valid = $false
            foreach ($kind in @('stage','backup','failed')) {
                try { $null = Assert-Sibling $full $kind; $valid = $true; break } catch {}
            }
            if (-not $valid) { throw 'Directory move outside the managed installation.' }
        }
    }
    [IO.Directory]::Move($Source, $Destination)
}
function Read-Receipt([string]$Directory) {
    $receiptFile = Join-Path (Get-FullPath $Directory) 'install-receipt.json'
    if (-not (Test-Path -LiteralPath $receiptFile -PathType Leaf)) { throw "Not an installer-managed directory: $Directory" }
    $null = Get-FullPath $receiptFile
    $receipt = [IO.File]::ReadAllText($receiptFile) | ConvertFrom-Json
    if ($receipt.schema -ne 1 -or $receipt.product -ne 'Zaslon' -or $receipt.target -ne $script:install.Target -or $receipt.profile -ne $script:install.Profile) {
        throw 'Installation receipt does not match this directory/profile.'
    }
    return $receipt
}
function Read-SharedJSON([string]$Path) {
    # Do not obstruct Go's atomic replacement of state/config/recovery files.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $reader = New-Object IO.StreamReader($stream)
    try { return ($reader.ReadToEnd() | ConvertFrom-Json) } finally { $reader.Dispose() }
}
function Get-InstallProcesses {
    $exe = Join-Path $script:install.Target 'zaslon.exe'
    return @(Get-CimInstance Win32_Process -Filter "Name='zaslon.exe'" | Where-Object { $_.ExecutablePath -and [IO.Path]::GetFullPath($_.ExecutablePath) -eq $exe })
}
function Initialize-ProcessAPI {
    if ('ZaslonInstaller.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace ZaslonInstaller {
  public static class Native {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int id);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h, uint flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr h, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CommandLineToArgvW(string commandLine, out int count);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    public static bool SameCreated(long left, long right) { return left / 10 == right / 10; }
    public static bool IsPanel(string commandLine) {
      if (String.IsNullOrEmpty(commandLine)) return false;
      int count; IntPtr args = CommandLineToArgvW(commandLine, out count);
      if (args == IntPtr.Zero) throw new Win32Exception();
      try { return count == 2 && Marshal.PtrToStringUni(Marshal.ReadIntPtr(args, IntPtr.Size)) == "panel"; }
      finally { LocalFree(args); }
    }
    public static void Stop(int id, string path, long expectedCreated) {
      IntPtr h = OpenProcess(0x1000 | 0x100000 | 1, false, id);
      if (h == IntPtr.Zero) {
        int error = Marshal.GetLastWin32Error();
        if (error == 87) return;
        throw new Win32Exception(error);
      }
      try {
        if (WaitForSingleObject(h, 0) == 0) return;
        var image = new StringBuilder(32768); int length = image.Capacity;
        long created, exited, kernel, user;
        if (!QueryFullProcessImageName(h, 0, image, ref length) ||
            !GetProcessTimes(h, out created, out exited, out kernel, out user)) throw new Win32Exception();
        if (!String.Equals(image.ToString(), path, StringComparison.OrdinalIgnoreCase) ||
            created / 10 != expectedCreated / 10) throw new InvalidOperationException("Process identity changed; refused to stop it.");
        if (!TerminateProcess(h, 1)) throw new Win32Exception();
        if (WaitForSingleObject(h, 5000) != 0) throw new TimeoutException("Process did not stop.");
      } finally { CloseHandle(h); }
    }
  }
}
'@
}
function Get-InstallProcessRoles($Owned, $State) {
    Initialize-ProcessAPI
    $owned = @($Owned); $state = $State
    $worker = @($owned | Where-Object { $_.ProcessId -eq $state.pid })
    if ($worker.Count -ne 1 -or $state.config -ne (Join-Path $script:install.Profile 'config.yaml') -or
        ([datetime]$state.updated).ToUniversalTime() -lt $worker[0].CreationDate.ToUniversalTime()) {
        throw 'Cannot identify the running profile; no process was stopped.'
    }
    $panels = @($owned | Where-Object { $_.ProcessId -ne $state.pid -and $_.ParentProcessId -eq $state.pid -and [ZaslonInstaller.Native]::IsPanel($_.CommandLine) })
    $panelIDs = @($panels | ForEach-Object { $_.ProcessId })
    $supervisors = @($owned | Where-Object { $_.ProcessId -ne $state.pid -and $_.ProcessId -notin $panelIDs })
    if ($supervisors.Count -gt 1 -or ($supervisors.Count -eq 1 -and $worker[0].ParentProcessId -ne $supervisors[0].ProcessId)) {
        throw 'Multiple Zaslon instances use this executable; update each installation separately.'
    }
    return @{supervisors=$supervisors;panels=$panels;worker=$worker}
}
function Stop-InstallProcesses {
    $owned = @(Get-InstallProcesses)
    if ($owned.Count -eq 0) { return }
    Initialize-ProcessAPI
    try {
        $state = Read-SharedJSON (Join-Path $script:install.Profile 'state.json')
        $roles = Get-InstallProcessRoles $owned $state
        $ordered = @($roles.supervisors) + @($roles.panels) + @($roles.worker)
    } catch {
        # A failed new worker may never write state.json. Only the process tree
        # whose root we started and recorded may be stopped without that proof.
        if (-not $script:install.ContainsKey('Started')) { throw }
        $started = $script:install.Started
        $known = @($owned | Where-Object { $_.ProcessId -eq $started.id -and
            [ZaslonInstaller.Native]::SameCreated($_.CreationDate.ToUniversalTime().ToFileTimeUtc(), [long]$started.created) })
        if ($known.Count -ne 1) { throw 'Cannot identify the newly started process; rollback preserved for inspection.' }
        $ordered = @($known[0])
        do {
            $countBefore = $ordered.Count
            $knownIDs = @($ordered | ForEach-Object { $_.ProcessId })
            $ordered += @($owned | Where-Object { $_.ProcessId -notin $knownIDs -and $_.ParentProcessId -in $knownIDs })
        } while ($ordered.Count -gt $countBefore)
        if ($ordered.Count -ne $owned.Count) { throw 'Unrelated instance prevents rollback.' }
    }
    Initialize-ProcessAPI
    # Kill supervisors first; forced termination never runs the normal exit/resume.
    foreach ($process in $ordered) {
        [ZaslonInstaller.Native]::Stop([int]$process.ProcessId, (Join-Path $script:install.Target 'zaslon.exe'), $process.CreationDate.ToUniversalTime().ToFileTimeUtc())
    }
    if (@(Get-InstallProcesses).Count -ne 0) { throw 'Another instance started during update.' }
}
function Invoke-Version([string]$Exe, [string]$Arguments, [string]$Expected, [string]$ProbeProfile) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Exe
    $info.Arguments = $Arguments
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.EnvironmentVariables['ZASLON_DIR'] = $ProbeProfile
    $process = [Diagnostics.Process]::Start($info)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) { $process.Kill(); throw 'Version command timed out.' }
        if ($process.ExitCode -ne 0 -or $output.Result.Trim() -ne $Expected) { throw ('Invalid package executable version: ' + $errors.Result) }
    } finally { $process.Dispose() }
}
function Start-InstallRuntime([bool]$HeadlessMode) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = Join-Path $script:install.Target 'zaslon.exe'
    if ($HeadlessMode) { $info.Arguments = 'headless' }
    # ShellExecute detaches the long-lived GUI process from the installer's
    # redirected stdout/stderr, otherwise callers waiting for EOF never finish.
    $info.UseShellExecute = $true
    $info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $started = [datetime]::UtcNow
    $savedProfile = $env:ZASLON_DIR
    $savedChild = $env:ZASLON_CHILD
    try {
        $env:ZASLON_CHILD = $null
        # Suppress first-launch autostart until installation is committed.
        $env:ZASLON_DIR = $script:install.Profile
        $process = [Diagnostics.Process]::Start($info)
        $script:install.Started = @{id=$process.Id;created=$process.StartTime.ToUniversalTime().ToFileTimeUtc()}
        $process.Dispose()
        if ($script:install.ContainsKey('Transaction')) {
            $script:install.Transaction.started = $script:install.Started
            Write-InstallJSON $script:install.Journal $script:install.Transaction
        }
    } finally {
        $env:ZASLON_DIR = $savedProfile
        $env:ZASLON_CHILD = $savedChild
    }
    $deadline = [datetime]::UtcNow.AddSeconds(20)
    do {
        try {
            $state = Read-SharedJSON (Join-Path $script:install.Profile 'state.json')
            $owned = @(Get-InstallProcesses | Where-Object { $_.ProcessId -eq $state.pid })
            if ($owned.Count -eq 1 -and ([datetime]$state.updated).ToUniversalTime() -ge $started -and
                $state.config -eq (Join-Path $script:install.Profile 'config.yaml')) { return }
        } catch {}
        Start-Sleep -Milliseconds 200
    } while ([datetime]::UtcNow -lt $deadline)
    throw 'New Zaslon did not confirm startup; restoring the previous files.'
}
function Get-ReleaseFiles([string]$ReleaseVersion, [string]$Archive, [string]$Sums, [string]$Work) {
    $arch = $env:PROCESSOR_ARCHITEW6432
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch ($arch.ToUpperInvariant()) {
        'AMD64' { $arch = 'amd64' }
        'ARM64' { $arch = 'arm64' }
        default { throw 'Only 64-bit Windows AMD64/ARM64 is supported.' }
    }
    $name = "zaslon-$ReleaseVersion-windows-$arch.zip"
    if ($Archive) {
        if (-not $Sums) { throw '-PackagePath requires -ChecksumPath from the same trusted release.' }
        Copy-Item -LiteralPath $Archive -Destination (Join-Path $Work $name)
        Copy-Item -LiteralPath $Sums -Destination (Join-Path $Work 'SHA256SUMS.download.txt')
    } else {
        if ($Sums) { throw '-ChecksumPath requires -PackagePath.' }
        $base = "https://github.com/avazar/zaslon/releases/download/v$ReleaseVersion"
        $oldTLS = [Net.ServicePointManager]::SecurityProtocol
        try {
            [Net.ServicePointManager]::SecurityProtocol = $oldTLS -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $Work $name) -TimeoutSec 120
            Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS.txt" -OutFile (Join-Path $Work 'SHA256SUMS.download.txt') -TimeoutSec 30
        } finally { [Net.ServicePointManager]::SecurityProtocol = $oldTLS }
    }
    $matchesForArchive = @(Get-Content -LiteralPath (Join-Path $Work 'SHA256SUMS.download.txt') | Where-Object { $_ -match ('^([a-fA-F0-9]{64})  ' + [regex]::Escape($name) + '$') })
    if ($matchesForArchive.Count -ne 1 -or (Get-FileHash -LiteralPath (Join-Path $Work $name) -Algorithm SHA256).Hash -ne ($matchesForArchive[0] -split '  ',2)[0]) {
        throw 'Archive checksum mismatch or missing/duplicate checksum entry.'
    }
    return (Join-Path $Work $name)
}
function Expand-InstallPackage([string]$Archive, [string]$Destination, [string]$ReleaseVersion) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $expected = @('zaslon.exe','zaslon-recover.exe','VERSION','LICENSE','README.txt','SHA256SUMS.txt')
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName })
        if ($names.Count -ne $expected.Count -or @($names | Sort-Object -Unique).Count -ne $expected.Count -or
            @(Compare-Object $names $expected).Count -ne 0) { throw 'Unexpected, duplicate or unsafe ZIP entries.' }
        foreach ($entry in $zip.Entries) {
            if ($entry.Length -gt 100MB -or $entry.Length -lt 1 -or ($entry.ExternalAttributes -shr 16 -band 0xF000) -eq 0xA000) { throw 'Invalid ZIP entry.' }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $Destination $entry.FullName), $false)
        }
    } finally { $zip.Dispose() }
    if ([IO.File]::ReadAllText((Join-Path $Destination 'VERSION')).Trim() -ne $ReleaseVersion) { throw 'Package VERSION mismatch.' }
    $checksums = @(Get-Content -LiteralPath (Join-Path $Destination 'SHA256SUMS.txt'))
    $seen = @{}
    foreach ($line in $checksums) {
        if ($line -notmatch '^([a-fA-F0-9]{64})  ([^\\/:]+)$') { throw 'Invalid internal checksum entry.' }
        $hash = $Matches[1]; $name = $Matches[2]
        if ($name -notin $expected -or $name -eq 'SHA256SUMS.txt' -or $seen.ContainsKey($name)) { throw 'Unexpected internal checksum file.' }
        if ((Get-FileHash -LiteralPath (Join-Path $Destination $name) -Algorithm SHA256).Hash -ne $hash) { throw 'Internal package checksum mismatch.' }
        $seen[$name] = $true
    }
    if ($seen.Count -ne 5) { throw 'Incomplete internal checksums.' }
    $probe = Join-Path $Destination 'unused-probe-profile'
    Invoke-Version (Join-Path $Destination 'zaslon.exe') 'version' "zaslon $ReleaseVersion" $probe
    Invoke-Version (Join-Path $Destination 'zaslon-recover.exe') '-version' "zaslon-recover $ReleaseVersion" $probe
}
function Undo-Install($Transaction) {
    if ($Transaction.schema -ne 1 -or $Transaction.target -ne $script:install.Target -or $Transaction.profile -ne $script:install.Profile) { throw 'Invalid pending installation; preserved for inspection.' }
    $backup = Assert-Sibling $Transaction.backup 'backup'
    $stage = Assert-Sibling $Transaction.stage 'stage'
    if ($Transaction -is [hashtable]) { $hasStarted = $Transaction.ContainsKey('started') }
    else { $hasStarted = $null -ne $Transaction.PSObject.Properties['started'] }
    if ($hasStarted) { $script:install.Started = $Transaction.started }
    if ($Transaction.committed) { Remove-Item -LiteralPath $script:install.Journal; return }
    $isNew = $false
    if (Test-Path -LiteralPath $script:install.Target) {
        $receipt = Read-Receipt $script:install.Target
        $isNew = $receipt.transaction -eq $Transaction.id
    }
    if ($isNew) {
        Stop-InstallProcesses
        Move-InstallDirectory $script:install.Target (Join-Path $script:install.Parent ($script:install.Leaf + '.failed-' + [guid]::NewGuid().ToString('N')))
    }
    if (Test-Path -LiteralPath $backup) {
        $null = Read-Receipt $backup
        if (Test-Path -LiteralPath $script:install.Target) { throw 'Both original and backup exist; refusing to guess.' }
        Move-InstallDirectory $backup $script:install.Target
    } elseif ($Transaction.hadInstall -and -not (Test-Path -LiteralPath $script:install.Target)) {
        throw 'Previous installation missing; pending record preserved.'
    }
    if ($Transaction.wasRunning -and (Test-Path -LiteralPath $script:install.Target) -and @(Get-InstallProcesses).Count -eq 0) {
        Start-InstallRuntime ([bool]$Transaction.headless)
    }
    Remove-Item -LiteralPath $script:install.Journal
}
function Set-InstallShortcut {
    $programs = [Environment]::GetFolderPath('Programs')
    $link = Join-Path $programs 'Zaslon.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($link)
    if ((Test-Path -LiteralPath $link) -and $shortcut.TargetPath -ne (Join-Path $script:install.Target 'zaslon.exe')) { throw 'A shortcut for another installation already exists.' }
    $shortcut.TargetPath = Join-Path $script:install.Target 'zaslon.exe'
    $shortcut.WorkingDirectory = $script:install.Target
    $shortcut.IconLocation = $shortcut.TargetPath + ',0'
    $shortcut.Save()
}
function Remove-Install {
    $null = Read-Receipt $script:install.Target
    if (@(Get-InstallProcesses).Count -ne 0) { throw 'Exit Zaslon from its tray menu before uninstalling.' }
    $journalPath = Join-Path $script:install.Profile 'process-recovery.json'
    if (Test-Path -LiteralPath $journalPath) {
        $recovery = Read-SharedJSON $journalPath
        if ($recovery.version -ne 1 -or $recovery.entries -isnot [pscustomobject] -or @($recovery.entries.PSObject.Properties).Count -ne 0) {
            throw 'Recovery records remain. Restart Zaslon or use its separate recovery utility before uninstalling.'
        }
    }
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $auto = Get-ItemProperty -LiteralPath $runKey -Name Zaslon -ErrorAction SilentlyContinue
    if ($auto -and $auto.Zaslon -eq ('"' + (Join-Path $script:install.Target 'zaslon.exe') + '"')) {
        Remove-ItemProperty -LiteralPath $runKey -Name Zaslon
    }
    if (-not $script:install.NoShortcut) {
        $link = Join-Path ([Environment]::GetFolderPath('Programs')) 'Zaslon.lnk'
        if (Test-Path -LiteralPath $link) {
            $shortcut = (New-Object -ComObject WScript.Shell).CreateShortcut($link)
            if ($shortcut.TargetPath -eq (Join-Path $script:install.Target 'zaslon.exe')) { Remove-Item -LiteralPath $link }
        }
    }
    foreach ($name in @('zaslon.exe','zaslon-recover.exe','VERSION','LICENSE','README.txt','SHA256SUMS.txt','install-receipt.json')) {
        $path = Join-Path $script:install.Target $name
        $null = Get-FullPath $path
        if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
    }
    if (@(Get-ChildItem -LiteralPath $script:install.Target -Force).Count -eq 0) { [IO.Directory]::Delete($script:install.Target) }
    Write-Host ('Zaslon removed. Settings and recovery backups kept: ' + $script:install.Profile)
}
function Invoke-ZaslonInstaller([hashtable]$Options) {
    $defaults = @{ Version='__ZASLON_VERSION__'; InstallDirectory=(Join-Path $env:LOCALAPPDATA 'Programs\Zaslon'); ProfileDirectory=''; PackagePath=''; ChecksumPath=''; NoStart=$false; NoShortcut=$false; Headless=$false; Uninstall=$false }
    foreach ($key in $Options.Keys) { $defaults[$key] = $Options[$key] }
    $customProfile = [bool]$defaults.ProfileDirectory -or [bool]$env:ZASLON_DIR
    if (-not $defaults.ProfileDirectory) { $defaults.ProfileDirectory = if ($env:ZASLON_DIR) { $env:ZASLON_DIR } else { Join-Path $env:APPDATA 'Zaslon' } }
    if ($customProfile -and -not $defaults.NoShortcut) { throw 'Custom profiles require -NoShortcut; start with the same ZASLON_DIR.' }
    $target = Get-FullPath $defaults.InstallDirectory
    $profile = Get-FullPath $defaults.ProfileDirectory
    foreach ($protected in @($env:LOCALAPPDATA,$env:APPDATA,$env:WINDIR,$profile)) {
        if ($protected -and (($protected.TrimEnd('\') + '\').StartsWith($target + '\', [StringComparison]::OrdinalIgnoreCase) -or ($target + '\').StartsWith($profile + '\', [StringComparison]::OrdinalIgnoreCase))) { throw 'Unsafe installation directory.' }
    }
    $parent = Split-Path $target -Parent
    if (-not $parent -or $target -eq [IO.Path]::GetPathRoot($target).TrimEnd('\')) { throw 'Cannot install at a drive root.' }
    $null = New-Item -ItemType Directory -Path $parent -Force
    $script:install = @{ Target=$target; Profile=$profile; Parent=$parent; Leaf=(Split-Path $target -Leaf); CustomProfile=$customProfile; NoShortcut=[bool]$defaults.NoShortcut; Journal=($target + '.install.json') }
    foreach ($special in @($script:install.Journal,($target + '.install.lock'))) { $null = Get-FullPath $special }
    $mutex = [IO.File]::Open(($target + '.install.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $profileLock = $null
    try {
        if (Test-Path -LiteralPath $script:install.Journal) { Undo-Install (Read-SharedJSON $script:install.Journal) }
        if ($defaults.Uninstall) {
            $null = Read-Receipt $target
            if (@(Get-InstallProcesses).Count -ne 0) { throw 'Exit Zaslon from its tray menu before uninstalling.' }
            $null = New-Item -ItemType Directory -Path $profile -Force
            try { $profileLock = [IO.File]::Open((Join-Path $profile 'zaslon.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
            catch { throw 'The profile is still in use. Exit its Zaslon instance before uninstalling.' }
            Remove-Install
            return
        }
        $releaseVersion = $defaults.Version -replace '^v',''
        if ($releaseVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'Supply -Version x.y.z; use a version-pinned installer from a release.' }
        $hadInstall = Test-Path -LiteralPath $target
        $oldReceipt = $null
        if ($hadInstall) {
            $oldReceipt = Read-Receipt $target
            if ([version]$oldReceipt.version -gt [version]$releaseVersion) { throw 'Refusing an accidental downgrade.' }
        }
        $wasRunning = @(Get-InstallProcesses).Count -gt 0
        if ($wasRunning -and $defaults.NoStart) { throw '-NoStart cannot interrupt an active protection instance.' }
        $enableAutostart = -not $customProfile -and -not $defaults.NoStart -and -not (Test-Path -LiteralPath (Join-Path $profile 'config.yaml'))
        $transactionId = [guid]::NewGuid().ToString('N')
        $stage = Join-Path $parent ($script:install.Leaf + '.stage-' + $transactionId)
        $backup = Join-Path $parent ($script:install.Leaf + '.backup-' + $transactionId)
        $null = New-Item -ItemType Directory -Path $stage
        $archive = Get-ReleaseFiles $releaseVersion $defaults.PackagePath $defaults.ChecksumPath $stage
        # Downloads live in the stage only until extraction, then move beside it.
        $downloadArchive = $archive
        $downloadSums = Join-Path $stage 'SHA256SUMS.download.txt'
        Expand-InstallPackage $archive $stage $releaseVersion
        Remove-Item -LiteralPath $downloadArchive,$downloadSums
        $headlessMode = [bool]$defaults.Headless
        if ($oldReceipt) { $headlessMode = [bool]$oldReceipt.headless }
        $receipt = @{schema=1; product='Zaslon'; target=$target; profile=$profile; version=$releaseVersion; transaction=$transactionId; headless=$headlessMode; previous=$backup}
        Write-InstallJSON (Join-Path $stage 'install-receipt.json') $receipt
        $transaction = @{schema=1; id=$transactionId; target=$target; profile=$profile; stage=$stage; backup=$backup; hadInstall=[bool]$hadInstall; wasRunning=$wasRunning; headless=$headlessMode; committed=$false}
        $script:install.Transaction = $transaction
        Write-InstallJSON $script:install.Journal $transaction
        try {
            if ($wasRunning) { Stop-InstallProcesses }
            $null = New-Item -ItemType Directory -Path $profile -Force
            $profileLock = [IO.File]::Open((Join-Path $profile 'zaslon.lock'), [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            if ($hadInstall) { Move-InstallDirectory $target $backup }
            Move-InstallDirectory $stage $target
            if ($hadInstall -and (Test-Path -LiteralPath (Join-Path $profile 'config.yaml'))) {
                Copy-Item -LiteralPath (Join-Path $profile 'config.yaml') -Destination (Join-Path $backup 'profile-config-backup.yaml')
            }
            $profileLock.Dispose(); $profileLock = $null
            if (-not $defaults.NoStart) { Start-InstallRuntime $headlessMode }
            $transaction.committed = $true
            Write-InstallJSON $script:install.Journal $transaction
            Remove-Item -LiteralPath $script:install.Journal
        } catch {
            $originalError = $_
            if ($profileLock) { $profileLock.Dispose(); $profileLock = $null }
            try {
                $persisted = if (Test-Path -LiteralPath $script:install.Journal) { Read-SharedJSON $script:install.Journal } else { $transaction }
                Undo-Install $persisted
            }
            catch { throw "Installation failed; rollback also needs attention: $_. Recovery journal was not resumed or replaced. See $($script:install.Journal)" }
            throw $originalError
        }
        if (-not $defaults.NoShortcut) {
            try { Set-InstallShortcut } catch { Write-Warning "Installed, but the shortcut could not be saved: $_" }
        }
        if ($enableAutostart) {
            try { Invoke-Version (Join-Path $target 'zaslon.exe') 'autostart on' '' $profile }
            catch { Write-Warning "Installed, but autostart could not be enabled: $_" }
        }
        Write-Host "Zaslon $releaseVersion installed: $target"
        if ($hadInstall) { Write-Host "Previous files and a settings copy: $backup" }
    } finally {
        if ($profileLock) { $profileLock.Dispose() }
        $mutex.Dispose()
    }
}
# Dot sourcing imports functions for deterministic offline regression tests.
if ($MyInvocation.InvocationName -ne '.') { Invoke-ZaslonInstaller $PSBoundParameters }
