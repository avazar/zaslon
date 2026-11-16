# Build and test only. Never launches the guard, installs it, or changes networking.
[CmdletBinding()]
param(
    [ValidateSet('Check', 'Build')][string]$Task = 'Check',
    [string]$GoExe,
    [string]$ModuleCache,
    [string]$Version
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = Split-Path $PSScriptRoot -Parent
$saved = @{}
$resourceBackups = @{}
$vars = @('GOTOOLCHAIN', 'GOENV', 'GOWORK', 'GOFLAGS', 'GOPATH', 'GOMODCACHE', 'GOCACHE', 'GOBIN', 'CGO_ENABLED', 'GOOS', 'GOARCH', 'ZASLON_DIR')
foreach ($name in $vars) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
function Invoke-Go {
    & $script:goPath @args
    if ($LASTEXITCODE -ne 0) { throw "go $($args -join ' ') failed (exit $LASTEXITCODE)" }
}
function Add-WindowsResources {
    param([string]$Package, [string]$FileName, [string]$Description, [string]$Manifest)
    $resourcePath = Join-Path $repo "$Package/rsrc_windows_$($env:GOARCH).syso"
    $resourceBackups[$resourcePath] = if (Test-Path -LiteralPath $resourcePath) { [IO.File]::ReadAllBytes($resourcePath) } else { $null }
    & $script:winresExe simply `
        --arch $env:GOARCH --out (Join-Path $repo "$Package/rsrc") `
        --icon (Join-Path $repo 'build/icons/zaslon.ico') --manifest $Manifest `
        --product-name Zaslon --file-description $Description `
        --copyright 'ef1m03, Efimov Dev, MIT' --original-filename $FileName `
        --product-version $script:resourceVersion --file-version $script:resourceVersion
    if ($LASTEXITCODE -ne 0) { throw "Windows resources for $FileName failed (exit $LASTEXITCODE)" }
}
Push-Location $repo
try {
    if (-not $Version) { $Version = (Get-Content -LiteralPath (Join-Path $repo 'VERSION') -Raw).Trim() }
    if ($Version.StartsWith('v')) { $Version = $Version.Substring(1) }
    if ($Version -cne 'dev' -and $Version -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'Version must be major.minor.patch or dev.' }
    $script:resourceVersion = if ($Version -ceq 'dev') { '0.0.0' } else { $Version }
    foreach ($part in $script:resourceVersion.Split('.')) { if ([uint32]$part -gt 65535) { throw 'Windows version components must not exceed 65535.' } }
    if (-not $GoExe) {
        $installed = Get-Command go -ErrorAction SilentlyContinue
        if ($installed) { $GoExe = $installed.Source }
        elseif (Test-Path 'build/tools/go/bin/go.exe') { $GoExe = 'build/tools/go/bin/go.exe' }
        elseif (Test-Path 'build/audit/go/bin/go.exe') { $GoExe = 'build/audit/go/bin/go.exe' }
        else { throw 'Install the Go version in go.mod or pass -GoExe <path-to-go.exe>.' }
    }
    $script:goPath = (Resolve-Path -LiteralPath $GoExe).Path
    $required = [regex]::Match((Get-Content go.mod -Raw), '(?m)^go (\S+)').Groups[1].Value
    $env:GOTOOLCHAIN = 'local'
    $env:GOENV = 'off'
    $env:GOWORK = 'off'
    $actual = & $script:goPath env GOVERSION
    if ($LASTEXITCODE -ne 0 -or $actual -ne "go$required") { throw "Expected Go $required; found $actual." }
    $env:GOFLAGS = '-mod=readonly'
    $env:GOPATH = Join-Path $repo 'build/gopath'
    $env:GOCACHE = Join-Path $repo 'build/gocache'
    $env:GOMODCACHE = if ($ModuleCache) { [IO.Path]::GetFullPath($ModuleCache) } else { Join-Path $env:GOPATH 'pkg/mod' }
    $env:ZASLON_DIR = Join-Path $repo 'build/dev/zaslon-profile'
    $env:CGO_ENABLED = '0'
    $env:GOOS = 'windows'
    $env:GOARCH = & $script:goPath env GOHOSTARCH
    if ($LASTEXITCODE -ne 0) { throw 'Cannot determine host architecture.' }
    New-Item -ItemType Directory -Force 'build/dev' | Out-Null
    Invoke-Go version
    if ($Task -eq 'Check') {
        $env:GOBIN = Join-Path $repo "build/tools/actionlint-v1.7.12-$($env:GOARCH)"
        $workflowLinter = Join-Path $env:GOBIN 'actionlint.exe'
        if (-not (Test-Path -LiteralPath $workflowLinter)) {
            Invoke-Go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
        }
        & $workflowLinter -no-color -shellcheck= -pyflakes= .github/workflows/ci.yml
        if ($LASTEXITCODE -ne 0) { throw 'GitHub Actions workflow validation failed.' }
        & $workflowLinter -no-color -shellcheck= -pyflakes= .github/workflows/release.yml
        if ($LASTEXITCODE -ne 0) { throw 'Release workflow validation failed.' }
        Invoke-Go vet ./...
        Invoke-Go test -count=1 -timeout=120s ./...
    }
    $env:GOBIN = Join-Path $repo "build/tools/go-winres-v0.3.3-$($env:GOARCH)"
    $script:winresExe = Join-Path $env:GOBIN 'go-winres.exe'
    if (-not (Test-Path -LiteralPath $script:winresExe)) {
        Invoke-Go install github.com/tc-hib/go-winres@v0.3.3
    }
    Invoke-Go run ./tools/mkicons build/icons
    Add-WindowsResources -Package 'cmd/zaslon' -FileName 'zaslon.exe' -Description 'Zaslon - application network protection' -Manifest gui
    Add-WindowsResources -Package 'cmd/zaslon-recover' -FileName 'zaslon-recover.exe' -Description 'Zaslon - process recovery' -Manifest cli
    Invoke-Go build -trimpath -ldflags "-H windowsgui -X main.version=$Version" -o build/dev/zaslon.exe ./cmd/zaslon
    Invoke-Go build -trimpath -ldflags "-X main.version=$Version" -o build/dev/zaslon-recover.exe ./cmd/zaslon-recover
    & .\build\dev\zaslon.exe version
    if ($LASTEXITCODE -ne 0) { throw 'Version smoke check failed.' }
    & .\build\dev\zaslon-recover.exe -version
    if ($LASTEXITCODE -ne 0) { throw 'Recovery version smoke check failed.' }
    Write-Host "Built Zaslon $Version`: build/dev/zaslon.exe and build/dev/zaslon-recover.exe. Protection was not started."
}
finally {
    try {
        foreach ($resourcePath in $resourceBackups.Keys) {
            if ($null -eq $resourceBackups[$resourcePath]) {
                if (Test-Path -LiteralPath $resourcePath) { Remove-Item -LiteralPath $resourcePath -Force }
            } else {
                [IO.File]::WriteAllBytes($resourcePath, $resourceBackups[$resourcePath])
            }
        }
    } finally {
        foreach ($name in $vars) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
        Pop-Location
    }
}
