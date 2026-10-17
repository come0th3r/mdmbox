param(
    [Parameter(Mandatory = $true)][string]$QtRoot,
    [Parameter(Mandatory = $true)][string]$GuiPath,
    [Parameter(Mandatory = $true)][string]$CorePath,
    [Parameter(Mandatory = $true)][string]$MihomoPath,
    [Parameter(Mandatory = $true)][string]$GoExecutable,
    [Parameter(Mandatory = $true)][string[]]$GoModuleDirectories,
    [Parameter(Mandatory = $true)][string]$PinnedDependencyRoot,
    [Parameter(Mandatory = $true)][string]$MihomoLicensePath,
    [Parameter(Mandatory = $true)][string]$QtLicenseSourceRoot,
    [Parameter(Mandatory = $true)][string[]]$QtLicenseFiles,
    [Parameter(Mandatory = $true)][string]$QtWebEngineNoticeSourceRoot,
    [Parameter(Mandatory = $true)][string[]]$QtWebEngineNoticeFiles,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
    [Parameter(Mandatory = $true)][string]$QtVersion,
    [Parameter(Mandatory = $true)][hashtable]$DependencyRevisions
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$deploy = Join-Path $QtRoot 'bin/windeployqt.exe'
foreach ($file in @($GuiPath, $CorePath, $MihomoPath, $GoExecutable, $deploy)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing input: $file" }
}
foreach ($directory in @($GoModuleDirectories) + @($PinnedDependencyRoot) + @($QtLicenseSourceRoot, $QtWebEngineNoticeSourceRoot)) {
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw "Missing directory: $directory" }
}
foreach ($file in @($MihomoLicensePath) + @($QtLicenseFiles) + @($QtWebEngineNoticeFiles)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing licensing input: $file" }
}
if ($QtLicenseFiles.Count -eq 0 -or $QtWebEngineNoticeFiles.Count -eq 0) {
    throw 'Pass the Qt and Qt WebEngine notice file lists for this exact build'
}
$webEngineLicenseRoot = Join-Path $QtWebEngineNoticeSourceRoot 'LICENSES'
$chromiumLicense = Join-Path $QtWebEngineNoticeSourceRoot 'LICENSE.Chromium'
if (-not (Test-Path -LiteralPath $webEngineLicenseRoot -PathType Container) -or
    -not (Test-Path -LiteralPath $chromiumLicense -PathType Leaf)) {
    throw 'Qt WebEngine source root must contain LICENSE.Chromium and LICENSES/'
}
$expectedWebEngineNotices = @($chromiumLicense) + @(Get-ChildItem -LiteralPath $webEngineLicenseRoot -File -Recurse | ForEach-Object FullName)
$providedWebEngineNotices = @($QtWebEngineNoticeFiles | ForEach-Object { [IO.Path]::GetFullPath($_) })
foreach ($expectedNotice in $expectedWebEngineNotices) {
    if ($expectedNotice -notin $providedWebEngineNotices) { throw "Qt WebEngine notice list is incomplete: $expectedNotice" }
}
$name = 'mdmbox-technical-alpha-' + $SourceCommit.Substring(0, 8) + '-win64'
$stage = Join-Path $OutputDirectory $name
$zip = "$stage.zip"
# Never reuse a directory that could contain user profiles or stale DLLs.
if ((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $zip)) { throw 'Output already exists; choose a fresh output directory' }
New-Item -ItemType Directory -Path $stage -Force | Out-Null
Copy-Item -LiteralPath $GuiPath -Destination (Join-Path $stage 'mdmbox.exe')
Copy-Item -LiteralPath $CorePath -Destination (Join-Path $stage 'nekobox_core.exe')
Copy-Item -LiteralPath $MihomoPath -Destination (Join-Path $stage 'mihomo.exe')
Copy-Item -LiteralPath (Join-Path $repo 'LICENSE') -Destination $stage
Copy-Item -LiteralPath (Join-Path $repo 'docs/TECHNICAL_ALPHA.md') -Destination (Join-Path $stage 'README.md')
Copy-Item -LiteralPath (Join-Path $repo 'docs/THIRD_PARTY_NOTICES.md') -Destination (Join-Path $stage 'THIRD_PARTY_NOTICES.md')
$licenseDir = Join-Path $stage 'LICENSES'
New-Item -ItemType Directory -Path $licenseDir | Out-Null
Copy-Item -LiteralPath (Join-Path $repo 'LICENSE') -Destination (Join-Path $licenseDir 'GPL-3.0.txt')
$licenseSources = @(
    @{ Name = 'QHotkey-BSD-3-Clause.txt'; Path = (Join-Path $repo '3rdparty/QHotkey/LICENSE') },
    @{ Name = 'Inter-OFL-1.1.txt'; Path = (Join-Path $repo 'res/Inter/LICENSE.txt') },
    @{ Name = 'sing-box-LICENSE'; Path = (Join-Path $PinnedDependencyRoot 'sing-box/LICENSE') },
    @{ Name = 'sing-quic-LICENSE'; Path = (Join-Path $PinnedDependencyRoot 'sing-quic/LICENSE') },
    @{ Name = 'sing-LICENSE'; Path = (Join-Path $PinnedDependencyRoot 'sing/LICENSE') },
    @{ Name = 'mihomo-GPL-3.0.txt'; Path = $MihomoLicensePath }
)
foreach ($item in $licenseSources) {
    if (-not (Test-Path -LiteralPath $item.Path -PathType Leaf)) { throw "Required notice missing: $($item.Path)" }
    Copy-Item -LiteralPath $item.Path -Destination (Join-Path $licenseDir $item.Name)
}
foreach ($file in $QtLicenseFiles) {
    $fullFile = [IO.Path]::GetFullPath($file)
    $rootPath = [IO.Path]::GetFullPath($QtLicenseSourceRoot).TrimEnd('\') + '\'
    if (-not $fullFile.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)) { throw "Qt notice is outside source root: $file" }
    $relative = $fullFile.Substring($rootPath.Length)
    $destination = Join-Path $licenseDir (Join-Path 'Qt' $relative)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $fullFile -Destination $destination
}
$webEngineLicenseDir = Join-Path $licenseDir 'QtWebEngine-Chromium'
New-Item -ItemType Directory -Path $webEngineLicenseDir | Out-Null
foreach ($file in $QtWebEngineNoticeFiles) {
    $fullFile = [IO.Path]::GetFullPath($file)
    $rootPath = [IO.Path]::GetFullPath($QtWebEngineNoticeSourceRoot).TrimEnd('\') + '\'
    if (-not $fullFile.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase)) { throw "Qt WebEngine notice is outside source root: $file" }
    $relative = $fullFile.Substring($rootPath.Length)
    $destination = Join-Path $webEngineLicenseDir $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    Copy-Item -LiteralPath $fullFile -Destination $destination
}
$goLicenseDir = Join-Path $licenseDir 'go-modules'
New-Item -ItemType Directory -Path $goLicenseDir | Out-Null
$inventory = @{}
foreach ($moduleDirectory in $GoModuleDirectories) {
    $oldLocation = Get-Location
    try {
        Set-Location -LiteralPath $moduleDirectory
        $moduleLines = @(& $GoExecutable list -mod=readonly -deps -f '{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}' .)
        if ($LASTEXITCODE -ne 0) { throw "go list failed in $moduleDirectory while collecting dependency notices" }
    } finally { Set-Location $oldLocation }
    foreach ($line in $moduleLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = [regex]::Split($line, '\|', 3)
        if ($parts.Count -ne 3) { throw "Unexpected go list module row: $line" }
        $modulePath, $version, $moduleDir = $parts
        $key = "$modulePath@$version"
        if ($inventory.ContainsKey($key)) { continue }
        $licenseFiles = @(Get-ChildItem -LiteralPath $moduleDir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|NOTICE)(\.|$)' })
        if ($licenseFiles.Count -eq 0) {
            $inventory[$key] = [pscustomobject]@{ module = $modulePath; version = $version; status = 'NO_ROOT_LICENSE_FOUND'; files = '' }
            continue
        }
        $safeName = [Uri]::EscapeDataString("$modulePath@$version")
        $copied = @()
        foreach ($license in $licenseFiles) {
            $destinationName = "$safeName-$($license.Name)"
            Copy-Item -LiteralPath $license.FullName -Destination (Join-Path $goLicenseDir $destinationName)
            $copied += $destinationName
        }
        $inventory[$key] = [pscustomobject]@{ module = $modulePath; version = $version; status = 'ROOT_LICENSE_COPIED'; files = ($copied -join ';') }
    }
}
$inventory.Values | Sort-Object module, version | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath (Join-Path $licenseDir 'go-module-license-inventory.csv')
# Deploy Qt and the compiler runtime using the toolchain's official deployment rules.
& $deploy --release --compiler-runtime (Join-Path $stage 'mdmbox.exe')
if ($LASTEXITCODE) { throw 'windeployqt failed' }
foreach ($file in @('Qt6Core.dll', 'Qt6Widgets.dll', 'Qt6WebEngineCore.dll', 'QtWebEngineProcess.exe',
                    'platforms/qwindows.dll', 'resources/icudtl.dat', 'resources/qtwebengine_resources.pak',
                    'translations/qtwebengine_locales/en-US.pak')) {
    if (-not (Test-Path -LiteralPath (Join-Path $stage $file))) { throw "Deployment incomplete: $file" }
}
# Launch with a dedicated data directory, never the user's existing config.
@'
@echo off
cd /d "%~dp0"
start "" "%~dp0mdmbox.exe" -many -appdata "%~dp0alpha-data"
'@ | Set-Content -LiteralPath (Join-Path $stage 'Start Alpha.cmd') -Encoding ASCII
$files = @(Get-ChildItem -LiteralPath $stage -Recurse -File | ForEach-Object {
    [ordered]@{ path = $_.FullName.Substring($stage.Length + 1).Replace('\', '/');
        bytes = $_.Length; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
})
[ordered]@{ schemaVersion = 1; channel = 'technical-alpha-candidate'; sourceCommit = $SourceCommit;
    qtVersion = $QtVersion; dependencyRevisions = $DependencyRevisions;
    createdUtc = [DateTime]::UtcNow.ToString('o'); files = $files;
    cleanVm = 'NOT RUN'; licenseAudit = 'INCOMPLETE: see THIRD_PARTY_NOTICES.md and LICENSES/go-module-license-inventory.csv';
    publicDistribution = 'BLOCKED: licensing and source-offer audit pending' } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding UTF8
Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $name.zip" | Set-Content -LiteralPath "$zip.sha256" -Encoding ASCII
Get-Item -LiteralPath $zip | Select-Object FullName, Length
