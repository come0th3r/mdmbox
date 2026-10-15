param(
    [Parameter(Mandatory = $true)][string]$QtRoot,
    [Parameter(Mandatory = $true)][string]$GuiPath,
    [Parameter(Mandatory = $true)][string]$CorePath,
    [Parameter(Mandatory = $true)][string]$MihomoPath,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$deploy = Join-Path $QtRoot 'bin/windeployqt.exe'
foreach ($file in @($GuiPath, $CorePath, $MihomoPath, $deploy)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing input: $file" }
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
    createdUtc = [DateTime]::UtcNow.ToString('o'); files = $files;
    cleanVm = 'NOT RUN'; publicDistribution = 'BLOCKED: dependency notices/source offers audit pending' } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stage 'manifest.json') -Encoding UTF8
Compress-Archive -Path $stage -DestinationPath $zip -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $name.zip" | Set-Content -LiteralPath "$zip.sha256" -Encoding ASCII
Get-Item -LiteralPath $zip | Select-Object FullName, Length
