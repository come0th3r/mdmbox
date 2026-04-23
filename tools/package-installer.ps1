param(
    [string]$QtRoot = "C:\Qt\6.5.3\msvc2019_64",
    [string]$BuildDir = "",
    [string]$Version = "0.1.0"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Invoke-NativeChecked {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $FilePath $($Arguments -join ' ')"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $repoRoot "build"
}

$stageDir = Join-Path $repoRoot "dist\mdmbox-stage"
$outputDir = Join-Path $repoRoot "dist"
$iconPath = Join-Path $repoRoot "res\nekobox.ico"
$windeployqt = Join-Path $QtRoot "bin\windeployqt.exe"
$isccCandidates = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
$exePath = Join-Path $BuildDir "mdmbox.exe"
$corePath = Join-Path $BuildDir "nekobox_core.exe"
$xrayPath = Join-Path $BuildDir "xray.exe"

if (-not (Test-Path $exePath)) {
    throw "GUI binary not found: $exePath"
}
if (-not (Test-Path $corePath)) {
    throw "Core binary not found: $corePath"
}
if (-not (Test-Path $windeployqt)) {
    throw "windeployqt not found: $windeployqt"
}
if (-not ($isccCandidates | Where-Object { Test-Path $_ })) {
    $foundIscc = Get-ChildItem "$env:LOCALAPPDATA\Programs", "${env:ProgramFiles(x86)}", "${env:ProgramFiles}" -Recurse -Filter ISCC.exe -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if ($foundIscc) {
        $iscc = $foundIscc
    }
}
else {
    $iscc = ($isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1)
}

if (-not $iscc -or -not (Test-Path $iscc)) {
    throw "ISCC.exe not found: $iscc"
}

Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stageDir | Out-Null
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

Copy-Item $exePath $stageDir -Force
Copy-Item $corePath $stageDir -Force
if (Test-Path $xrayPath) {
    Copy-Item $xrayPath $stageDir -Force
}

foreach ($file in @("geoip.db", "geosite.db", "geoip.dat", "geosite.dat", "fa_IR.qm", "ru_RU.qm", "zh_CN.qm")) {
    $src = Join-Path $BuildDir $file
    if (Test-Path $src) {
        Copy-Item $src $stageDir -Force
    }
}

if (Test-Path $iconPath) {
    Copy-Item $iconPath (Join-Path $stageDir "mdmbox.ico") -Force
}

Invoke-NativeChecked $windeployqt @(
    "--release",
    "--compiler-runtime",
    "--no-system-d3d-compiler",
    "--no-opengl-sw",
    (Join-Path $stageDir "mdmbox.exe")
)

Invoke-NativeChecked $iscc @(
    "/Qp",
    "/DMyAppVersion=$Version",
    "/DSourceDir=$stageDir",
    "/DOutputDir=$outputDir",
    "/DRepoRoot=$repoRoot",
    (Join-Path $repoRoot "installer\mdmbox.iss")
)

Get-ChildItem $outputDir -Filter "mdmbox-setup-*.exe" | Select-Object FullName, Length, LastWriteTime
