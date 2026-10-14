param(
    [string]$QtRoot = $env:MDMBOX_QT_ROOT,
    [string]$DependencyRoot = "",
    [string]$SourcesRoot = ""
)

# Read-only preflight: no downloads, installs, process termination or manifest changes.
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $DependencyRoot) { $DependencyRoot = Join-Path $repoRoot "libs\deps\built" }
if (-not $SourcesRoot) { $SourcesRoot = Split-Path -Parent $repoRoot }
$checks = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param([string]$Name, [bool]$Available, [string]$Detail)
    $checks.Add([pscustomobject]@{ name = $Name; status = $(if ($Available) { "PASS" } else { "BLOCKED" }); detail = $Detail })
}

function Find-Executable {
    param([string]$Name, [string[]]$Candidates)
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate }
    }
    return $null
}

$cmake = Find-Executable "cmake.exe" @("$env:ProgramFiles\CMake\bin\cmake.exe")
$go = Find-Executable "go.exe" @("$env:ProgramFiles\Go\bin\go.exe")
$node = Find-Executable "node.exe" @("$env:ProgramFiles\nodejs\node.exe")
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsRoot = $null
if (Test-Path -LiteralPath $vswhere) {
    $vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0) { $vsRoot = $null }
}
$devCmd = if ($vsRoot) { Join-Path $vsRoot "Common7\Tools\VsDevCmd.bat" } else { "" }
if (-not $cmake -and $vsRoot) {
    $cmake = Find-Executable "cmake.exe" @((Join-Path $vsRoot "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"))
}
$ninjaCandidates = @()
if ($vsRoot) { $ninjaCandidates += Join-Path $vsRoot "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" }
$ninja = Find-Executable "ninja.exe" $ninjaCandidates

Add-Check "MSVC developer environment" ([bool]($devCmd -and (Test-Path -LiteralPath $devCmd))) $(if ($devCmd) { $devCmd } else { "Install MSVC C++ Build Tools and Windows SDK; no matching vswhere installation found." })
foreach ($tool in @(@("CMake", $cmake), @("Ninja", $ninja), @("Go", $go), @("Node.js (diagnostics)", $node))) {
    Add-Check $tool[0] ([bool]$tool[1]) $(if ($tool[1]) { $tool[1] } else { "Not found in PATH or supported installation locations." })
}

if (-not $QtRoot) {
    $qtCandidates = @((Join-Path $repoRoot "qtsdk\Qt"))
    if (Test-Path "C:\Qt") {
        $qtCandidates += @(Get-ChildItem "C:\Qt" -Directory | ForEach-Object {
            Get-ChildItem $_.FullName -Directory -Filter "msvc*" | Select-Object -ExpandProperty FullName
        })
    }
    $QtRoot = $qtCandidates | Where-Object { Test-Path (Join-Path $_ "lib\cmake\Qt6\Qt6Config.cmake") } | Select-Object -First 1
}
foreach ($module in @("Qt6", "Qt6Widgets", "Qt6Network", "Qt6Svg", "Qt6LinguistTools", "Qt6WebEngineWidgets", "Qt6WebChannel")) {
    $path = if ($QtRoot) { Join-Path $QtRoot "lib\cmake\$module\${module}Config.cmake" } else { "" }
    Add-Check $module ([bool]($path -and (Test-Path -LiteralPath $path))) $(if ($path) { $path } else { "Supply -QtRoot or MDMBOX_QT_ROOT pointing to a prebuilt Qt 6 MSVC SDK." })
}

foreach ($dependency in @("yaml-cpp", "ZXing", "protobuf")) {
    $match = $null
    if (Test-Path -LiteralPath $DependencyRoot) {
        $match = Get-ChildItem -LiteralPath $DependencyRoot -Recurse -File -Filter "*config.cmake" |
            Where-Object { $_.Name -match [regex]::Escape($dependency) } | Select-Object -First 1
    }
    Add-Check "C++ dependency: $dependency" ([bool]$match) $(if ($match) { $match.FullName } else { "Missing CMake package under DependencyRoot; configure a verified prebuilt dependency bundle." })
}
Add-Check "QHotkey submodule" (Test-Path (Join-Path $repoRoot "3rdparty\QHotkey\CMakeLists.txt")) "Requires initialized 3rdparty/QHotkey submodule."

foreach ($source in @("libneko", "sing-box", "sing-quic", "sing")) {
    $path = Join-Path $SourcesRoot "$source\go.mod"
    Add-Check "Go local replacement: $source" (Test-Path -LiteralPath $path) $path
}

$blocked = @($checks | Where-Object { $_.status -eq "BLOCKED" }).Count
[pscustomobject]@{ status = $(if ($blocked) { "BLOCKED" } else { "READY_FOR_BUILD_ATTEMPT" });
    scope = "Presence checks only; compilation and runtime tests have not been run.";
    blockedCount = $blocked; checks = $checks } | ConvertTo-Json -Depth 5
if ($blocked) { exit 1 }
