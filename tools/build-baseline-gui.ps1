param(
    [Parameter(Mandatory = $true)][string]$QtRoot,
    [Parameter(Mandatory = $true)][string]$DependencyRoot,
    [Parameter(Mandatory = $true)][string]$BuildDirectory,
    [string]$VsDevCmd = "",
    [ValidateRange(1, 64)][int]$Parallel = 4
)

# Uses prepared SDKs only. Never downloads, removes build trees, stops processes,
# changes Go manifests or edits third-party CMake files.
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$QtRoot = (Resolve-Path -LiteralPath $QtRoot).Path
$DependencyRoot = (Resolve-Path -LiteralPath $DependencyRoot).Path
$BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
if ($BuildDirectory.TrimEnd('\', '/') -eq $repoRoot.TrimEnd('\', '/')) {
    throw "An out-of-source BuildDirectory is required."
}
if (-not $VsDevCmd) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere)) { throw "Supply -VsDevCmd or install Build Tools."
    }
    $vsRoot = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vsRoot) { throw "No MSVC C++ installation found." }
    $VsDevCmd = Join-Path $vsRoot "Common7\Tools\VsDevCmd.bat"
}
if (-not (Test-Path -LiteralPath $VsDevCmd)) { throw "VsDevCmd not found." }
foreach ($package in @("Qt6", "Qt6WebEngineWidgets", "Qt6WebChannel")) {
    if (-not (Test-Path (Join-Path $QtRoot "lib\cmake\$package\${package}Config.cmake"))) {
        throw "Missing Qt package: $package"
    }
}
$protobufDir = Join-Path $DependencyRoot "cmake"
if (-not (Test-Path (Join-Path $protobufDir "protobuf-config.cmake"))) {
    throw "Expected Protobuf 21.4 CMake package under DependencyRoot/cmake."
}

$originalEnvironment = @{}
# VsDevCmd defines more variables than the common compiler set; snapshot all of
# them so callers running this script in-process retain their original environment.
Get-ChildItem Env: | ForEach-Object { $originalEnvironment[$_.Name] = $_.Value }
try {
    $lines = & cmd.exe /d /s /c "`"$VsDevCmd`" -arch=amd64 -host_arch=amd64 >nul && set"
    if ($LASTEXITCODE -ne 0) { throw "Developer environment failed." }
    foreach ($line in $lines) {
        $index = $line.IndexOf('=')
        if ($index -gt 0) {
            [Environment]::SetEnvironmentVariable($line.Substring(0, $index), $line.Substring($index + 1), "Process")
        }
    }
    $env:PATH = "$QtRoot\bin;$DependencyRoot\bin;" + $env:PATH
    foreach ($tool in @("cmake.exe", "ninja.exe", "cl.exe")) {
        if (-not (Get-Command $tool -CommandType Application -ErrorAction SilentlyContinue)) { throw "Missing tool: $tool" }
    }
    $configureArgs = @(
        '-S', $repoRoot, '-B', $BuildDirectory, '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE=Release', '-DQT_VERSION_MAJOR=6',
        "-DCMAKE_PREFIX_PATH=$QtRoot;$DependencyRoot", "-DProtobuf_DIR=$protobufDir",
        '-DCMAKE_POLICY_VERSION_MINIMUM:STRING=3.5'
    )
    & cmake.exe @configureArgs
    if ($LASTEXITCODE -ne 0) { throw "GUI configuration failed." }
    & cmake.exe --build $BuildDirectory --parallel $Parallel
    if ($LASTEXITCODE -ne 0) { throw "GUI build failed." }
    $exe = Join-Path $BuildDirectory "mdmbox.exe"
    if (-not (Test-Path -LiteralPath $exe)) { throw "Expected GUI artifact missing." }
    [pscustomobject]@{
        status = "GUI_BUILD_PASS"
        artifact = $exe
        sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        runtime = "NOT_RUN"
        coreBuild = "NOT_RUN"
    } | ConvertTo-Json
} finally {
    Get-ChildItem Env: | Where-Object { -not $originalEnvironment.ContainsKey($_.Name) } | ForEach-Object {
        [Environment]::SetEnvironmentVariable($_.Name, $null, "Process")
    }
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], "Process")
    }
}
