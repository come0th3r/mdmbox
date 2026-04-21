param(
    [string]$QtRoot = "C:\Qt\6.5.3\msvc2019_64",
    [string]$VsDevCmd = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $VsDevCmd)) {
    throw "VsDevCmd.bat not found: $VsDevCmd"
}

if (-not (Test-Path $QtRoot)) {
    throw "Qt root not found: $QtRoot"
}

$cmd = "`"$VsDevCmd`" -arch=$Arch -host_arch=$Arch >nul && set"
$envLines = & cmd.exe /d /s /c $cmd

foreach ($line in $envLines) {
    $idx = $line.IndexOf("=")
    if ($idx -le 0) { continue }
    $name = $line.Substring(0, $idx)
    $value = $line.Substring($idx + 1)
    [Environment]::SetEnvironmentVariable($name, $value, "Process")
}

$prepend = @(
    "$QtRoot\bin",
    "C:\Program Files\Go\bin",
    "C:\Program Files\CMake\bin",
    "C:\Users\0th3r\AppData\Local\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe",
    "C:\Users\0th3r\AppData\Local\Programs\Python\Python312",
    "C:\Users\0th3r\AppData\Local\Programs\Python\Python312\Scripts"
)

$env:Path = (($prepend + ($env:Path -split ";")) | Select-Object -Unique) -join ";"
$env:CMAKE_PREFIX_PATH = $QtRoot
$env:Qt6_DIR = "$QtRoot\lib\cmake\Qt6"

Write-Host "Build environment loaded."
Write-Host "QtRoot=$QtRoot"
Write-Host "Qt6_DIR=$env:Qt6_DIR"
Write-Host "cl=$(Get-Command cl.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)"
Write-Host "cmake=$(Get-Command cmake.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)"
Write-Host "ninja=$(Get-Command ninja.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)"
