param(
    [string]$QtRoot = "C:\Qt\6.5.3\msvc2019_64",
    [string]$VsDevCmd = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat",
    [string]$GoProxy = "direct",
    [string]$SmuxModule = "github.com/xtaci/smux",
    [string]$SmuxVersion = "v1.5.34",
    [string]$CoreTags = "with_clash_api,with_quic,with_utls,with_ech",
    [switch]$RebuildProtobuf,
    [switch]$SkipCore
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "==> $Name"
    & $Action
}

function Import-VsEnvironment {
    if (-not (Test-Path $VsDevCmd)) {
        throw "VsDevCmd.bat not found: $VsDevCmd"
    }

    $cmd = "`"$VsDevCmd`" -arch=amd64 -host_arch=amd64 >nul && set"
    $envLines = & cmd.exe /d /s /c $cmd
    foreach ($line in $envLines) {
        $idx = $line.IndexOf("=")
        if ($idx -le 0) { continue }
        [Environment]::SetEnvironmentVariable(
            $line.Substring(0, $idx),
            $line.Substring($idx + 1),
            "Process"
        )
    }
}

function Prepend-Path {
    param([string[]]$Entries)

    $env:Path = (($Entries + ($env:Path -split ";")) | Select-Object -Unique) -join ";"
}

function Assert-Command {
    param([string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "Command not found: $Name"
    }
    return $cmd.Source
}

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

function Invoke-WebDownload {
    param(
        [string]$Url,
        [string]$OutFile
    )

    try {
        Invoke-NativeChecked "powershell.exe" @(
            "-NoProfile",
            "-Command",
            "Invoke-WebRequest -Uri '$Url' -OutFile '$OutFile'"
        )
        return
    } catch {
        Write-Warning "Invoke-WebRequest failed for $Url, retrying with curl.exe"
    }

    Invoke-NativeChecked "curl.exe" @(
        "-L",
        "--fail",
        $Url,
        "-o",
        $OutFile
    )
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$buildExe = Join-Path $repoRoot "build\mdmbox.exe"
$buildCoreExe = Join-Path $repoRoot "build\nekobox_core.exe"
Get-CimInstance Win32_Process -Filter "name = 'mdmbox.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -eq $buildExe } |
    ForEach-Object {
        try {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to stop build mdmbox.exe (PID $($_.ProcessId)): $($_.Exception.Message)"
        }
    }
Get-CimInstance Win32_Process -Filter "name = 'nekobox_core.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.ExecutablePath -eq $buildCoreExe } |
    ForEach-Object {
        try {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
        } catch {
            Write-Warning "Failed to stop build nekobox_core.exe (PID $($_.ProcessId)): $($_.Exception.Message)"
        }
    }

Import-VsEnvironment
Prepend-Path @(
    "$QtRoot\bin",
    "C:\Program Files\Go\bin",
    "C:\Program Files\CMake\bin",
    "C:\Users\0th3r\AppData\Local\Microsoft\WinGet\Packages\Ninja-build.Ninja_Microsoft.Winget.Source_8wekyb3d8bbwe",
    "C:\Users\0th3r\AppData\Local\Programs\Python\Python312",
    "C:\Users\0th3r\AppData\Local\Programs\Python\Python312\Scripts"
)

$cmake = Assert-Command "cmake.exe"
$ninja = Assert-Command "ninja.exe"
$cl = Assert-Command "cl.exe"
$go = Get-Command "go.exe" -ErrorAction SilentlyContinue

Write-Host "cl=$cl"
Write-Host "cmake=$cmake"
Write-Host "ninja=$ninja"
if ($go) {
    Write-Host "go=$($go.Source)"
}

$depsRoot = Join-Path $repoRoot "libs\deps\built"
$protobufSrc = Join-Path $repoRoot "libs\deps\src\protobuf-21.4"
$protobufBuild = Join-Path $protobufSrc "build-codex-final"
$buildDir = Join-Path $repoRoot "build"

Invoke-Step "Configure GUI" {
    Remove-Item -Recurse -Force $buildDir -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

    $prefix = @(
        $QtRoot,
        $depsRoot,
        (Join-Path $depsRoot "share\cmake\yaml-cpp"),
        (Join-Path $depsRoot "lib\cmake\ZXing"),
        (Join-Path $depsRoot "cmake")
    ) -join ";"

    Invoke-NativeChecked $cmake @(
        "-S", $repoRoot,
        "-B", $buildDir,
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DQT_VERSION_MAJOR=6",
        "-DCMAKE_PREFIX_PATH=$prefix",
        "-DProtobuf_DIR=$(Join-Path $depsRoot 'cmake')"
    )
}

if ($RebuildProtobuf) {
    Invoke-Step "Rebuild protobuf" {
        if (-not (Test-Path $protobufSrc)) {
            throw "protobuf source tree not found: $protobufSrc"
        }

        Remove-Item -Recurse -Force $protobufBuild -ErrorAction SilentlyContinue
        Invoke-NativeChecked $cmake @(
            "-S", $protobufSrc,
            "-B", $protobufBuild,
            "-G", "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DCMAKE_INSTALL_PREFIX=$depsRoot",
            "-DBUILD_SHARED_LIBS=OFF",
            "-Dprotobuf_BUILD_TESTS=OFF",
            "-Dprotobuf_WITH_ZLIB=OFF"
        )
        Invoke-NativeChecked $ninja @("-C", $protobufBuild)
        Invoke-NativeChecked $ninja @("-C", $protobufBuild, "install")
    }
}

Invoke-Step "Build GUI" {
    Invoke-NativeChecked $ninja @("-C", $buildDir)
}

Invoke-Step "Show GUI binary" {
    Get-Item (Join-Path $buildDir "mdmbox.exe") | Select-Object FullName, Length, LastWriteTime
}

Invoke-Step "Fetch geo assets" {
    try {
        Invoke-WebDownload -Url "https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db" -OutFile (Join-Path $buildDir "geoip.db")
        Invoke-WebDownload -Url "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db" -OutFile (Join-Path $buildDir "geosite.db")
        Get-Item (Join-Path $buildDir "geoip.db"), (Join-Path $buildDir "geosite.db") | Select-Object FullName, Length, LastWriteTime
    } catch {
        Write-Warning "Geo assets download skipped: $($_.Exception.Message)"
    }
}

Invoke-Step "Fetch xray-core" {
    try {
        $xrayZip = Join-Path $buildDir "xray.zip"
        $xrayExtract = Join-Path $buildDir "xray_extract"

        Remove-Item -Force $xrayZip -ErrorAction SilentlyContinue
        Remove-Item -Recurse -Force $xrayExtract -ErrorAction SilentlyContinue

        Invoke-WebDownload -Url "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-windows-64.zip" -OutFile $xrayZip
        Expand-Archive -Path $xrayZip -DestinationPath $xrayExtract -Force

        $xrayExe = Get-ChildItem -Path $xrayExtract -Recurse -File -Filter "xray.exe" | Select-Object -First 1
        if (-not $xrayExe) {
            throw "xray.exe not found in downloaded archive"
        }

        Copy-Item -Force $xrayExe.FullName (Join-Path $buildDir "xray.exe")
        Get-Item (Join-Path $buildDir "xray.exe") | Select-Object FullName, Length, LastWriteTime
    } catch {
        Write-Warning "xray-core download skipped: $($_.Exception.Message)"
    }
}

Invoke-Step "Fetch xray geo assets" {
    try {
        Invoke-WebDownload -Url "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" -OutFile (Join-Path $buildDir "geosite.dat")
        Invoke-WebDownload -Url "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" -OutFile (Join-Path $buildDir "geoip.dat")
        Get-Item (Join-Path $buildDir "geosite.dat"), (Join-Path $buildDir "geoip.dat") | Select-Object FullName, Length, LastWriteTime
    } catch {
        Write-Warning "xray geo assets download skipped: $($_.Exception.Message)"
    }
}

if (-not $SkipCore) {
    if (-not $go) {
        throw "go.exe not found. Use -SkipCore or install Go."
    }

    Invoke-Step "Build nekobox_core" {
        $coreDir = Join-Path $repoRoot "go\cmd\nekobox_core"
        Push-Location $coreDir
        try {
            $env:GOPROXY = $GoProxy
            $env:GOSUMDB = "off"
            $env:GONOSUMDB = "*"
            $env:GOINSECURE = "*"

            # Upstream pseudo-version pinned in this tree may be unavailable via proxy/direct fetch.
            if ($SmuxVersion) {
                Invoke-NativeChecked $go.Source @(
                    "mod", "edit",
                    "-replace=github.com/sagernet/smux=$SmuxModule@$SmuxVersion"
                )
                Invoke-NativeChecked $go.Source @(
                    "mod", "download",
                    "$SmuxModule@$SmuxVersion"
                )
            }

            Push-Location (Join-Path $repoRoot "..\sing-box")
            try {
                Invoke-NativeChecked $go.Source @(
                    "mod", "edit",
                    "-droprequire=github.com/sagernet/gvisor"
                )
                Invoke-NativeChecked $go.Source @(
                    "mod", "edit",
                    "-droprequire=github.com/sagernet/wireguard-go"
                )
                Invoke-NativeChecked $go.Source @(
                    "mod", "edit",
                    "-droprequire=golang.zx2c4.com/wireguard/wgctrl"
                )
            }
            finally {
                Pop-Location
            }

            Invoke-NativeChecked $go.Source @(
                "mod", "edit",
                "-droprequire=github.com/sagernet/gvisor"
            )
            Invoke-NativeChecked $go.Source @(
                "mod", "edit",
                "-droprequire=github.com/sagernet/wireguard-go"
            )
            Invoke-NativeChecked $go.Source @(
                "mod", "edit",
                "-droprequire=golang.zx2c4.com/wireguard/wgctrl"
            )
            Invoke-NativeChecked $go.Source @(
                "mod", "edit",
                "-droprequire=github.com/sagernet/sing"
            )
            Invoke-NativeChecked $go.Source @(
                "mod", "edit",
                "-droprequire=github.com/sagernet/sing-dns"
            )
            Invoke-NativeChecked $go.Source @(
                "mod", "edit",
                "-replace=github.com/sagernet/sing=../../../../sing"
            )
            Invoke-NativeChecked $go.Source @(
                "mod", "edit",
                "-replace=github.com/sagernet/sing-dns=github.com/sagernet/sing-dns@v0.2.3"
            )

            Invoke-NativeChecked $go.Source @(
                "build",
                "-mod=mod",
                "-v",
                "-o", "nekobox_core.exe",
                "-trimpath",
                "-ldflags", "-w -s",
                "-tags", $CoreTags
            )

            Get-Item (Join-Path $coreDir "nekobox_core.exe") | Select-Object FullName, Length, LastWriteTime
            Copy-Item -Force (Join-Path $coreDir "nekobox_core.exe") (Join-Path $buildDir "nekobox_core.exe")
            Get-Item (Join-Path $buildDir "nekobox_core.exe") | Select-Object FullName, Length, LastWriteTime
        }
        finally {
            Pop-Location
        }
    }
} else {
    Invoke-Step "Copy existing nekobox_core" {
        $existingCore = Join-Path $repoRoot "go\cmd\nekobox_core\nekobox_core.exe"
        if (-not (Test-Path $existingCore)) {
            Write-Warning "nekobox_core.exe not found at $existingCore"
        } else {
            Copy-Item -Force $existingCore (Join-Path $buildDir "nekobox_core.exe")
            Get-Item (Join-Path $buildDir "nekobox_core.exe") | Select-Object FullName, Length, LastWriteTime
        }
    }
}
