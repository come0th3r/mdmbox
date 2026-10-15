param([Parameter(Mandatory = $true)][string]$Archive)
$ErrorActionPreference = 'Stop'
$base = Split-Path -Parent $Archive
$out = Join-Path $base ('smoke-' + [Guid]::NewGuid().ToString('N'))
Expand-Archive -LiteralPath $Archive -DestinationPath $out
$d = (Get-ChildItem -LiteralPath $out -Directory | Select-Object -First 1).FullName
$manifest = Get-Content (Join-Path $d 'manifest.json') -Raw | ConvertFrom-Json
foreach ($f in $manifest.files) {
    if ((Get-FileHash (Join-Path $d $f.path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $f.sha256) {
        throw "Manifest mismatch: $($f.path)"
    }
}
$proxy = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
function ProxySnapshot {
    Get-ItemProperty $proxy | Select-Object ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL | ConvertTo-Json -Compress
}
$before = ProxySnapshot
$savedPath = $env:PATH
$keys = @('QT_QPA_PLATFORM', 'QTWEBENGINE_CHROMIUM_FLAGS', 'QTWEBENGINEPROCESS_PATH', 'QT_PLUGIN_PATH', 'QML2_IMPORT_PATH')
$saved = @{}
$p = $null
$children = @()
try {
    $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
    foreach ($key in $keys) {
        $saved[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
        [Environment]::SetEnvironmentVariable($key, $null, 'Process')
    }
    $p = Start-Process -FilePath (Join-Path $d 'mdmbox.exe') -ArgumentList @('-many', '-appdata',
        ('"' + (Join-Path $d 'alpha-data') + '"')) -WorkingDirectory $d -PassThru `
        -RedirectStandardOutput (Join-Path $out 'stdout.log') -RedirectStandardError (Join-Path $out 'stderr.log')
    Start-Sleep 15
    $p.Refresh()
    if ($p.HasExited) { throw "Client exited: $($p.ExitCode)" }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class AlphaWindows {
    public delegate bool Callback(IntPtr h, IntPtr p);
    [DllImport("user32.dll")] public static extern bool EnumWindows(Callback c, IntPtr p);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
    public static int Count(uint pid) {
        int n = 0;
        EnumWindows((h,p) => { uint id; GetWindowThreadProcessId(h,out id);
            if(id == pid && IsWindowVisible(h)) n++; return true; }, IntPtr.Zero);
        return n;
    }
}
'@
    $visible = [AlphaWindows]::Count($p.Id)
    $all = @(Get-CimInstance Win32_Process)
    $ids = @($p.Id)
    do {
        $new = @($all | Where-Object { $_.ParentProcessId -in $ids -and $_.ProcessId -notin $ids })
        $ids += @($new | ForEach-Object { $_.ProcessId })
    } while ($new.Count)
    $children = @($all | Where-Object { $_.ProcessId -in $ids -and $_.ProcessId -ne $p.Id })
    $unchanged = $before -eq (ProxySnapshot)
    [ordered]@{ manifest = 'PASS'; alive = $true; visibleWindows = $visible;
        children = @($children.Name); proxyUnchanged = $unchanged; noSdkPath = $true;
        cleanVm = 'NOT RUN'; cleanup = 'forced tracked descendants; graceful NOT RUN' } |
        ConvertTo-Json -Depth 4 | Tee-Object -FilePath (Join-Path $out 'result.json')
    if ($visible -lt 1 -or -not $unchanged) { throw 'Startup acceptance failed' }
} finally {
    foreach ($child in $children) { Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue }
    if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    $env:PATH = $savedPath
    foreach ($key in $saved.Keys) { [Environment]::SetEnvironmentVariable($key, $saved[$key], 'Process') }
}
'ALPHA_EXTRACTED_VISIBLE_STARTUP_PASS'
