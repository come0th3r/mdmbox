param(
    [Parameter(Mandatory = $true)][string]$OutputFile
)

# Prepared pinned sources only. Does not clone, patch or edit manifests.
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$root = Split-Path -Parent $repo
$OutputFile = [IO.Path]::GetFullPath($OutputFile)
$git = (Get-Command git.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$go = (Get-Command go.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$pins = [ordered]@{
    libneko = '1c47a3af71990a7b2192e03292b4d246c308ef0b'
    'sing-box' = '06557f6cef23160668122a17a818b378b5a216b5'
    'sing-quic' = 'b49ce60d9b3622d5238fee96bfd3c5f6e3915b42'
    sing = 'f7cd94b14d31ace655e3f2285463c2ebf30294aa'
}
foreach ($name in $pins.Keys) {
    $directory = Join-Path $root $name
    $head = & $git -C $directory rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $head -ne $pins[$name]) { throw "Unexpected dependency revision: $name" }
    $changed = @(& $git -C $directory diff HEAD --name-only)
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect dependency: $name" }
    $expected = if ($name -eq 'sing') { @('common/control/bind_finder_default.go') } else { @() }
    if (($changed -join '|') -ne ($expected -join '|')) { throw "Unexpected tracked dependency changes: $name" }
    $untracked = @(& $git -C $directory ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw "Cannot inspect untracked dependency files: $name" }
    foreach ($file in $untracked) {
        if ($name -ne 'sing' -or $file -ne 'common/control/mdmbox_compat_test.go') {
            throw "Unexpected untracked dependency file: $name/$file"
        }
        $overlay = Join-Path $directory $file
        $fixture = Join-Path $repo 'test/fixtures/sing-control-compat_test.go'
        if ((Get-FileHash $overlay).Hash -ne (Get-FileHash $fixture).Hash) { throw "Unexpected test overlay contents." }
    }
}
$blob = & $git -C (Join-Path $root 'sing') hash-object common/control/bind_finder_default.go
if ($LASTEXITCODE -ne 0 -or $blob -ne '7d8f2f54ecfca279eb4003d6f4797483ede71fc7') {
    throw "Expected exact sing linkname backport. See libs/patches/README.md."
}
$version = & $go version
if ($LASTEXITCODE -ne 0 -or $version -notmatch '^go version go1\.27\.2 windows/amd64$') {
    throw "Baseline requires Go 1.27.2 windows/amd64."
}
$module = Join-Path $repo 'go/cmd/nekobox_core'
$manifests = @(Get-ChildItem (Join-Path $repo 'go') -Recurse -File | Where-Object { $_.Name -in @('go.mod', 'go.sum') })
$before = @{}
foreach ($file in $manifests) { $before[$file.FullName] = (Get-FileHash $file.FullName).Hash }
$variables = @('GOSUMDB', 'GOPROXY', 'CGO_ENABLED', 'GOTOOLCHAIN', 'GOFLAGS', 'GOOS', 'GOARCH', 'GOWORK', 'GOPRIVATE', 'GONOSUMDB', 'GONOPROXY')
$old = @{}
foreach ($name in $variables) { $old[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location $module
try {
    $env:GOSUMDB = 'sum.golang.org'
    $env:GOPROXY = 'https://proxy.golang.org,direct'
    $env:CGO_ENABLED = '0'
    $env:GOTOOLCHAIN = 'local'
    $env:GOFLAGS = ''
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:GOWORK = 'off'
    $env:GOPRIVATE = ''
    $env:GONOSUMDB = ''
    $env:GONOPROXY = ''
    & $go build '-mod=readonly' '-trimpath' '-tags=with_clash_api,with_quic,with_utls,with_ech' '-o' $OutputFile '.'
    if ($LASTEXITCODE -ne 0) { throw "Core build failed." }
    & $OutputFile version
    if ($LASTEXITCODE -ne 0) { throw "Core version command failed." }
    [pscustomobject]@{
        status = 'CORE_BUILD_PASS'
        artifact = $OutputFile
        sha256 = (Get-FileHash $OutputFile -Algorithm SHA256).Hash
        go = $version
        runtimeConnections = 'NOT_RUN'
    } | ConvertTo-Json
} finally {
    Pop-Location
    foreach ($name in $variables) { [Environment]::SetEnvironmentVariable($name, $old[$name], 'Process') }
    foreach ($file in $manifests) {
        if ((Get-FileHash $file.FullName).Hash -ne $before[$file.FullName]) { throw "Manifest changed unexpectedly: $($file.Name)" }
    }
}
