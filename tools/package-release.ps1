[CmdletBinding()]
param(
    [string]$BuildRoot = 'build/release',
    [string]$OutputDirectory = 'dist',
    [switch]$AllowDirty
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$utf8 = New-Object Text.UTF8Encoding($false)

function Resolve-ProjectPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

function Invoke-CMake([string[]]$Arguments) {
    & cmake @Arguments
    if ($LASTEXITCODE -ne 0) { throw "CMake failed with exit code $LASTEXITCODE." }
}

Get-Command cmake, git -ErrorAction Stop | Out-Null
$version = ([IO.File]::ReadAllText((Join-Path $repoRoot 'VERSION'))).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$') {
    throw 'VERSION must contain a semantic version, such as 0.1.0-alpha.'
}
$commit = & git -C $repoRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'A Git checkout with at least one commit is required.' }
$status = @(& git -C $repoRoot status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the source worktree.' }
$dirty = $status.Count -gt 0
if ($dirty -and -not $AllowDirty) {
    throw 'The worktree has uncommitted changes. Commit reviewed source first, or use -AllowDirty for local validation only.'
}

$buildPath = Resolve-ProjectPath $BuildRoot
$outputPath = Resolve-ProjectPath $OutputDirectory
$x86Build = Join-Path $buildPath 'x86'
$x64Build = Join-Path $buildPath 'x64'
$x86Bin = Join-Path $x86Build 'bin/Release'
$x64Bin = Join-Path $x64Build 'bin/Release'

Invoke-CMake @('-S', $repoRoot, '-B', $x86Build, '-G', 'Visual Studio 17 2022',
    '-A', 'Win32', '-DBUILD_TESTING=OFF', '-DCLIP_NO_ELEVATE=OFF')
Invoke-CMake @('--build', $x86Build, '--config', 'Release', '--parallel', '4')
Invoke-CMake @('-S', $repoRoot, '-B', $x64Build, '-G', 'Visual Studio 17 2022',
    '-A', 'x64', '-DBUILD_TESTING=OFF', '-DCLIP_NO_ELEVATE=OFF', "-DCLIP_X86_BIN_DIR=$x86Bin")
Invoke-CMake @('--build', $x64Build, '--config', 'Release', '--parallel', '4')

# POST_BUILD may not run if the x64 executable is already up to date.
foreach ($name in @('HookHost32.exe', 'HookDll32.dll')) {
    Copy-Item -LiteralPath (Join-Path $x86Bin $name) -Destination (Join-Path $x64Bin $name) -Force
}

$finalCommit = & git -C $repoRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or "$finalCommit" -cne "$commit") {
    throw 'The source commit changed during the build; run packaging again.'
}
$finalStatus = @(& git -C $repoRoot status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw 'Cannot recheck the source worktree.' }
if (-not $dirty -and $finalStatus.Count -gt 0) {
    throw 'The worktree changed during the build; do not label this package as clean source.'
}

$suffix = if ($dirty) { '-local' } else { '' }
$packageName = "ClipboardProtector-$version$suffix-windows-x64"
$stagingRoot = Join-Path $buildPath ('package-' + [Guid]::NewGuid().ToString('N'))
$packagePath = Join-Path $stagingRoot $packageName
[void][IO.Directory]::CreateDirectory($packagePath)
[void][IO.Directory]::CreateDirectory($outputPath)

# Allow only production components, never the entire build directory.
$binaries = @('ClipboardProtector.exe', 'HookDll.dll', 'HookHost32.exe', 'HookDll32.dll')
foreach ($name in $binaries) {
    $source = Join-Path $x64Bin $name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing component: $name" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $packagePath $name)
}

# Keep links usable without bundling the source documentation or image assets.
$repository = if ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY } else { 'clanet/ClipboardProtector' }
$sourceUrl = "https://github.com/$repository/blob/$commit"
foreach ($name in @('readme.md', 'README.en.md')) {
    $content = [IO.File]::ReadAllText((Join-Path $repoRoot $name))
    $content = [regex]::Replace($content, '\]\((?![a-zA-Z][a-zA-Z0-9+.-]*:|#)([^)]+)\)', {
        param($match)
        $target = $match.Groups[1].Value
        if ($target -in @('readme.md', 'README.en.md')) { return $match.Value }
        return "]($sourceUrl/$target)"
    })
    $content = [regex]::Replace($content, '(?m)^<img [^\r\n]+>\r?\n', '')
    if ($name -eq 'README.en.md') {
        # MIT notices must travel with the binaries; embed them in the README.
        $content += "`n## Licenses`n"
        $licenses = [ordered]@{
            'ClipboardProtector' = 'LICENSE'
            'Microsoft Detours' = 'licenses/Detours-MIT.txt'
            'BIP-39 English word list' = 'licenses/BIP39-MIT.txt'
        }
        foreach ($license in $licenses.GetEnumerator()) {
            $text = [IO.File]::ReadAllText((Join-Path $repoRoot $license.Value)).Trim()
            $content += "`n### $($license.Key)`n`n$text`n"
        }
    }
    [IO.File]::WriteAllText((Join-Path $packagePath $name), $content, $utf8)
}
$zip = Join-Path $outputPath "$packageName.zip"
Compress-Archive -LiteralPath $packagePath -DestinationPath $zip -CompressionLevel Optimal -Force
$zipHash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$zip.sha256", "$zipHash  $packageName.zip`n", $utf8)
Write-Output "Package: $zip"
Write-Output "SHA256:  $zipHash"
if ($dirty) { Write-Warning 'This is a LOCAL VALIDATION package containing uncommitted changes.' }
