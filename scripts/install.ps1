# LANChat installer for Windows (PowerShell 5.1 or later).
#
#   irm https://raw.githubusercontent.com/milad-raeisi/LANChat/main/scripts/install.ps1 | iex
#
# Downloads the latest release for this architecture from GitHub, verifies
# its SHA-256 checksum against checksums.txt, installs lanchat.exe into
# %LOCALAPPDATA%\Programs\LANChat and adds that folder to the *user* PATH.
# No administrator rights are needed; firewall settings are not changed.
#
# Optional environment variables: LANCHAT_VERSION (e.g. v1.0.0),
# LANCHAT_INSTALL_DIR, LANCHAT_NO_MODIFY_PATH=1, LANCHAT_DOWNLOAD_BASE.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'milad-raeisi/LANChat'
$base = if ($env:LANCHAT_DOWNLOAD_BASE) { $env:LANCHAT_DOWNLOAD_BASE } else { "https://github.com/$repo/releases/download" }

switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "Unsupported CPU architecture: $($env:PROCESSOR_ARCHITECTURE). Supported: AMD64, ARM64." }
}

$version = $env:LANCHAT_VERSION
if (-not $version) {
    Write-Host 'Looking up the latest LANChat release...'
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ Accept = 'application/vnd.github+json' }
        $version = $release.tag_name
    } catch {
        if (Get-Command go -ErrorAction SilentlyContinue) {
            Write-Host "No published release found; building from source with 'go install'..."
            go install "github.com/$repo/cmd/lanchat@latest"
            Write-Host 'Installed with go install. Make sure your Go bin directory is on PATH, then run: lanchat'
            return
        }
        throw "No published LANChat release was found on GitHub yet. Install Go (https://go.dev/dl) and run: go install github.com/$repo/cmd/lanchat@latest"
    }
}
if ($version -notmatch '^v\d') { throw "Invalid version '$version' (expected a tag such as v1.0.0)." }
$num = $version.Substring(1)
$archive = "lanchat_${num}_windows_${arch}.zip"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("lanchat-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading LANChat $version for windows/$arch..."
    Invoke-WebRequest -Uri "$base/$version/$archive" -OutFile (Join-Path $tmp $archive) -UseBasicParsing
    Invoke-WebRequest -Uri "$base/$version/checksums.txt" -OutFile (Join-Path $tmp 'checksums.txt') -UseBasicParsing

    $expected = $null
    foreach ($line in Get-Content (Join-Path $tmp 'checksums.txt')) {
        $parts = $line -split '\s+'
        if ($parts.Count -ge 2 -and $parts[1].TrimStart('*') -eq $archive) { $expected = $parts[0].ToLower() }
    }
    if (-not $expected) { throw "checksums.txt has no entry for $archive." }
    $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp $archive)).Hash.ToLower()
    if ($expected -ne $actual) { throw "Checksum mismatch for $archive (expected $expected, got $actual). The download may be corrupted or tampered with." }
    Write-Host 'Checksum verified (SHA-256).'

    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath (Join-Path $tmp 'x') -Force
    $exe = Join-Path $tmp 'x\lanchat.exe'
    if (-not (Test-Path $exe)) { throw 'The archive does not contain lanchat.exe.' }

    $dir = if ($env:LANCHAT_INSTALL_DIR) { $env:LANCHAT_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\LANChat' }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item $exe (Join-Path $dir 'lanchat.exe') -Force
    Write-Host "Installed $(Join-Path $dir 'lanchat.exe')"

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @($userPath -split ';' | Where-Object { $_ })
    if ($entries -notcontains $dir) {
        if ($env:LANCHAT_NO_MODIFY_PATH -eq '1') {
            Write-Host "Add $dir to your PATH to run lanchat from any terminal."
        } else {
            [Environment]::SetEnvironmentVariable('Path', (($entries + $dir) -join ';'), 'User')
            Write-Host "Added $dir to your user PATH. Open a new terminal to use it."
        }
    }
    $env:Path = "$dir;$env:Path"

    & (Join-Path $dir 'lanchat.exe') --version
    Write-Host ''
    Write-Host 'Start LANChat with:  lanchat'
    Write-Host 'Windows Defender Firewall will ask whether lanchat may use the network: allow Private networks.'
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
