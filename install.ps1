# caddy-analyze static binary installer for Windows PowerShell
$ErrorActionPreference = 'Stop'

$Repo = "lenny-ts/caddy-analyzer"
$BinaryName = "caddy-analyze.exe"

$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $Arch = "arm64" }

$LatestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
$Tag = $LatestRelease.tag_name
if (-not $Tag) { $Tag = "v0.1.0" }

$VersionNum = $Tag.TrimStart('v')
$ArchiveName = "caddy-analyzer_${VersionNum}_windows_${Arch}.zip"
$Url = "https://github.com/$Repo/releases/download/$Tag/$ArchiveName"
$ChecksumsUrl = "https://github.com/$Repo/releases/download/$Tag/checksums.txt"

$InstallDir = Join-Path $env:LOCALAPPDATA "caddy-analyze"
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ZipPath = Join-Path $env:TEMP "caddy-analyze.zip"
$ChecksumsPath = Join-Path $env:TEMP "caddy-analyze-checksums.txt"

Write-Host "[*] Downloading caddy-analyze $Tag ($Arch) for Windows..." -ForegroundColor Cyan

try {
    Invoke-WebRequest -Uri $Url -OutFile $ZipPath
    Write-Host "[*] Downloading checksums..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath

    Write-Host "[*] Verifying SHA256 checksum..." -ForegroundColor Cyan
    $ExpectedLine = Get-Content $ChecksumsPath | Where-Object { $_ -match "\s$([regex]::Escape($ArchiveName))$" }
    if (-not $ExpectedLine) {
        throw "checksum for $ArchiveName not found in checksums.txt"
    }
    $ExpectedHash = ($ExpectedLine -split '\s+')[0].Trim()

    $ActualHash = (Get-FileHash -Algorithm SHA256 -Path $ZipPath).Hash.ToLower()
    if ($ActualHash -ne $ExpectedHash.ToLower()) {
        throw "checksum mismatch: expected $ExpectedHash, got $ActualHash"
    }
    Write-Host "[+] Checksum verified." -ForegroundColor Green

    Expand-Archive -Path $ZipPath -DestinationPath $InstallDir -Force
} finally {
    if (Test-Path $ZipPath) { Remove-Item -Path $ZipPath -Force -ErrorAction SilentlyContinue }
    if (Test-Path $ChecksumsPath) { Remove-Item -Path $ChecksumsPath -Force -ErrorAction SilentlyContinue }
}

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*caddy-analyze*") {
    $NewPath = "$UserPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "[+] Added $InstallDir to User PATH." -ForegroundColor Green
}

Write-Host "[+] Success! caddy-analyze $Tag installed to $InstallDir\$BinaryName" -ForegroundColor Green
Write-Host "Restart your terminal and run 'caddy-analyze --help' to get started." -ForegroundColor Yellow
