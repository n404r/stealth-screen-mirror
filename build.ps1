Write-Host "Screen Mirror - Build" -ForegroundColor Cyan

# Ask for executable name
$inputName = Read-Host "Executable name (e.g. mirrorplus or mirrorplus.exe)"
if ([string]::IsNullOrWhiteSpace($inputName)) {
    Write-Host "Aborted: no name provided." -ForegroundColor Red
    exit 1
}
if ($inputName -notlike "*.exe") { $exeName = "$inputName.exe" } else { $exeName = $inputName }

# Validate name
if ($exeName -notmatch '^[\w\-.]+\.exe$') {
    Write-Host "Invalid name. Use letters, numbers, underscore, dash, dot, and end with .exe" -ForegroundColor Red
    exit 1
}

$mainFile = "main.go"
if (-not (Test-Path $mainFile)) {
    Write-Host "Error: main.go not found." -ForegroundColor Red
    exit 1
}

# Create temp file
$tempFile = "build_temp_$((Get-Random)).go"
Copy-Item $mainFile $tempFile -Force

# Replace "mirror.exe" with user input (simple string replace, no regex)
(Get-Content $tempFile -Raw) -replace "mirror.exe", $exeName | Set-Content $tempFile -Encoding UTF8

# Build quietly
Write-Host "Building $exeName ..." -ForegroundColor Yellow
go build -ldflags="-s -w" -trimpath -o $exeName $tempFile
$code = $LASTEXITCODE

# Clean temp file
Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

if ($code -eq 0) {
    $size = (Get-Item $exeName).Length / 1MB
    Write-Host "Build successful: $exeName ($([math]::Round($size,2)) MB)" -ForegroundColor Green
} else {
    Write-Host "Build failed (code $code)" -ForegroundColor Red
}
