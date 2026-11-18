$ErrorActionPreference = "Continue"

function Step($label, $block) {
    Write-Host "== $label" -ForegroundColor Cyan
    & $block
    if ($LASTEXITCODE -ne 0) {
        Write-Host "FAILED: $label" -ForegroundColor Red
        Read-Host "Press Enter to close"
        exit 1
    }
}

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "Go is not installed. Get it from https://go.dev/dl/ and open a new terminal." -ForegroundColor Red
    Read-Host "Press Enter to close"
    exit 1
}

Step "go mod tidy" { go mod tidy }
Step "tests" { go test ./internal/engine ./internal/secret }
Step "build" { go build -ldflags "-s -w" -o peanut.exe . }

Write-Host "Built peanut.exe" -ForegroundColor Green
Read-Host "Press Enter to close"
