# ===================================================
# Django/Pytest Test Runner (PowerShell)
# Run all tests in the tests/ directory
# ===================================================

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Running Django Tests with Pytest" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Activate virtual environment if it exists
if (Test-Path "venv\Scripts\Activate.ps1") {
    & "venv\Scripts\Activate.ps1"
}

# Run pytest with all tests
python -m pytest tests/ -v --tb=short --reuse-db

# Check exit code
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "Tests PASSED!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Red
    Write-Host "Tests FAILED! Check output above." -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Red
}

Read-Host "Press Enter to continue"

