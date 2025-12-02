@echo off
REM ===================================================
REM Django/Pytest Test Runner
REM Run all tests in the tests/ directory
REM ===================================================

echo.
echo ================================================
echo Running Django Tests with Pytest
echo ================================================
echo.

REM Activate virtual environment if it exists
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM Run pytest with all tests
python -m pytest tests/ -v --tb=short --reuse-db

REM Check exit code
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ================================================
    echo Tests PASSED!
    echo ================================================
) else (
    echo.
    echo ================================================
    echo Tests FAILED! Check output above.
    echo ================================================
)

pause

