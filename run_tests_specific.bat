@echo off
REM ===================================================
REM Run Specific Test File
REM Usage: run_tests_specific.bat tests\test_models_simple.py
REM ===================================================

if "%~1"=="" (
    echo Error: Please provide a test file path
    echo Usage: run_tests_specific.bat tests\test_models_simple.py
    pause
    exit /b 1
)

echo.
echo ================================================
echo Running Test File: %~1
echo ================================================
echo.

REM Activate virtual environment if it exists
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)

REM Run pytest on specific file
python -m pytest %~1 -v --tb=short --reuse-db

pause

