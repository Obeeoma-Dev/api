# Test Commands Reference

## 🚀 SIMPLEST COMMAND (Copy & Paste This!)
```bash
python -m pytest tests/ -v --tb=short --reuse-db
```

⚠️ **IMPORTANT:** It's `pytest` (NOT "pytests") with a space before `tests/`

## Quick Commands

### Run All Tests
```bash
python -m pytest tests/ -v --tb=short --reuse-db
```

### OR Use Simple Scripts
- **Windows:** Double-click `test.bat`
- **Git Bash:** Run `bash test.sh` or `./test.sh`
- **PowerShell:** Run `.\test.ps1`

### Run Specific Test File
```bash
python -m pytest tests/test_models_simple.py -v --tb=short
```

### Run Specific Test Class
```bash
python -m pytest tests/test_models_simple.py::BasicUserModelTest -v
```

### Run Specific Test Function
```bash
python -m pytest tests/test_models_simple.py::BasicUserModelTest::test_create_user -v
```

### Run Tests with Coverage
```bash
python -m pytest tests/ -v --tb=short --cov=obeeomaapp --cov=sana_ai
```

### Run Only Failed Tests (from last run)
```bash
python -m pytest tests/ --lf -v
```

### Run Tests in Parallel (faster)
```bash
python -m pytest tests/ -v -n auto
```

## Using Scripts

### Windows Batch File (Double-click or run)
```bash
run_tests.bat
```

### PowerShell Script
```powershell
.\run_tests.ps1
```

### Run Specific Test File
```bash
run_tests_specific.bat tests\test_models_simple.py
```

## Shortest Command (What you'll use most)

Just remember this one simple command:
```bash
pytest
```

This works because `pytest.ini` is already configured with all the settings!

## Options Explained

- `-v` or `--verbose`: Shows detailed test output
- `--tb=short`: Shows shorter traceback format
- `--reuse-db`: Reuses test database (faster)
- `--lf` or `--last-failed`: Run only failed tests from last run
- `-n auto`: Run tests in parallel (requires pytest-xdist)
- `--cov`: Generate coverage report

## VS Code Integration

You can also run tests directly from VS Code:
1. Open the Testing panel (beaker icon)
2. Click the play button next to any test
3. Or use the Command Palette (Ctrl+Shift+P) → "Python: Run All Tests"

