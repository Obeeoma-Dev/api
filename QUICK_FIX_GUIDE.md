# Quick Fix Guide - Pytest Issues

## Problem 1: `ModuleNotFoundError: No module named 'model_bakery'`

**Solution:**
```bash
# If using venv (recommended)
.\venv\Scripts\pip install model-bakery==1.20.0

# If not using venv
pip install model-bakery==1.20.0
```

## Problem 2: `PytestCollectionWarning: cannot collect test class 'WellnessTest'`

**Cause:** Pytest thinks `WellnessTest` model is a test class because it starts with "Test"

**Solution:** Already fixed in `pytest.ini` by:
1. Removing `*Test` from `python_classes` pattern
2. Adding `filterwarnings = ignore::pytest.PytestCollectionWarning`

## Problem 3: Duplicate model registration warning

**Warning:** `Model 'obeeomaapp.resourcecategory' was already registered`

**Cause:** You have duplicate model definitions in your models.py

**To Fix:** Search for duplicate `class ResourceCategory` or `class Progress` in `obeeomaapp/models.py` and remove duplicates.

## Running Tests:

### In your venv:
```bash
# Activate venv first
.\venv\Scripts\activate

# Run tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_models.py -v
```

### Without venv:
```bash
pytest -v
```

## Commit Changes:

```bash
git add .
git commit -m "fix: Setup pytest and fix test imports for CI/CD"
git push origin main
```

## Files Modified:
- ✅ `requirements.txt` - Added pytest dependencies, removed duplicates
- ✅ `pytest.ini` - Pytest configuration
- ✅ `conftest.py` - Pytest fixtures
- ✅ `tests/test_models.py` - Fixed imports
- ✅ `tests/test_serializers.py` - Fixed imports
- ✅ `.github/workflows/CI_CD.yml` - Use pytest instead of Django test
- ✅ `.github/workflows/api-ci_cd.yml` - Use pytest instead of Django test
- ✅ `api/settings.py` - Support SQLite for CI

## Expected Result:
After pushing, GitHub Actions should pass with pytest running all your tests!
