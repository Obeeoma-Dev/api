# Testing Guide

## ✅ How to Run Tests Locally

### Windows:
```bash
run_tests.bat
```

### Mac/Linux:
```bash
bash run_tests.sh
```

### Manual:
```bash
# Set environment variables
set DATABASE_URL=sqlite:///test.db
set SECRET_KEY=test-secret-key

# Run tests
python -m pytest tests/ -v
```

---

## 🔍 What's Happening?

### Production Database (Neon PostgreSQL):
- **Used by:** Your live application
- **Contains:** Real user data
- **Location:** Neon cloud
- **Status:** ✅ Safe and untouched

### Test Database (SQLite):
- **Used by:** Tests only
- **Contains:** Temporary fake data
- **Location:** Local file `test.db`
- **Status:** 🔵 Created and deleted for each test run

---

## 📊 Current Test Status

**Total Tests:** 49
**Passing:** 49 ✅
**Failing:** 0 ❌

---

## 🚀 GitHub Actions CI

When you push to GitHub:
1. GitHub Actions starts
2. Creates temporary SQLite database
3. Runs all 49 tests
4. Shows GREEN ✅ if all pass
5. Deletes temporary database

**Your Neon database is never touched by CI!**

---

## 🛡️ Safety Notes

1. **Tests use SQLite** - Your Neon database is safe
2. **Test data is temporary** - Deleted after tests
3. **Production unchanged** - Tests don't affect live app
4. **Fast and reliable** - SQLite is faster than PostgreSQL for tests

---

## 📝 Test Files

- `tests/test_models_simple.py` - Model tests
- `tests/test_serializers.py` - Serializer tests
- `tests/test_serializers_minimal.py` - Minimal serializer tests
- `tests/test_views.py` - View tests (helper functions)

---

## 🔧 Troubleshooting

### Tests fail locally?
```bash
# Make sure you're using SQLite
echo $DATABASE_URL  # Should be: sqlite:///test.db

# Run tests again
run_tests.bat
```

### Tests pass locally but fail in CI?
- Check GitHub Actions logs
- Usually a dependency issue
- Make sure `requirements.txt` is up to date

---

## ✨ Best Practices

1. **Always run tests before pushing:**
   ```bash
   run_tests.bat
   ```

2. **If tests pass locally, they'll pass in CI** ✅

3. **Never run tests against Neon database** ❌

4. **Keep test.db in .gitignore** (already done)

---

**Happy Testing!** 🎉
