@echo off
REM Run tests with SQLite (not Neon database)
REM This keeps your Neon production database safe!

echo Running tests with SQLite...
set DATABASE_URL=sqlite:///test.db
set SECRET_KEY=test-secret-key
set DEBUG=False

python -m pytest tests/ -v --tb=short

echo.
echo Tests completed!
echo Note: Your Neon database was NOT touched.
