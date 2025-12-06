@echo off
REM Simple test runner - just run this file!
python -m pytest tests/ -v --tb=short --reuse-db

