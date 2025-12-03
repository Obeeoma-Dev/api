#!/bin/bash
# Run tests with SQLite (not Neon database)
export DATABASE_URL="sqlite:///test.db"
export SECRET_KEY="test-secret-key"
export DEBUG="False"

python -m pytest tests/ -v --tb=short
