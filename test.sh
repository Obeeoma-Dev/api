#!/bin/bash
# Simple test runner for Git Bash / Linux
python -m pytest tests/ -v --tb=short --reuse-db

