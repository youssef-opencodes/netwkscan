deactivate 2>/dev/null || true
rm -rf venv

# Remove database files
rm -f data/nmd.db
rm -f src/data/nmd.db

# Remove log files
rm -rf src/data/logs/*.log

# Remove Python cache files
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
find . -type f -name "*.pyo" -delete 2>/dev/null || true

# Remove build artifacts
rm -rf build/ dist/ *.spec

# Remove pytest cache
rm -rf .pytest_cache/

# Remove any temp files
rm -f *.log *.tmp

