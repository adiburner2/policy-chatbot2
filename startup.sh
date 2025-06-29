#!/bin/bash

# Exit on any error
set -e

echo "Starting Policy Insight application..."

# Wait for database to be ready (optional but recommended)
echo "Checking database connection..."
python3 -c "
import sys, time, psycopg2, os
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    print('ERROR: DATABASE_URL environment variable not set'); sys.exit(1)
max_attempts = 30; attempt = 1
while attempt <= max_attempts:
    try:
        conn = psycopg2.connect(DATABASE_URL); conn.close()
        print('Database connection successful!'); break
    except psycopg2.OperationalError as e:
        print(f'Database connection attempt {attempt}/{max_attempts} failed: {e}')
        if attempt == max_attempts:
            print('ERROR: Could not connect to database'); sys.exit(1)
        time.sleep(2); attempt += 1
"

# Initialize database schema and settings
echo "Initializing database schema and settings..."
python3 -c "
import index, traceback
try:
    index.init_db()
    index.init_settings()
    print('Database initialization completed successfully!')
except Exception as e:
    print(f'Database initialization failed: {e}'); traceback.print_exc(); exit(1)
"

# Preload document cache
echo "Preloading document cache..."
python3 -c "
import index, traceback
try:
    index.preload_documents_to_cache()
except Exception as e:
    print(f'Cache preloading failed: {e}'); traceback.print_exc(); exit(1)
"

# Start the application with a longer timeout
echo "Starting Gunicorn server..."
if [ -f "gunicorn.conf.py" ]; then
    exec gunicorn -c gunicorn.conf.py index:app
else
    echo "gunicorn.conf.py not found, using default configuration..."
    exec gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 4 --timeout 30 --log-level info index:app
fi