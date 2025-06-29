# --- START OF FILE startup.sh ---

#!/bin/bash

# Exit on any error
set -e

echo "Starting Policy Insight application..."

# Initialize database schema and settings
echo "Initializing database schema and settings..."
python -c "
import index, traceback
try:
    index.init_db()
    index.init_settings()
    print('Database initialization completed successfully!')
except Exception as e:
    print(f'Database initialization failed: {e}'); traceback.print_exc(); exit(1)
"

# Start the application with a longer timeout to handle slow LLM responses
echo "Starting Gunicorn server..."
exec gunicorn -c gunicorn.conf.py index:app

# --- END OF FILE startup.sh ---