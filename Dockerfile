# Use an official lightweight Python image as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code into the container
COPY . .

# --- START OF CHANGES ---

# Create the uploads directory inside the container
RUN mkdir -p /app/uploads

# Copy the pre-defined knowledge base files into the container's upload directory
COPY knowledge_base/ /app/uploads/

# We need to manually add these to the database so the app knows they exist
# NOTE: This assumes the admin user (ID 1) and client user (ID 2) are created first
# This is a bit of a "hack" for demo purposes, but effective.
RUN python -c 'import index; index.init_db(); index.init_settings(); \
    from index import get_db_connection, datetime; \
    conn = get_db_connection(); \
    conn.execute("INSERT OR IGNORE INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)", ("global_rules.pdf", "global_rules.pdf", "pdf", 1000, datetime.now().isoformat(), 1)); \
    conn.execute("INSERT OR IGNORE INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)", ("client_policy.pdf", "client_policy.pdf", "pdf", 1000, datetime.now().isoformat(), 2)); \
    conn.commit(); conn.close()'

# --- END OF CHANGES ---

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define the command to run the app using Gunicorn, a production-ready server
# FIX: Added --timeout 120 to give the AI more time to respond.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "180", "index:app"]