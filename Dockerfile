# Use an official lightweight Python image as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies needed for PostgreSQL
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code into the container
COPY . .

# Copy and make the startup script executable
COPY startup.sh .
RUN chmod +x startup.sh

# Create upload directory
RUN mkdir -p temp_uploads

# Make port 8000 available to the world outside this container
EXPOSE 8000

# REMOVED: Database initialization from build time
# This was causing the error because DATABASE_URL isn't available during build

# Use startup script that handles database initialization at runtime
CMD ["./startup.sh"]