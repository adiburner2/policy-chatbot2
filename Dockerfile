# Use an official lightweight Python image as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file first to leverage Docker cache
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# --no-cache-dir reduces image size, and --upgrade pip is good practice
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application's code into the container
COPY . .

# Initialize the database and settings when the image is built.
# This ensures the .db file exists in the container image.
RUN python -c 'import index; index.init_db(); index.init_settings()'

# Make port 8000 available to the world outside this container
EXPOSE 8000

# Define the command to run the app using Gunicorn, a production-ready server
# The bind address 0.0.0.0 is crucial for Docker networking.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "index:app"]