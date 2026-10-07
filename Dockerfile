# Use an official lightweight Python image
FROM python:3.11-slim

# Set environment variables for Python
# PYTHONDONTWRITEBYTECODE prevents Python from writing .pyc files to disk
# PYTHONUNBUFFERED prevents Python from buffering stdout and stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PHISHGUARD_ENV=production

# Create a directory for the application
WORKDIR /app

# Install system dependencies (useful if you switch to PostgreSQL later which requires libpq)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the backend, dashboard, and ML model directories
# (We exclude tests and the extension via .dockerignore)
COPY backend/ backend/
COPY dashboard/ dashboard/
COPY ml/ ml/
COPY scripts/ scripts/

# Create a non-root user to run the application for better security
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app
USER appuser

# Expose the port FastAPI will run on
EXPOSE 8000

# Start the application using Uvicorn
CMD ["uvicorn", "backend.api.main:app_factory", "--host", "0.0.0.0", "--port", "8000"]
