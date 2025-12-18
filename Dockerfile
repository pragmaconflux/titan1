FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    git \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt requirements-optional.txt ./

# Install Python dependencies
# Core dependencies only by default
RUN pip install --no-cache-dir -r requirements.txt

# Optional: Install all features (uncomment if needed)
# RUN pip install --no-cache-dir -r requirements-optional.txt

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

# Create directory for samples
RUN mkdir -p /samples /reports

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Default command
ENTRYPOINT ["titan-decoder"]
CMD ["--help"]

# Example usage:
# docker build -t titan-decoder .
# docker run -v $(pwd)/samples:/samples titan-decoder --file /samples/malware.bin --out /samples/report.json
# docker run -v $(pwd)/samples:/samples titan-decoder --batch /samples --out /reports
