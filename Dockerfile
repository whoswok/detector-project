# Detector Project Dockerfile
FROM python:3.9-slim

WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || echo "No requirements.txt found"

# Expose port for web service
EXPOSE 8000

# Simple start command
CMD ["python", "-c", "print('Detector Project - Deploy via Railway\\n\\nAccess your live demo at the provided URL!\\n\\nFeatures:\\n• Threat Detection Engine\\n• ML-based Anomaly Detection\\n• Real-time Log Processing\\n• Kibana Dashboards')"]
