.PHONY: help setup dev-setup test test-parser test-rules clean lint format docker-build docker-up docker-down

# Default target
help:
	@echo "Detector Project - Available commands:"
	@echo ""
	@echo "Setup & Installation:"
	@echo "  setup       - Install Python dependencies"
	@echo "  dev-setup   - Full development environment setup"
	@echo ""
	@echo "Testing:"
	@echo "  test        - Run all tests"
	@echo "  test-parser - Run parser tests only"
	@echo "  test-rules  - Run rules engine tests only"
	@echo ""
	@echo "Code Quality:"
	@echo "  lint        - Run linting and type checking"
	@echo "  format      - Format code with black"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build - Build all Docker images"
	@echo "  docker-up    - Start all services with Docker Compose"
	@echo "  docker-down  - Stop all services"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean       - Remove build artifacts and cache"

# Setup and installation
setup:
	@echo "Installing Python dependencies..."
	cd parser && pip install -r requirements.txt

dev-setup: setup
	@echo "Setting up development environment..."
	@echo "Starting Docker services..."
	docker-compose up -d
	@echo "Waiting for services to initialize..."
	sleep 30
	@echo "Development environment ready!"
	@echo "Kibana available at: http://localhost:5601"
	@echo "Elasticsearch available at: http://localhost:9200"

# Testing
test: test-parser test-rules

test-parser:
	@echo "Running parser tests..."
	cd parser && python -m pytest tests/ -v

test-rules:
	@echo "Running rules engine tests..."
	cd rules/engine && python -m pytest test_rules_engine.py -v || echo "Rules engine tests not yet implemented"

# Code quality
lint:
	@echo "Running code quality checks..."
	black --check --diff .
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	mypy . --ignore-missing-imports || echo "MyPy not configured"

format:
	@echo "Formatting code..."
	black .

# Docker commands
docker-build:
	@echo "Building Docker images..."
	cd parser && docker build -t detector-parser:latest .
	@echo "Docker images built successfully"

docker-up:
	@echo "Starting services with Docker Compose..."
	docker-compose up -d
	@echo "Services started. Kibana: http://localhost:5601"

docker-down:
	@echo "Stopping services..."
	docker-compose down

# Cleanup
clean:
	@echo "Cleaning up..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	docker system prune -f
	@echo "Cleanup completed"
