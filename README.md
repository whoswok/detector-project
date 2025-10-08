Detector Project

A log analysis and threat detection system that processes security logs, applies detection rules, and provides real-time monitoring capabilities.

## Features

- **Log Parsing**: Parse various log formats (syslog, JSON, CSV)
- **Detection Rules**: Configurable rules engine for threat detection
- **Real-time Processing**: Stream processing with Elasticsearch integration
- **Kibana Dashboards**: Pre-built visualizations for security monitoring
- **Alerting**: Automated alert generation based on detection rules

## Architecture

The system consists of several components:
- **Parser Service**: Processes incoming log data
- **Rules Engine**: Applies detection rules to parsed logs  
- **Storage**: Elasticsearch for log storage and indexing
- **Visualization**: Kibana for dashboards and monitoring
- **Alerting**: Automated notification system

## Quick Start

1. Clone the repository
2. Start the services: `docker-compose up -d`
3. Access Kibana at http://localhost:5601
4. Upload sample logs for testing

## Project Structure

```
├── docker-compose.yml      # ELK stack and services
├── parser/                 # Log parsing service
│   ├── src/
│   ├── tests/
│   └── Dockerfile
├── rules/                  # Detection rules
│   ├── engine/
│   └── samples/
├── logs/                   # Sample log files
├── dashboards/             # Kibana dashboard exports
├── docs/                   # Documentation
└── ci/                     # CI/CD configurations
```

## Development

### Prerequisites
- Docker and Docker Compose
- Python 3.8+ (for local development)
- Elasticsearch 7.10+

### Setup
1. `docker-compose up -d` - Start ELK stack
2. `pip install -r requirements.txt` - Install Python dependencies
3. `python -m pytest` - Run tests

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions, please open an issue on GitHub.
