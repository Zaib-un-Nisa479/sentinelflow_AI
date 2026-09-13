# SentinelFlow Infrastructure

A comprehensive security infrastructure platform for threat intelligence enrichment and automated incident response workflows.

## Overview

SentinelFlow is a containerized system that integrates multiple security tools and services to automate threat detection, indicator enrichment, and incident response. It combines:

- **FastAPI Backend** - RESTful API for security operations
- **n8n Automation** - Workflow orchestration engine
- **PostgreSQL Database** - Persistent threat intelligence storage
- **Threat Intelligence APIs** - Integration with VirusTotal and AbuseIPDB

## Features

- 🎯 **IOC Enrichment** - Automatically enrich indicators of compromise (IPs, domains, file hashes) with threat intelligence
- 🔄 **Workflow Automation** - n8n-based workflows for orchestrating security responses
- 📊 **Security Metrics** - Dashboard metrics for monitoring security posture
- 📋 **Report Generation** - Automated report generation for security incidents
- 🔐 **Containerized Deployment** - Docker Compose setup for easy deployment
- 🛡️ **API Security** - API key authentication for all endpoints

## Project Structure

```
sentinelflow-infra/
├── api/                          # FastAPI application
│   ├── main.py                  # Main application entry point
│   ├── models.py                # Pydantic data models
│   ├── database.py              # Database connection and utilities
│   ├── enrichment.py            # Threat intelligence enrichment logic
│   ├── actions.py               # Security action execution
│   ├── metrics.py               # Dashboard metrics
│   ├── reports.py               # Report generation
│   ├── requirements.txt         # Python dependencies
│   ├── Dockerfile               # Container configuration
│   └── tests/                   # Unit tests
├── n8n-custom/                  # n8n custom configuration
│   └── Dockerfile               # n8n container configuration
├── docker-compose.yml           # Multi-container orchestration
├── .gitignore                   # Git ignore rules
└── README.md                    # This file
```

## Prerequisites

- Docker and Docker Compose
- Python 3.9+ (for local development)
- Environment variables configuration

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Zaib-un-Nisa479/sentinelflow_AI.git
cd sentinelflow-infra
```

### 2. Configure Environment Variables

Create a `.env` file in the project root:

```env
# PostgreSQL Configuration
POSTGRES_USER=sentinelflow
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=sentinelflow

# API Configuration
API_SECRET_KEY=your_secret_api_key

# n8n Configuration
N8N_ENCRYPTION_KEY=your_n8n_encryption_key

# Threat Intelligence APIs
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

### 3. Start Services

```bash
docker-compose up -d
```

This will start:
- **PostgreSQL** (port not exposed, internal use)
- **n8n** (http://localhost:5678)
- **SentinelFlow API** (http://localhost:8000)

## API Endpoints

All endpoints require the `X-API-Key` header.

### Enrich Indicators

```bash
curl -X POST http://localhost:8000/enrich \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "192.168.1.1", "type": "ip"}'
```

### Execute Security Actions

```bash
curl -X POST http://localhost:8000/action \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"action_type": "block", "target": "192.168.1.1"}'
```

### Generate Reports

```bash
curl -X POST http://localhost:8000/report \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "daily_summary", "date": "2024-01-15"}'
```

### Get Dashboard Metrics

```bash
curl -X GET http://localhost:8000/metrics \
  -H "X-API-Key: your_api_key"
```

## Local Development

### Setup Python Environment

```bash
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate
```

### Install Dependencies

```bash
cd api
pip install -r requirements.txt
```

### Run Tests

```bash
pytest tests/
```

## Configuration

### PostgreSQL

- **Host**: postgres (Docker network)
- **Port**: 5432
- **Database**: ${POSTGRES_DB}
- **User**: ${POSTGRES_USER}
- **Password**: ${POSTGRES_PASSWORD}

### n8n

Access the n8n interface at `http://localhost:5678` to create and manage workflows.

### API Security

The API uses header-based authentication. All requests must include:

```
X-API-Key: ${API_SECRET_KEY}
```

## Development

### Adding New Enrichment Sources

Modify `api/enrichment.py` to add new threat intelligence sources.

### Creating Security Actions

Update `api/actions.py` with new incident response actions.

### Extending Reports

Enhance `api/reports.py` for additional reporting capabilities.

## Troubleshooting

### Services Won't Start

```bash
# Check logs
docker-compose logs -f

# Verify database health
docker-compose ps
```

### API Connection Issues

- Ensure all services are healthy: `docker-compose ps`
- Verify API key is correct in requests
- Check network connectivity: `docker network ls`

### Database Connection Errors

- Confirm PostgreSQL is healthy: `docker-compose logs postgres`
- Verify environment variables are set correctly
- Check database user permissions

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

## Roadmap

- [ ] Webhook support for incident notifications
- [ ] Real-time alert dashboard
- [ ] Machine learning-based threat scoring
- [ ] SIEM integration
- [ ] Multi-source threat correlation

## Authors

- **Zaib-un-Nisa** - Initial development

## Acknowledgments

- VirusTotal for threat intelligence data
- AbuseIPDB for IP reputation data
- n8n for workflow automation platform
