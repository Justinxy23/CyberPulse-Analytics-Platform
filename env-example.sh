# CyberPulse Analytics Platform - Environment Configuration
# Copy this file to .env and update with your values
# Author: Justin Christopher Weaver

# Application Settings
ENVIRONMENT=development
DEBUG=false
LOG_LEVEL=info
SECRET_KEY=your-super-secret-key-change-this-in-production
API_PORT=8080

# Database Configuration
DATABASE_URL=postgresql://cyberpulse_admin:your-db-password@localhost:5432/cyberpulse
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cyberpulse
DB_USER=cyberpulse_admin
DB_PASSWORD=your-secure-database-password
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40

# Redis Configuration
REDIS_URL=redis://:your-redis-password@localhost:6379
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
REDIS_DB=0
REDIS_MAX_CONNECTIONS=50

# Authentication
JWT_SECRET=your-jwt-secret-key-must-be-long-and-random
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
ADMIN_PASSWORD=ChangeMeImmediately!
MFA_ENABLED=true

# Security Settings
ALLOWED_ORIGINS=http://localhost:3000,https://cyberpulse.io
CORS_ALLOW_CREDENTIALS=true
RATE_LIMIT_PER_MINUTE=60
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=30

# AWS Configuration (for production deployment)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
S3_BUCKET_NAME=cyberpulse-data
S3_BACKUP_BUCKET=cyberpulse-backups

# Azure Configuration (optional)
AZURE_STORAGE_CONNECTION_STRING=your-azure-connection-string
AZURE_CONTAINER_NAME=cyberpulse-data

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=notifications@cyberpulse.io
SMTP_PASSWORD=your-smtp-password
SMTP_USE_TLS=true
EMAIL_FROM=CyberPulse Security <notifications@cyberpulse.io>
ALERT_EMAIL_RECIPIENTS=security-team@company.com,admin@company.com

# Threat Intelligence Feeds
THREATINTEL_API_KEY=your-threat-intel-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
SHODAN_API_KEY=your-shodan-api-key
ALIENVAULT_API_KEY=your-alienvault-api-key

# External Services
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
PAGERDUTY_API_KEY=your-pagerduty-api-key
SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id

# Monitoring
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
GRAFANA_API_KEY=your-grafana-api-key
ELASTICSEARCH_URL=http://localhost:9200
KIBANA_URL=http://localhost:5601

# Scanner Configuration
NMAP_PATH=/usr/bin/nmap
MASSCAN_PATH=/usr/bin/masscan
NUCLEI_PATH=/usr/local/bin/nuclei
SCAN_TIMEOUT_SECONDS=3600
MAX_CONCURRENT_SCANS=5

# Machine Learning
ML_MODEL_PATH=/app/models
ML_UPDATE_INTERVAL_HOURS=24
ANOMALY_THRESHOLD=0.7
ML_TRAINING_DATA_DAYS=30

# Backup Configuration
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *
BACKUP_RETENTION_DAYS=30
BACKUP_ENCRYPTION_KEY=your-backup-encryption-key

# Feature Flags
FEATURE_REALTIME_ANALYTICS=true
FEATURE_ML_THREAT_DETECTION=true
FEATURE_AUTOMATED_RESPONSE=false
FEATURE_COMPLIANCE_REPORTING=true

# API Keys for Internal Services
INTERNAL_API_KEY=your-internal-api-key-for-service-communication
SCANNER_API_KEY=your-scanner-service-api-key

# Vault Configuration (for production secrets management)
VAULT_ENABLED=false
VAULT_URL=https://vault.company.com
VAULT_TOKEN=your-vault-token
VAULT_PATH=secret/data/cyberpulse

# Development Settings (remove in production)
DEV_AUTO_RELOAD=true
DEV_MOCK_EXTERNAL_APIS=false
DEV_SEED_DATABASE=true

# Docker Settings
DOCKER_REGISTRY=ghcr.io
DOCKER_IMAGE_TAG=latest

# Kubernetes Settings
K8S_NAMESPACE=cyberpulse
K8S_CONFIG_PATH=/etc/kubernetes/config

# Celery Configuration
CELERY_BROKER_URL=redis://:your-redis-password@localhost:6379/0
CELERY_RESULT_BACKEND=redis://:your-redis-password@localhost:6379/1
CELERY_TASK_SERIALIZER=json
CELERY_RESULT_SERIALIZER=json
CELERY_ACCEPT_CONTENT=json
CELERY_TIMEZONE=UTC
CELERY_ENABLE_UTC=true
CELERYD_MAX_TASKS_PER_CHILD=1000

# Flower (Celery Monitoring)
FLOWER_USER=admin
FLOWER_PASSWORD=your-flower-password
FLOWER_PORT=5555

# MinIO (S3-compatible storage)
MINIO_USER=minioadmin
MINIO_PASSWORD=your-minio-password
MINIO_ENDPOINT=localhost:9000
MINIO_USE_SSL=false

# Performance Settings
WORKER_COUNT=4
WORKER_CLASS=uvicorn.workers.UvicornWorker
WORKER_TIMEOUT=300
KEEPALIVE=5

# Compliance Settings
COMPLIANCE_MODE=SOC2,HIPAA,PCI-DSS
AUDIT_LOG_RETENTION_DAYS=2555
DATA_RETENTION_DAYS=365
PII_ENCRYPTION_ENABLED=true

# Geographic Restrictions
ALLOWED_COUNTRIES=US,CA,GB,AU
BLOCKED_IPS=192.168.1.100,10.0.0.50
GEO_IP_DATABASE_PATH=/app/data/GeoLite2-City.mmdb

# Session Management
SESSION_TIMEOUT_MINUTES=30
SESSION_EXTENSION_ENABLED=true
MAX_SESSIONS_PER_USER=3

# Password Policy
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_HISTORY_COUNT=5
PASSWORD_EXPIRY_DAYS=90

# Two-Factor Authentication
TFA_ISSUER=CyberPulse
TFA_QR_CODE_ENABLED=true
TFA_BACKUP_CODES_COUNT=10

# API Documentation
API_DOCS_ENABLED=true
API_DOCS_URL=/docs
API_REDOC_URL=/redoc
API_OPENAPI_URL=/openapi.json

# Custom Branding
COMPANY_NAME=CyberPulse Analytics
COMPANY_LOGO_URL=/static/logo.png
SUPPORT_EMAIL=support@cyberpulse.io
SUPPORT_URL=https://support.cyberpulse.io