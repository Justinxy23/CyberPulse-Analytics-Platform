# CyberPulse Analytics Platform API Documentation

## Table of Contents
- [Overview](#overview)
- [Authentication](#authentication)
- [API Endpoints](#api-endpoints)
  - [Authentication Endpoints](#authentication-endpoints)
  - [Security Operations](#security-operations)
  - [Vulnerability Management](#vulnerability-management)
  - [Project Management](#project-management)
  - [Dashboard & Analytics](#dashboard--analytics)
  - [System Administration](#system-administration)
- [WebSocket Events](#websocket-events)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Code Examples](#code-examples)

## Overview

The CyberPulse Analytics Platform API provides comprehensive security operations, project management, and analytics capabilities. All API requests should be made to:

**Base URL**: `https://api.cyberpulse.io/api/v1`

**API Version**: 1.0.0

### Request/Response Format
- All requests and responses are in JSON format
- Timestamps are in ISO 8601 format with timezone
- All endpoints require authentication unless specified

## Authentication

CyberPulse uses JWT (JSON Web Tokens) for authentication.

### Obtaining a Token

```http
POST /auth/login
Content-Type: application/json

{
  "username": "your_username",
  "password": "your_password"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 86400,
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "role": "SECURITY_ANALYST"
}
```

### Using the Token

Include the token in the Authorization header:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

## API Endpoints

### Authentication Endpoints

#### Register New User
```http
POST /auth/register
```

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john.doe@company.com",
  "password": "SecurePassword123!",
  "full_name": "John Doe",
  "role": "viewer",
  "department": "IT Security"
}
```

**Response:** Same as login response

#### Logout
```http
POST /auth/logout
Authorization: Bearer {token}
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

### Security Operations

#### Create Security Event
```http
POST /security/events
Authorization: Bearer {token}
```

**Request Body:**
```json
{
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.5",
  "port": 22,
  "protocol": "SSH",
  "event_type": "AUTHENTICATION_FAILURE",
  "severity": "HIGH",
  "payload": {
    "username": "root",
    "attempts": 5
  }
}
```

**Response:**
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440001",
  "timestamp": "2024-01-15T10:30:00Z",
  "source_ip": "192.168.1.100",
  "destination_ip": "10.0.0.5",
  "port": 22,
  "protocol": "SSH",
  "event_type": "AUTHENTICATION_FAILURE",
  "severity": "HIGH",
  "risk_score": 0.75,
  "processed": false
}
```

#### List Security Events
```http
GET /security/events?skip=0&limit=100&severity=HIGH
Authorization: Bearer {token}
```

**Query Parameters:**
- `skip` (optional): Number of records to skip (default: 0)
- `limit` (optional): Maximum records to return (default: 100, max: 1000)
- `severity` (optional): Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- `start_date` (optional): Filter events after this date (ISO 8601)
- `end_date` (optional): Filter events before this date (ISO 8601)

**Response:**
```json
{
  "total": 250,
  "skip": 0,
  "limit": 100,
  "events": [
    {
      "event_id": "550e8400-e29b-41d4-a716-446655440001",
      "timestamp": "2024-01-15T10:30:00Z",
      "source_ip": "192.168.1.100",
      "destination_ip": "10.0.0.5",
      "port": 22,
      "protocol": "SSH",
      "event_type": "AUTHENTICATION_FAILURE",
      "severity": "HIGH",
      "risk_score": 0.75,
      "processed": true
    }
  ]
}
```

#### Create Security Alert
```http
POST /security/alerts
Authorization: Bearer {token}
```

**Request Body:**
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440001",
  "alert_type": "BRUTE_FORCE_ATTACK",
  "severity": "CRITICAL",
  "title": "Brute Force Attack Detected",
  "description": "Multiple failed SSH login attempts from suspicious IP",
  "affected_assets": ["server-01", "server-02"]
}
```

### Vulnerability Management

#### Initiate Vulnerability Scan
```http
POST /security/scan
Authorization: Bearer {token}
```

**Request Body:**
```json
{
  "scan_type": "network",
  "target_type": "cidr",
  "target_identifier": "192.168.1.0/24",
  "scanner": "nmap"
}
```

**Response:**
```json
{
  "scan_id": "scan_123456",
  "status": "queued",
  "estimated_duration": "15-30 minutes",
  "target": "192.168.1.0/24"
}
```

#### Get Scan Results
```http
GET /security/scan/{scan_id}
Authorization: Bearer {token}
```

**Response:**
```json
{
  "scan_id": "scan_123456",
  "status": "completed",
  "started_at": "2024-01-15T10:00:00Z",
  "completed_at": "2024-01-15T10:25:00Z",
  "findings": [
    {
      "severity": "HIGH",
      "title": "Outdated SSL/TLS version",
      "affected_host": "192.168.1.10",
      "port": 443,
      "description": "Server supports TLS 1.0 which is deprecated",
      "remediation": "Update to TLS 1.2 or higher"
    }
  ],
  "statistics": {
    "hosts_scanned": 254,
    "hosts_up": 45,
    "total_vulnerabilities": 23,
    "critical": 2,
    "high": 5,
    "medium": 10,
    "low": 6
  }
}
```

### Project Management

#### Create Project
```http
POST /projects
Authorization: Bearer {token}
```

**Request Body:**
```json
{
  "project_name": "Security Infrastructure Upgrade",
  "project_code": "SEC-2024-001",
  "description": "Upgrade security monitoring infrastructure",
  "start_date": "2024-02-01T00:00:00Z",
  "end_date": "2024-06-30T00:00:00Z",
  "budget": 150000.00,
  "team_members": ["user1", "user2", "user3"]
}
```

#### Create Task
```http
POST /tasks
Authorization: Bearer {token}
```

**Request Body:**
```json
{
  "project_id": "proj_123",
  "sprint_id": "sprint_456",
  "task_type": "feature",
  "title": "Implement real-time threat detection",
  "description": "Develop ML-based threat detection system",
  "priority": "HIGH",
  "story_points": 8,
  "assigned_to": "user123"
}
```

### Dashboard & Analytics

#### Get Dashboard Metrics
```http
GET /dashboard/metrics
Authorization: Bearer {token}
```

**Response:**
```json
{
  "security_score": 87.5,
  "total_events_24h": 1523,
  "critical_alerts": 3,
  "open_vulnerabilities": 45,
  "compliance_status": {
    "SOC2": 95.0,
    "HIPAA": 88.0,
    "PCI-DSS": 76.0
  },
  "project_completion": 72.5,
  "active_threats": [
    {
      "threat_id": "threat_001",
      "type": "BRUTE_FORCE",
      "source": "45.155.205.86",
      "target": "SSH Service",
      "first_seen": "2024-01-15T08:00:00Z",
      "event_count": 150
    }
  ],
  "system_health": {
    "cpu_usage": 45.2,
    "memory_usage": 62.8,
    "disk_usage": 38.5,
    "network_latency": 12.3
  }
}
```

#### Get Analytics Report
```http
POST /analytics/report
Authorization: Bearer {token}
```

**Request Body:**
```json
{
  "report_type": "security_summary",
  "period": "weekly",
  "start_date": "2024-01-08T00:00:00Z",
  "end_date": "2024-01-15T00:00:00Z",
  "include_sections": ["threats", "vulnerabilities", "compliance", "incidents"]
}
```

### System Administration

#### Get System Health
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "services": {
    "database": "healthy",
    "redis": "healthy",
    "elasticsearch": "healthy"
  },
  "version": "1.0.0"
}
```

#### Get System Metrics (Prometheus Format)
```http
GET /metrics
```

## WebSocket Events

Connect to real-time updates:
```javascript
const ws = new WebSocket('wss://api.cyberpulse.io/ws');

ws.on('message', (data) => {
  const event = JSON.parse(data);
  console.log('Received:', event);
});
```

### Event Types

**Security Event:**
```json
{
  "channel": "security_events",
  "data": {
    "event_id": "evt_123",
    "severity": "HIGH",
    "source_ip": "192.168.1.100",
    "event_type": "INTRUSION_ATTEMPT"
  }
}
```

**Security Alert:**
```json
{
  "channel": "security_alerts",
  "data": {
    "alert_id": "alert_456",
    "severity": "CRITICAL",
    "title": "Active Ransomware Detected"
  }
}
```

**Project Update:**
```json
{
  "channel": "project_updates",
  "data": {
    "type": "task_completed",
    "task_id": "task_789",
    "project_id": "proj_123",
    "completed_by": "user456"
  }
}
```

## Error Handling

All errors follow a consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    },
    "request_id": "req_123456"
  }
}
```

### Common Error Codes

| HTTP Status | Error Code | Description |
|-------------|------------|-------------|
| 400 | VALIDATION_ERROR | Invalid request data |
| 401 | UNAUTHORIZED | Missing or invalid authentication |
| 403 | FORBIDDEN | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 429 | RATE_LIMITED | Too many requests |
| 500 | INTERNAL_ERROR | Server error |

## Rate Limiting

API requests are rate limited to ensure fair usage:

- **Authenticated requests**: 1000 requests per hour
- **Unauthenticated requests**: 100 requests per hour
- **Burst limit**: 50 requests per minute

Rate limit information is included in response headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 998
X-RateLimit-Reset: 1642248000
```

## Code Examples

### Python Example
```python
import requests
import json

class CyberPulseClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.token = self._authenticate(username, password)
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    def _authenticate(self, username, password):
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"username": username, "password": password}
        )
        response.raise_for_status()
        return response.json()["access_token"]
    
    def create_security_event(self, event_data):
        response = requests.post(
            f"{self.base_url}/security/events",
            headers=self.headers,
            json=event_data
        )
        response.raise_for_status()
        return response.json()
    
    def get_dashboard_metrics(self):
        response = requests.get(
            f"{self.base_url}/dashboard/metrics",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()

# Usage
client = CyberPulseClient(
    "https://api.cyberpulse.io/api/v1",
    "your_username",
    "your_password"
)

# Create security event
event = client.create_security_event({
    "source_ip": "192.168.1.100",
    "port": 22,
    "protocol": "SSH",
    "event_type": "AUTHENTICATION_FAILURE",
    "severity": "HIGH"
})

print(f"Event created: {event['event_id']}")

# Get dashboard metrics
metrics = client.get_dashboard_metrics()
print(f"Security Score: {metrics['security_score']}")
```

### JavaScript/Node.js Example
```javascript
const axios = require('axios');

class CyberPulseClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl;
    this.token = null;
  }

  async authenticate(username, password) {
    const response = await axios.post(`${this.baseUrl}/auth/login`, {
      username,
      password
    });
    this.token = response.data.access_token;
    axios.defaults.headers.common['Authorization'] = `Bearer ${this.token}`;
  }

  async createSecurityEvent(eventData) {
    const response = await axios.post(
      `${this.baseUrl}/security/events`,
      eventData
    );
    return response.data;
  }

  async getDashboardMetrics() {
    const response = await axios.get(`${this.baseUrl}/dashboard/metrics`);
    return response.data;
  }
}

// Usage
const client = new CyberPulseClient('https://api.cyberpulse.io/api/v1');

(async () => {
  await client.authenticate('your_username', 'your_password');
  
  const event = await client.createSecurityEvent({
    source_ip: '192.168.1.100',
    port: 22,
    protocol: 'SSH',
    event_type: 'AUTHENTICATION_FAILURE',
    severity: 'HIGH'
  });
  
  console.log(`Event created: ${event.event_id}`);
  
  const metrics = await client.getDashboardMetrics();
  console.log(`Security Score: ${metrics.security_score}`);
})();
```

### cURL Examples

**Login:**
```bash
curl -X POST https://api.cyberpulse.io/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your_username","password":"your_password"}'
```

**Create Security Event:**
```bash
curl -X POST https://api.cyberpulse.io/api/v1/security/events \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "port": 22,
    "protocol": "SSH",
    "event_type": "AUTHENTICATION_FAILURE",
    "severity": "HIGH"
  }'
```

**Get Dashboard Metrics:**
```bash
curl -X GET https://api.cyberpulse.io/api/v1/dashboard/metrics \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## Support

For API support, please contact:
- Email: api-support@cyberpulse.io
- Documentation: https://docs.cyberpulse.io
- Status Page: https://status.cyberpulse.io

---

*Last Updated: January 2024*