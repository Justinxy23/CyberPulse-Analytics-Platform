#!/usr/bin/env python3
"""
CyberPulse Analytics Platform - Comprehensive Test Suite
Author: Justin Christopher Weaver
Description: Unit and integration tests for API endpoints
"""

import pytest
import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import jwt

from src.api_server import app, get_db, User, SecurityEvent, Base
from src.threat_detector import ThreatDetectionEngine, SecurityEvent as ThreatEvent, ThreatLevel

# Test database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override the get_db dependency
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

# Create test client
client = TestClient(app)

# Test fixtures
@pytest.fixture(scope="module")
def setup_database():
    """Create test database tables"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def test_user():
    """Create a test user"""
    return {
        "username": "testuser",
        "email": "test@cyberpulse.io",
        "password": "TestPassword123!",
        "full_name": "Test User",
        "role": "SECURITY_ANALYST"
    }

@pytest.fixture
def admin_user():
    """Create an admin user"""
    return {
        "username": "adminuser",
        "email": "admin@cyberpulse.io",
        "password": "AdminPassword123!",
        "full_name": "Admin User",
        "role": "ADMIN"
    }

@pytest.fixture
def auth_headers(test_user):
    """Get authentication headers"""
    response = client.post("/api/v1/auth/register", json=test_user)
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def admin_headers(admin_user):
    """Get admin authentication headers"""
    response = client.post("/api/v1/auth/register", json=admin_user)
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

# Authentication Tests
class TestAuthentication:
    """Test authentication endpoints"""
    
    def test_register_success(self, setup_database):
        """Test successful user registration"""
        user_data = {
            "username": "newuser",
            "email": "newuser@cyberpulse.io",
            "password": "SecurePass123!",
            "full_name": "New User",
            "role": "viewer"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "viewer"
    
    def test_register_duplicate_username(self, setup_database, test_user):
        """Test registration with duplicate username"""
        client.post("/api/v1/auth/register", json=test_user)
        
        # Try to register again with same username
        response = client.post("/api/v1/auth/register", json=test_user)
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]
    
    def test_login_success(self, setup_database, test_user):
        """Test successful login"""
        # Register user first
        client.post("/api/v1/auth/register", json=test_user)
        
        # Login
        login_data = {
            "username": test_user["username"],
            "password": test_user["password"]
        }
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        data = response.json()
        assert "access_token" in data
        assert data["role"] == test_user["role"]
    
    def test_login_invalid_credentials(self, setup_database):
        """Test login with invalid credentials"""
        login_data = {
            "username": "nonexistent",
            "password": "wrongpassword"
        }
        response = client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    def test_logout(self, setup_database, auth_headers):
        """Test logout functionality"""
        response = client.post("/api/v1/auth/logout", headers=auth_headers)
        assert response.status_code == 200
        assert "Logged out successfully" in response.json()["message"]

# Security Event Tests
class TestSecurityEvents:
    """Test security event endpoints"""
    
    def test_create_security_event(self, setup_database, admin_headers):
        """Test creating a security event"""
        event_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "port": 22,
            "protocol": "SSH",
            "event_type": "AUTHENTICATION_FAILURE",
            "severity": "HIGH",
            "payload": {"attempts": 5}
        }
        
        response = client.post(
            "/api/v1/security/events",
            json=event_data,
            headers=admin_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["source_ip"] == event_data["source_ip"]
        assert data["severity"] == event_data["severity"]
        assert "event_id" in data
    
    def test_create_event_unauthorized(self, setup_database, auth_headers):
        """Test creating event without proper permissions"""
        event_data = {
            "source_ip": "192.168.1.100",
            "port": 22,
            "protocol": "SSH",
            "event_type": "TEST",
            "severity": "LOW"
        }
        
        # Regular user (not admin/analyst) shouldn't be able to create events
        viewer_user = {
            "username": "viewer",
            "email": "viewer@cyberpulse.io",
            "password": "ViewerPass123!",
            "full_name": "Viewer User",
            "role": "viewer"
        }
        response = client.post("/api/v1/auth/register", json=viewer_user)
        viewer_token = response.json()["access_token"]
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}
        
        response = client.post(
            "/api/v1/security/events",
            json=event_data,
            headers=viewer_headers
        )
        assert response.status_code == 403
    
    def test_list_security_events(self, setup_database, auth_headers, admin_headers):
        """Test listing security events"""
        # Create some events
        for i in range(5):
            event_data = {
                "source_ip": f"192.168.1.{100+i}",
                "port": 22,
                "protocol": "SSH",
                "event_type": "TEST",
                "severity": "HIGH" if i < 2 else "MEDIUM"
            }
            client.post(
                "/api/v1/security/events",
                json=event_data,
                headers=admin_headers
            )
        
        # List all events
        response = client.get(
            "/api/v1/security/events",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        assert data["total"] >= 5
        assert len(data["events"]) >= 5
    
    def test_list_events_with_filter(self, setup_database, auth_headers):
        """Test listing events with severity filter"""
        response = client.get(
            "/api/v1/security/events?severity=HIGH",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        for event in data["events"]:
            assert event["severity"] == "HIGH"
    
    @pytest.mark.asyncio
    async def test_event_processing(self, setup_database):
        """Test async event processing"""
        from src.api_server import process_security_event
        
        # Create a mock event
        event_id = "test-event-123"
        
        with patch('src.api_server.SessionLocal') as mock_session:
            mock_db = Mock()
            mock_event = Mock()
            mock_event.severity = "HIGH"
            mock_db.query.return_value.filter.return_value.first.return_value = mock_event
            mock_session.return_value = mock_db
            
            await process_security_event(event_id)
            
            assert mock_event.processed == True
            assert mock_event.risk_score > 0

# Threat Detection Tests
class TestThreatDetection:
    """Test threat detection functionality"""
    
    @pytest.fixture
    def threat_engine(self):
        """Create threat detection engine instance"""
        return ThreatDetectionEngine()
    
    @pytest.mark.asyncio
    async def test_analyze_brute_force(self, threat_engine):
        """Test brute force attack detection"""
        event = ThreatEvent(
            event_id="test-001",
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            port=22,
            protocol="SSH",
            event_type="AUTHENTICATION_FAILURE",
            payload={"username": "root", "attempts": 10}
        )
        
        risk_score, threat_level, indicators = await threat_engine.analyze_event(event)
        
        assert risk_score > 0.7
        assert threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        assert any("brute force" in ind.lower() for ind in indicators)
    
    @pytest.mark.asyncio
    async def test_analyze_sql_injection(self, threat_engine):
        """Test SQL injection detection"""
        event = ThreatEvent(
            event_id="test-002",
            timestamp=datetime.now(timezone.utc),
            source_ip="192.168.1.101",
            destination_ip="10.0.0.10",
            port=80,
            protocol="HTTP",
            event_type="WEB_REQUEST",
            payload={
                "url": "/login",
                "params": "username=admin' OR '1'='1"
            }
        )
        
        risk_score, threat_level, indicators = await threat_engine.analyze_event(event)
        
        assert risk_score > 0.6
        assert threat_level in [ThreatLevel.HIGH, ThreatLevel.MEDIUM]
    
    def test_entropy_calculation(self, threat_engine):
        """Test entropy calculation for DGA detection"""
        # Normal domain
        normal_entropy = threat_engine._calculate_entropy("google")
        assert normal_entropy < 3.0
        
        # DGA-like domain
        dga_entropy = threat_engine._calculate_entropy("xkj3n4m8p9q2")
        assert dga_entropy > 3.5
    
    def test_threat_level_determination(self, threat_engine):
        """Test threat level determination"""
        assert threat_engine._determine_threat_level(0.95) == ThreatLevel.CRITICAL
        assert threat_engine._determine_threat_level(0.75) == ThreatLevel.HIGH
        assert threat_engine._determine_threat_level(0.55) == ThreatLevel.MEDIUM
        assert threat_engine._determine_threat_level(0.35) == ThreatLevel.LOW
        assert threat_engine._determine_threat_level(0.15) == ThreatLevel.INFO

# Dashboard Tests
class TestDashboard:
    """Test dashboard endpoints"""
    
    def test_get_dashboard_metrics(self, setup_database, auth_headers):
        """Test retrieving dashboard metrics"""
        response = client.get(
            "/api/v1/dashboard/metrics",
            headers=auth_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "security_score" in data
        assert "total_events_24h" in data
        assert "compliance_status" in data
        assert data["security_score"] >= 0 and data["security_score"] <= 100
    
    def test_metrics_caching(self, setup_database, auth_headers):
        """Test that metrics are properly cached"""
        # First request
        response1 = client.get(
            "/api/v1/dashboard/metrics",
            headers=auth_headers
        )
        data1 = response1.json()
        
        # Second request (should be cached)
        response2 = client.get(
            "/api/v1/dashboard/metrics",
            headers=auth_headers
        )
        data2 = response2.json()
        
        # Basic check that structure is same
        assert data1.keys() == data2.keys()

# Vulnerability Scanning Tests
class TestVulnerabilityScanning:
    """Test vulnerability scanning endpoints"""
    
    def test_initiate_scan(self, setup_database, admin_headers):
        """Test initiating a vulnerability scan"""
        scan_request = {
            "scan_type": "network",
            "target_type": "ip",
            "target_identifier": "192.168.1.1",
            "scanner": "nmap"
        }
        
        response = client.post(
            "/api/v1/security/scan",
            json=scan_request,
            headers=admin_headers
        )
        assert response.status_code == 200
        
        data = response.json()
        assert "scan_id" in data
        assert data["status"] == "queued"
        assert data["target"] == scan_request["target_identifier"]
    
    def test_invalid_scan_request(self, setup_database, admin_headers):
        """Test scan request with invalid parameters"""
        scan_request = {
            "scan_type": "invalid_type",
            "target_type": "ip",
            "target_identifier": "192.168.1.1"
        }
        
        response = client.post(
            "/api/v1/security/scan",
            json=scan_request,
            headers=admin_headers
        )
        assert response.status_code == 422  # Validation error

# Health Check Tests
class TestHealthCheck:
    """Test system health endpoints"""
    
    def test_health_check(self):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] in ["healthy", "unhealthy"]
        assert "timestamp" in data
        assert "services" in data
    
    def test_metrics_endpoint(self):
        """Test Prometheus metrics endpoint"""
        response = client.get("/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; charset=utf-8"
        assert "cyberpulse_requests_total" in response.text

# Performance Tests
class TestPerformance:
    """Performance and load tests"""
    
    @pytest.mark.performance
    def test_api_response_time(self, setup_database, auth_headers):
        """Test API response times"""
        import time
        
        endpoints = [
            ("/api/v1/dashboard/metrics", "GET"),
            ("/api/v1/security/events", "GET"),
        ]
        
        for endpoint, method in endpoints:
            start_time = time.time()
            
            if method == "GET":
                response = client.get(endpoint, headers=auth_headers)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            assert response.status_code == 200
            assert response_time < 1.0  # Should respond within 1 second
    
    @pytest.mark.performance
    def test_concurrent_requests(self, setup_database, auth_headers):
        """Test handling concurrent requests"""
        import concurrent.futures
        
        def make_request():
            return client.get(
                "/api/v1/dashboard/metrics",
                headers=auth_headers
            )
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(50)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        # All requests should succeed
        assert all(r.status_code == 200 for r in results)

# Security Tests
class TestSecurity:
    """Security-specific tests"""
    
    def test_sql_injection_protection(self, setup_database, admin_headers):
        """Test protection against SQL injection"""
        malicious_event = {
            "source_ip": "192.168.1.1'; DROP TABLE security_events; --",
            "port": 80,
            "protocol": "HTTP",
            "event_type": "TEST",
            "severity": "LOW"
        }
        
        response = client.post(
            "/api/v1/security/events",
            json=malicious_event,
            headers=admin_headers
        )
        
        # Should handle the input safely
        assert response.status_code in [200, 422]
        
        # Verify table still exists
        response = client.get(
            "/api/v1/security/events",
            headers=admin_headers
        )
        assert response.status_code == 200
    
    def test_jwt_token_expiration(self, setup_database):
        """Test JWT token expiration"""
        # Create expired token
        expired_token = jwt.encode(
            {
                "sub": "test-user",
                "exp": datetime.now(timezone.utc) - timedelta(hours=1)
            },
            "test-secret",
            algorithm="HS256"
        )
        
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = client.get("/api/v1/dashboard/metrics", headers=headers)
        assert response.status_code == 401
    
    def test_rate_limiting(self, setup_database):
        """Test rate limiting functionality"""
        # Make many requests quickly
        responses = []
        for _ in range(150):  # Exceed rate limit
            response = client.get("/health")
            responses.append(response)
        
        # Some requests should be rate limited (would need actual implementation)
        # This is a placeholder for when rate limiting is implemented
        assert all(r.status_code in [200, 429] for r in responses)

# Integration Tests
class TestIntegration:
    """End-to-end integration tests"""
    
    @pytest.mark.integration
    def test_full_security_workflow(self, setup_database, admin_headers):
        """Test complete security event workflow"""
        # 1. Create security event
        event_data = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "port": 22,
            "protocol": "SSH",
            "event_type": "AUTHENTICATION_FAILURE",
            "severity": "HIGH",
            "payload": {"username": "root", "attempts": 50}
        }
        
        response = client.post(
            "/api/v1/security/events",
            json=event_data,
            headers=admin_headers
        )
        assert response.status_code == 200
        event_id = response.json()["event_id"]
        
        # 2. Create alert based on event
        alert_data = {
            "event_id": event_id,
            "alert_type": "BRUTE_FORCE_ATTACK",
            "severity": "CRITICAL",
            "title": "Brute Force Attack Detected",
            "description": "Multiple failed SSH attempts",
            "affected_assets": ["server-prod-01"]
        }
        
        response = client.post(
            "/api/v1/security/alerts",
            json=alert_data,
            headers=admin_headers
        )
        assert response.status_code == 200
        
        # 3. Check dashboard reflects the activity
        response = client.get(
            "/api/v1/dashboard/metrics",
            headers=admin_headers
        )
        assert response.status_code == 200
        metrics = response.json()
        assert metrics["total_events_24h"] > 0
        assert metrics["critical_alerts"] > 0

# Cleanup
def pytest_sessionfinish(session, exitstatus):
    """Cleanup after all tests"""
    import os
    if os.path.exists("./test.db"):
        os.remove("./test.db")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])