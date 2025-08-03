#!/usr/bin/env python3
"""
CyberPulse Analytics Platform - RESTful API Server
Author: Justin Christopher Weaver
Description: FastAPI-based backend for security operations and analytics
"""

import os
import json
import asyncio
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Security, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, EmailStr, validator
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Boolean, JSON, ForeignKey, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.dialects.postgresql import UUID
import jwt
import redis
from prometheus_client import Counter, Histogram, Gauge, generate_latest
import aiohttp
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add rotating file handler
file_handler = RotatingFileHandler('cyberpulse_api.log', maxBytes=10485760, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# Environment configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://cyberpulse_admin:password@localhost/cyberpulse")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Prometheus metrics
request_count = Counter('cyberpulse_requests_total', 'Total requests', ['method', 'endpoint'])
request_duration = Histogram('cyberpulse_request_duration_seconds', 'Request duration', ['method', 'endpoint'])
active_users = Gauge('cyberpulse_active_users', 'Number of active users')
security_score = Gauge('cyberpulse_security_score', 'Current security score')

# Database setup
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Redis client
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

# Security
security = HTTPBearer()

# Pydantic models
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str
    role: str = Field(default="viewer")
    department: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: str
    role: str

class SecurityEventCreate(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = None
    port: int
    protocol: str
    event_type: str
    severity: str = Field(..., regex="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    payload: Dict[str, Any] = {}

class SecurityEventResponse(BaseModel):
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str]
    port: int
    protocol: str
    event_type: str
    severity: str
    risk_score: float
    processed: bool

class AlertCreate(BaseModel):
    event_id: Optional[str] = None
    alert_type: str
    severity: str = Field(..., regex="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    title: str
    description: Optional[str] = None
    affected_assets: List[str] = []

class VulnerabilityScanRequest(BaseModel):
    scan_type: str = Field(..., regex="^(network|web|infrastructure|full)$")
    target_type: str = Field(..., regex="^(ip|hostname|cidr|url)$")
    target_identifier: str
    scanner: str = Field(default="internal")

class ProjectCreate(BaseModel):
    project_name: str
    project_code: str = Field(..., regex="^[A-Z0-9-]+$")
    description: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    budget: Optional[float] = None
    team_members: List[str] = []

class TaskCreate(BaseModel):
    project_id: str
    sprint_id: Optional[str] = None
    task_type: str = Field(..., regex="^(bug|feature|task|epic)$")
    title: str
    description: Optional[str] = None
    priority: str = Field(default="MEDIUM", regex="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    story_points: Optional[int] = Field(None, ge=1, le=21)
    assigned_to: Optional[str] = None

class DashboardMetrics(BaseModel):
    security_score: float
    total_events_24h: int
    critical_alerts: int
    open_vulnerabilities: int
    compliance_status: Dict[str, float]
    project_completion: float
    active_threats: List[Dict[str, Any]]
    system_health: Dict[str, Any]

# Database models
class User(Base):
    __tablename__ = "users"
    
    user_id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)
    department = Column(String(100))
    password_hash = Column(String(255), nullable=False)
    mfa_enabled = Column(Boolean, default=False)
    last_login = Column(DateTime(timezone=True))
    active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"))

class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    event_id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    timestamp = Column(DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP"))
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(20), nullable=False)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    risk_score = Column(Float, default=0.0)
    payload = Column(JSON)
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=text("CURRENT_TIMESTAMP"))

# Dependency injection
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    """Validate JWT token and return current user"""
    token = credentials.credentials
    
    try:
        # Check if token is blacklisted
        if redis_client.sismember("blacklisted_tokens", token):
            raise HTTPException(status_code=401, detail="Token has been revoked")
        
        # Decode token
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get user from database
        user = db.query(User).filter(User.user_id == user_id).first()
        if user is None or not user.active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        
        return user
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_role(required_roles: List[str]):
    """Role-based access control decorator"""
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in required_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required roles: {required_roles}"
            )
        return current_user
    return role_checker

# Lifespan manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events"""
    # Startup
    logger.info("Starting CyberPulse API Server...")
    
    # Initialize database tables
    Base.metadata.create_all(bind=engine)
    
    # Start background tasks
    asyncio.create_task(update_metrics_task())
    asyncio.create_task(process_security_events_task())
    
    logger.info("CyberPulse API Server started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down CyberPulse API Server...")
    
    # Clean up resources
    redis_client.close()
    
    logger.info("CyberPulse API Server shutdown complete")

# Create FastAPI app
app = FastAPI(
    title="CyberPulse Analytics Platform API",
    description="Security Operations Center and Project Intelligence API",
    version="1.0.0",
    contact={
        "name": "Justin Christopher Weaver",
        "email": "contact@cyberpulse.io",
    },
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware for metrics
@app.middleware("http")
async def metrics_middleware(request, call_next):
    """Track request metrics"""
    start_time = datetime.now()
    
    # Track request
    request_count.labels(method=request.method, endpoint=request.url.path).inc()
    
    # Process request
    response = await call_next(request)
    
    # Track duration
    duration = (datetime.now() - start_time).total_seconds()
    request_duration.labels(method=request.method, endpoint=request.url.path).observe(duration)
    
    return response

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check database
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_status = "healthy"
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
    
    # Check Redis
    try:
        redis_client.ping()
        redis_status = "healthy"
    except Exception as e:
        redis_status = f"unhealthy: {str(e)}"
    
    return {
        "status": "healthy" if db_status == "healthy" and redis_status == "healthy" else "unhealthy",
        "timestamp": datetime.now(timezone.utc),
        "services": {
            "database": db_status,
            "redis": redis_status
        }
    }

# Authentication endpoints
@app.post("/api/v1/auth/register", response_model=TokenResponse)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user"""
    # Check if user already exists
    if db.query(User).filter((User.username == user_data.username) | (User.email == user_data.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")
    
    # Hash password
    password_hash = hashlib.sha256(user_data.password.encode()).hexdigest()
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        department=user_data.department,
        password_hash=password_hash
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Generate token
    token_data = {
        "sub": str(user.user_id),
        "username": user.username,
        "role": user.role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    
    access_token = jwt.encode(token_data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Update active users metric
    active_users.inc()
    
    return TokenResponse(
        access_token=access_token,
        expires_in=JWT_EXPIRATION_HOURS * 3600,
        user_id=str(user.user_id),
        role=user.role
    )

@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return JWT token"""
    # Find user
    user = db.query(User).filter(User.username == credentials.username).first()
    
    if not user or not user.active:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    password_hash = hashlib.sha256(credentials.password.encode()).hexdigest()
    if password_hash != user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    
    # Generate token
    token_data = {
        "sub": str(user.user_id),
        "username": user.username,
        "role": user.role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    
    access_token = jwt.encode(token_data, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Cache user session
    redis_client.setex(
        f"session:{user.user_id}",
        JWT_EXPIRATION_HOURS * 3600,
        json.dumps({"username": user.username, "role": user.role})
    )
    
    # Update metrics
    active_users.inc()
    
    logger.info(f"User {user.username} logged in successfully")
    
    return TokenResponse(
        access_token=access_token,
        expires_in=JWT_EXPIRATION_HOURS * 3600,
        user_id=str(user.user_id),
        role=user.role
    )

@app.post("/api/v1/auth/logout")
async def logout(current_user: User = Depends(get_current_user), credentials: HTTPAuthorizationCredentials = Security(security)):
    """Logout user and blacklist token"""
    token = credentials.credentials
    
    # Add token to blacklist
    redis_client.sadd("blacklisted_tokens", token)
    redis_client.expire("blacklisted_tokens", JWT_EXPIRATION_HOURS * 3600)
    
    # Remove session
    redis_client.delete(f"session:{current_user.user_id}")
    
    # Update metrics
    active_users.dec()
    
    logger.info(f"User {current_user.username} logged out")
    
    return {"message": "Logged out successfully"}

# Security endpoints
@app.post("/api/v1/security/events", response_model=SecurityEventResponse)
async def create_security_event(
    event: SecurityEventCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["ADMIN", "SECURITY_ANALYST"]))
):
    """Create a new security event"""
    # Create event in database
    db_event = SecurityEvent(
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        port=event.port,
        protocol=event.protocol,
        event_type=event.event_type,
        severity=event.severity,
        payload=event.payload
    )
    
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    
    # Queue for processing
    background_tasks.add_task(process_security_event, str(db_event.event_id))
    
    # Publish to Redis for real-time updates
    redis_client.publish("security_events", json.dumps({
        "event_id": str(db_event.event_id),
        "severity": event.severity,
        "source_ip": event.source_ip,
        "event_type": event.event_type
    }))
    
    logger.info(f"Security event created: {db_event.event_id}")
    
    return SecurityEventResponse(
        event_id=str(db_event.event_id),
        timestamp=db_event.timestamp,
        source_ip=db_event.source_ip,
        destination_ip=db_event.destination_ip,
        port=db_event.port,
        protocol=db_event.protocol,
        event_type=db_event.event_type,
        severity=db_event.severity,
        risk_score=db_event.risk_score,
        processed=db_event.processed
    )

@app.get("/api/v1/security/events")
async def list_security_events(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List security events with filtering"""
    query = db.query(SecurityEvent)
    
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    
    total = query.count()
    events = query.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "events": [
            SecurityEventResponse(
                event_id=str(e.event_id),
                timestamp=e.timestamp,
                source_ip=e.source_ip,
                destination_ip=e.destination_ip,
                port=e.destination_port or e.source_port,
                protocol=e.protocol,
                event_type=e.event_type,
                severity=e.severity,
                risk_score=e.risk_score,
                processed=e.processed
            ) for e in events
        ]
    }

@app.post("/api/v1/security/alerts")
async def create_alert(
    alert: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["ADMIN", "SECURITY_ANALYST"]))
):
    """Create a new security alert"""
    # Implementation would create alert in database
    # For now, return mock response
    alert_id = secrets.token_urlsafe(16)
    
    # Publish alert
    redis_client.publish("security_alerts", json.dumps({
        "alert_id": alert_id,
        "severity": alert.severity,
        "title": alert.title
    }))
    
    logger.warning(f"Security alert created: {alert.title} ({alert.severity})")
    
    return {
        "alert_id": alert_id,
        "status": "created",
        "timestamp": datetime.now(timezone.utc)
    }

@app.post("/api/v1/security/scan")
async def initiate_vulnerability_scan(
    scan_request: VulnerabilityScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_role(["ADMIN", "SECURITY_ANALYST"]))
):
    """Initiate a vulnerability scan"""
    scan_id = secrets.token_urlsafe(16)
    
    # Queue scan for processing
    background_tasks.add_task(
        perform_vulnerability_scan,
        scan_id,
        scan_request.dict()
    )
    
    logger.info(f"Vulnerability scan initiated: {scan_id}")
    
    return {
        "scan_id": scan_id,
        "status": "queued",
        "estimated_duration": "15-30 minutes",
        "target": scan_request.target_identifier
    }

# Dashboard endpoint
@app.get("/api/v1/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get real-time dashboard metrics"""
    # Calculate metrics
    events_24h = db.query(SecurityEvent).filter(
        SecurityEvent.timestamp >= datetime.now(timezone.utc) - timedelta(hours=24)
    ).count()
    
    critical_alerts = db.execute(
        text("SELECT COUNT(*) FROM security_alerts WHERE status = 'OPEN' AND severity = 'CRITICAL'")
    ).scalar() or 0
    
    open_vulns = db.execute(
        text("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'OPEN'")
    ).scalar() or 0
    
    # Get cached security score
    cached_score = redis_client.get("security_score")
    current_score = float(cached_score) if cached_score else 85.0
    
    # Get compliance status
    compliance_status = {
        "SOC2": 95.0,
        "HIPAA": 88.0,
        "PCI-DSS": 76.0
    }
    
    # Get active threats from cache
    active_threats = []
    threat_keys = redis_client.keys("threat:*")
    for key in threat_keys[:5]:  # Top 5 threats
        threat_data = redis_client.get(key)
        if threat_data:
            active_threats.append(json.loads(threat_data))
    
    return DashboardMetrics(
        security_score=current_score,
        total_events_24h=events_24h,
        critical_alerts=critical_alerts,
        open_vulnerabilities=open_vulns,
        compliance_status=compliance_status,
        project_completion=72.5,
        active_threats=active_threats,
        system_health={
            "cpu_usage": 45.2,
            "memory_usage": 62.8,
            "disk_usage": 38.5,
            "network_latency": 12.3
        }
    )

# Project management endpoints
@app.post("/api/v1/projects")
async def create_project(
    project: ProjectCreate,
    current_user: User = Depends(require_role(["ADMIN", "PROJECT_MANAGER"]))
):
    """Create a new project"""
    project_id = secrets.token_urlsafe(16)
    
    logger.info(f"Project created: {project.project_name} ({project.project_code})")
    
    return {
        "project_id": project_id,
        "status": "created",
        "project_code": project.project_code
    }

@app.post("/api/v1/tasks")
async def create_task(
    task: TaskCreate,
    current_user: User = Depends(require_role(["ADMIN", "PROJECT_MANAGER"]))
):
    """Create a new task"""
    task_id = secrets.token_urlsafe(16)
    
    # Publish task update
    redis_client.publish("project_updates", json.dumps({
        "type": "task_created",
        "task_id": task_id,
        "project_id": task.project_id,
        "title": task.title
    }))
    
    return {
        "task_id": task_id,
        "status": "created",
        "assigned_to": task.assigned_to or "unassigned"
    }

# Metrics endpoint for Prometheus
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return StreamingResponse(
        generate_latest(),
        media_type="text/plain"
    )

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket):
    """WebSocket for real-time updates"""
    await websocket.accept()
    
    # Subscribe to Redis channels
    pubsub = redis_client.pubsub()
    pubsub.subscribe("security_events", "security_alerts", "project_updates")
    
    try:
        while True:
            message = pubsub.get_message(ignore_subscribe_messages=True)
            if message:
                await websocket.send_json({
                    "channel": message["channel"],
                    "data": json.loads(message["data"])
                })
            await asyncio.sleep(0.1)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()

# Background tasks
async def process_security_event(event_id: str):
    """Process security event asynchronously"""
    db = SessionLocal()
    try:
        event = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
        if event:
            # Simulate processing
            await asyncio.sleep(2)
            
            # Calculate risk score (simplified)
            risk_score = 0.5
            if event.severity == "CRITICAL":
                risk_score = 0.9
            elif event.severity == "HIGH":
                risk_score = 0.7
            
            event.risk_score = risk_score
            event.processed = True
            db.commit()
            
            logger.info(f"Processed security event {event_id} with risk score {risk_score}")
    finally:
        db.close()

async def perform_vulnerability_scan(scan_id: str, scan_config: dict):
    """Perform vulnerability scan asynchronously"""
    logger.info(f"Starting vulnerability scan {scan_id}")
    
    # Simulate scan (in production, integrate with actual scanners)
    await asyncio.sleep(30)
    
    # Store results in cache
    results = {
        "scan_id": scan_id,
        "status": "completed",
        "findings": [
            {"severity": "HIGH", "title": "Outdated SSL/TLS version"},
            {"severity": "MEDIUM", "title": "Missing security headers"},
            {"severity": "LOW", "title": "Information disclosure in error pages"}
        ]
    }
    
    redis_client.setex(f"scan_results:{scan_id}", 3600, json.dumps(results))
    
    logger.info(f"Vulnerability scan {scan_id} completed")

async def update_metrics_task():
    """Periodically update metrics"""
    while True:
        try:
            # Update security score
            db = SessionLocal()
            score = calculate_security_score(db)
            redis_client.set("security_score", str(score))
            security_score.set(score)
            db.close()
            
            # Update other metrics
            active_user_count = redis_client.scard("active_users") or 0
            active_users.set(active_user_count)
            
        except Exception as e:
            logger.error(f"Error updating metrics: {e}")
        
        await asyncio.sleep(60)  # Update every minute

async def process_security_events_task():
    """Process queued security events"""
    while True:
        try:
            # Get unprocessed events
            db = SessionLocal()
            events = db.query(SecurityEvent).filter(SecurityEvent.processed == False).limit(10).all()
            
            for event in events:
                await process_security_event(str(event.event_id))
            
            db.close()
            
        except Exception as e:
            logger.error(f"Error processing events: {e}")
        
        await asyncio.sleep(10)  # Check every 10 seconds

def calculate_security_score(db: Session) -> float:
    """Calculate overall security score"""
    score = 100.0
    
    # Deduct for critical events
    critical_events = db.query(SecurityEvent).filter(
        SecurityEvent.severity == "CRITICAL",
        SecurityEvent.timestamp >= datetime.now(timezone.utc) - timedelta(days=7)
    ).count()
    score -= critical_events * 5
    
    # Deduct for open vulnerabilities
    # (Simplified - in production, query actual vulnerability data)
    score -= 10
    
    return max(0, min(100, score))

# Main entry point
if __name__ == "__main__":
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )