-- CyberPulse Analytics Platform Database Schema
-- Author: Justin Christopher Weaver
-- Database: PostgreSQL 13+
-- Description: Comprehensive schema for security operations, project management, and analytics

-- Create database
CREATE DATABASE IF NOT EXISTS cyberpulse_analytics;
USE cyberpulse_analytics;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- =====================================================
-- SECURITY OPERATIONS SCHEMA
-- =====================================================

-- Security Events Table
CREATE TABLE security_events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    source_ip INET NOT NULL,
    destination_ip INET,
    source_port INTEGER,
    destination_port INTEGER,
    protocol VARCHAR(20) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    risk_score DECIMAL(3,2) CHECK (risk_score >= 0 AND risk_score <= 1),
    payload JSONB,
    raw_log TEXT,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_source_ip (source_ip),
    INDEX idx_severity (severity),
    INDEX idx_event_type (event_type)
);

-- Threat Intelligence Table
CREATE TABLE threat_intelligence (
    intel_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    indicator VARCHAR(255) NOT NULL UNIQUE,
    indicator_type VARCHAR(50) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
    source VARCHAR(100) NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    metadata JSONB,
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_indicator (indicator),
    INDEX idx_threat_type (threat_type),
    INDEX idx_active (active)
);

-- Security Alerts Table
CREATE TABLE security_alerts (
    alert_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID REFERENCES security_events(event_id),
    alert_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    source_ips INET[],
    affected_assets TEXT[],
    status VARCHAR(50) DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'ESCALATED')),
    assigned_to VARCHAR(100),
    priority INTEGER CHECK (priority >= 1 AND priority <= 5),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,
    INDEX idx_status (status),
    INDEX idx_severity_alerts (severity),
    INDEX idx_created_at (created_at)
);

-- Vulnerability Scans Table
CREATE TABLE vulnerability_scans (
    scan_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_type VARCHAR(50) NOT NULL,
    target_type VARCHAR(50) NOT NULL,
    target_identifier VARCHAR(255) NOT NULL,
    scanner VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'PENDING',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    scan_config JSONB,
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_target (target_identifier),
    INDEX idx_scan_status (status)
);

-- Vulnerabilities Table
CREATE TABLE vulnerabilities (
    vuln_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES vulnerability_scans(scan_id),
    cve_id VARCHAR(50),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    cvss_score DECIMAL(3,1) CHECK (cvss_score >= 0 AND cvss_score <= 10),
    affected_component VARCHAR(255),
    solution TEXT,
    references TEXT[],
    status VARCHAR(50) DEFAULT 'OPEN',
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    remediated_at TIMESTAMP WITH TIME ZONE,
    false_positive BOOLEAN DEFAULT FALSE,
    INDEX idx_cve (cve_id),
    INDEX idx_severity_vuln (severity),
    INDEX idx_status_vuln (status)
);

-- =====================================================
-- PROJECT MANAGEMENT SCHEMA
-- =====================================================

-- Projects Table
CREATE TABLE projects (
    project_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_name VARCHAR(255) NOT NULL,
    project_code VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'PLANNING',
    priority VARCHAR(20) DEFAULT 'MEDIUM',
    start_date DATE,
    end_date DATE,
    budget DECIMAL(12,2),
    owner VARCHAR(100) NOT NULL,
    team_members TEXT[],
    tags TEXT[],
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_project_status (status),
    INDEX idx_project_owner (owner)
);

-- Sprints Table
CREATE TABLE sprints (
    sprint_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(project_id),
    sprint_number INTEGER NOT NULL,
    sprint_name VARCHAR(255) NOT NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    sprint_goal TEXT,
    status VARCHAR(50) DEFAULT 'PLANNED',
    velocity INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sprint_project (project_id),
    INDEX idx_sprint_status (status),
    UNIQUE(project_id, sprint_number)
);

-- Tasks Table
CREATE TABLE tasks (
    task_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID REFERENCES projects(project_id),
    sprint_id UUID REFERENCES sprints(sprint_id),
    parent_task_id UUID REFERENCES tasks(task_id),
    task_type VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'TODO',
    priority VARCHAR(20) DEFAULT 'MEDIUM',
    story_points INTEGER,
    assigned_to VARCHAR(100),
    labels TEXT[],
    due_date DATE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_task_project (project_id),
    INDEX idx_task_sprint (sprint_id),
    INDEX idx_task_status (status),
    INDEX idx_task_assigned (assigned_to)
);

-- Task Comments Table
CREATE TABLE task_comments (
    comment_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id UUID REFERENCES tasks(task_id),
    author VARCHAR(100) NOT NULL,
    comment TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_comment_task (task_id)
);

-- =====================================================
-- COMPLIANCE & GOVERNANCE SCHEMA
-- =====================================================

-- Compliance Frameworks Table
CREATE TABLE compliance_frameworks (
    framework_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    framework_name VARCHAR(100) NOT NULL UNIQUE,
    version VARCHAR(20),
    description TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Compliance Controls Table
CREATE TABLE compliance_controls (
    control_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    framework_id UUID REFERENCES compliance_frameworks(framework_id),
    control_number VARCHAR(50) NOT NULL,
    control_title VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    implementation_status VARCHAR(50) DEFAULT 'NOT_IMPLEMENTED',
    effectiveness_score DECIMAL(3,2),
    last_assessed TIMESTAMP WITH TIME ZONE,
    evidence_links TEXT[],
    responsible_party VARCHAR(100),
    INDEX idx_control_framework (framework_id),
    INDEX idx_control_status (implementation_status)
);

-- Audit Logs Table
CREATE TABLE audit_logs (
    log_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    success BOOLEAN DEFAULT TRUE,
    INDEX idx_audit_timestamp (timestamp),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_action (action)
);

-- =====================================================
-- ANALYTICS & REPORTING SCHEMA
-- =====================================================

-- KPI Metrics Table
CREATE TABLE kpi_metrics (
    metric_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(100) NOT NULL,
    metric_type VARCHAR(50) NOT NULL,
    category VARCHAR(50),
    value DECIMAL(12,2) NOT NULL,
    unit VARCHAR(20),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    source VARCHAR(50),
    tags TEXT[],
    metadata JSONB,
    INDEX idx_metric_name (metric_name),
    INDEX idx_metric_timestamp (timestamp),
    INDEX idx_metric_category (category)
);

-- Reports Table
CREATE TABLE reports (
    report_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    description TEXT,
    generated_by VARCHAR(100) NOT NULL,
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    report_period_start DATE,
    report_period_end DATE,
    file_path VARCHAR(500),
    file_size BIGINT,
    status VARCHAR(50) DEFAULT 'COMPLETED',
    metadata JSONB,
    INDEX idx_report_type (report_type),
    INDEX idx_report_generated (generated_at)
);

-- Dashboard Configurations Table
CREATE TABLE dashboard_configs (
    config_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dashboard_name VARCHAR(100) NOT NULL,
    user_id VARCHAR(100) NOT NULL,
    layout JSONB NOT NULL,
    widgets JSONB NOT NULL,
    refresh_interval INTEGER DEFAULT 300,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_dashboard_user (user_id)
);

-- =====================================================
-- SYSTEM & USER MANAGEMENT SCHEMA
-- =====================================================

-- Users Table
CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    department VARCHAR(100),
    password_hash VARCHAR(255) NOT NULL,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    last_login TIMESTAMP WITH TIME ZONE,
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_email (email),
    INDEX idx_user_active (active)
);

-- Roles Table
CREATE TABLE roles (
    role_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Sessions Table
CREATE TABLE user_sessions (
    session_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(user_id),
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    INDEX idx_session_user (user_id),
    INDEX idx_session_token (token_hash)
);

-- =====================================================
-- CLOUD INFRASTRUCTURE MONITORING
-- =====================================================

-- Cloud Resources Table
CREATE TABLE cloud_resources (
    resource_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cloud_provider VARCHAR(50) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_name VARCHAR(255) NOT NULL,
    region VARCHAR(50),
    status VARCHAR(50),
    cost_per_hour DECIMAL(10,4),
    tags JSONB,
    metadata JSONB,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cloud_provider (cloud_provider),
    INDEX idx_resource_type (resource_type)
);

-- Cloud Security Findings Table
CREATE TABLE cloud_security_findings (
    finding_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    resource_id UUID REFERENCES cloud_resources(resource_id),
    finding_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    recommendation TEXT,
    compliance_standards TEXT[],
    status VARCHAR(50) DEFAULT 'OPEN',
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE,
    INDEX idx_finding_resource (resource_id),
    INDEX idx_finding_severity (severity),
    INDEX idx_finding_status (status)
);

-- =====================================================
-- FUNCTIONS AND TRIGGERS
-- =====================================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update timestamp triggers
CREATE TRIGGER update_threat_intelligence_updated_at BEFORE UPDATE ON threat_intelligence
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_alerts_updated_at BEFORE UPDATE ON security_alerts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_projects_updated_at BEFORE UPDATE ON projects
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tasks_updated_at BEFORE UPDATE ON tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to calculate security score
CREATE OR REPLACE FUNCTION calculate_security_score()
RETURNS DECIMAL AS $$
DECLARE
    score DECIMAL(5,2) := 100.0;
    vuln_penalty DECIMAL(5,2);
    alert_penalty DECIMAL(5,2);
    compliance_bonus DECIMAL(5,2);
BEGIN
    -- Deduct points for vulnerabilities
    SELECT 
        COALESCE(SUM(
            CASE 
                WHEN severity = 'CRITICAL' THEN 10
                WHEN severity = 'HIGH' THEN 5
                WHEN severity = 'MEDIUM' THEN 2
                WHEN severity = 'LOW' THEN 0.5
                ELSE 0
            END
        ), 0) INTO vuln_penalty
    FROM vulnerabilities
    WHERE status = 'OPEN';
    
    -- Deduct points for open alerts
    SELECT 
        COALESCE(SUM(
            CASE 
                WHEN severity = 'CRITICAL' THEN 8
                WHEN severity = 'HIGH' THEN 4
                WHEN severity = 'MEDIUM' THEN 1.5
                WHEN severity = 'LOW' THEN 0.3
                ELSE 0
            END
        ), 0) INTO alert_penalty
    FROM security_alerts
    WHERE status IN ('OPEN', 'IN_PROGRESS');
    
    -- Add bonus for compliance
    SELECT 
        COALESCE(AVG(effectiveness_score) * 10, 0) INTO compliance_bonus
    FROM compliance_controls
    WHERE implementation_status = 'IMPLEMENTED';
    
    score := GREATEST(0, score - vuln_penalty - alert_penalty + compliance_bonus);
    
    RETURN ROUND(score, 2);
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- VIEWS FOR REPORTING
-- =====================================================

-- Security Dashboard View
CREATE VIEW security_dashboard AS
SELECT 
    (SELECT COUNT(*) FROM security_events WHERE timestamp > NOW() - INTERVAL '24 hours') as events_24h,
    (SELECT COUNT(*) FROM security_alerts WHERE status = 'OPEN') as open_alerts,
    (SELECT COUNT(*) FROM vulnerabilities WHERE status = 'OPEN' AND severity IN ('CRITICAL', 'HIGH')) as critical_vulns,
    calculate_security_score() as security_score,
    (SELECT COUNT(DISTINCT source_ip) FROM security_events WHERE timestamp > NOW() - INTERVAL '1 hour' AND severity IN ('HIGH', 'CRITICAL')) as active_threats;

-- Project Status View
CREATE VIEW project_status AS
SELECT 
    p.project_id,
    p.project_name,
    p.status as project_status,
    COUNT(DISTINCT s.sprint_id) as total_sprints,
    COUNT(DISTINCT t.task_id) as total_tasks,
    SUM(CASE WHEN t.status = 'COMPLETED' THEN 1 ELSE 0 END) as completed_tasks,
    ROUND(100.0 * SUM(CASE WHEN t.status = 'COMPLETED' THEN 1 ELSE 0 END) / NULLIF(COUNT(t.task_id), 0), 2) as completion_percentage
FROM projects p
LEFT JOIN sprints s ON p.project_id = s.project_id
LEFT JOIN tasks t ON p.project_id = t.project_id
GROUP BY p.project_id, p.project_name, p.status;

-- Compliance Overview View
CREATE VIEW compliance_overview AS
SELECT 
    cf.framework_name,
    COUNT(cc.control_id) as total_controls,
    SUM(CASE WHEN cc.implementation_status = 'IMPLEMENTED' THEN 1 ELSE 0 END) as implemented_controls,
    ROUND(100.0 * SUM(CASE WHEN cc.implementation_status = 'IMPLEMENTED' THEN 1 ELSE 0 END) / NULLIF(COUNT(cc.control_id), 0), 2) as compliance_percentage,
    AVG(cc.effectiveness_score) as avg_effectiveness
FROM compliance_frameworks cf
LEFT JOIN compliance_controls cc ON cf.framework_id = cc.framework_id
WHERE cf.active = TRUE
GROUP BY cf.framework_name;

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

-- Composite indexes for common queries
CREATE INDEX idx_events_severity_time ON security_events(severity, timestamp DESC);
CREATE INDEX idx_alerts_status_severity ON security_alerts(status, severity);
CREATE INDEX idx_vulns_status_severity ON vulnerabilities(status, severity);
CREATE INDEX idx_tasks_project_status ON tasks(project_id, status);
CREATE INDEX idx_cloud_provider_type ON cloud_resources(cloud_provider, resource_type);

-- Full text search indexes
CREATE INDEX idx_events_payload_gin ON security_events USING gin(payload);
CREATE INDEX idx_tasks_search ON tasks USING gin(to_tsvector('english', title || ' ' || COALESCE(description, '')));

-- =====================================================
-- INITIAL DATA
-- =====================================================

-- Insert default compliance frameworks
INSERT INTO compliance_frameworks (framework_name, version, description) VALUES
('SOC2', 'Type II', 'Service Organization Control 2'),
('HIPAA', '2022', 'Health Insurance Portability and Accountability Act'),
('PCI-DSS', 'v4.0', 'Payment Card Industry Data Security Standard'),
('ISO 27001', '2022', 'Information Security Management System'),
('NIST CSF', 'v1.1', 'NIST Cybersecurity Framework');

-- Insert default roles
INSERT INTO roles (role_name, description, permissions) VALUES
('ADMIN', 'System Administrator', '{"all": true}'),
('SECURITY_ANALYST', 'Security Operations Analyst', '{"security": ["read", "write"], "compliance": ["read"]}'),
('PROJECT_MANAGER', 'Project Manager', '{"projects": ["read", "write"], "reports": ["read", "write"]}'),
('AUDITOR', 'Compliance Auditor', '{"compliance": ["read"], "audit": ["read"], "reports": ["read"]}'),
('VIEWER', 'Read-only Access', '{"all": ["read"]}');

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO cyberpulse_admin;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO cyberpulse_app;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO cyberpulse_readonly;