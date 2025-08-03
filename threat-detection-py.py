#!/usr/bin/env python3
"""
CyberPulse Analytics Platform - Threat Detection Engine
Author: Justin Christopher Weaver
Description: ML-powered threat detection and anomaly analysis
"""

import json
import datetime
import hashlib
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
import asyncio
import aiohttp
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AttackType(Enum):
    """Common attack types"""
    BRUTE_FORCE = "Brute Force Attack"
    DDoS = "Distributed Denial of Service"
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    MALWARE = "Malware Detection"
    PHISHING = "Phishing Attempt"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DATA_EXFILTRATION = "Data Exfiltration"
    ZERO_DAY = "Zero-Day Exploit"
    INSIDER_THREAT = "Insider Threat"


@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    timestamp: datetime.datetime
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    event_type: str
    payload: Dict
    risk_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.INFO
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'protocol': self.protocol,
            'event_type': self.event_type,
            'payload': self.payload,
            'risk_score': self.risk_score,
            'threat_level': self.threat_level.value
        }


@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    indicator: str
    indicator_type: str  # IP, Domain, Hash, etc.
    threat_type: AttackType
    confidence: float
    source: str
    last_seen: datetime.datetime
    metadata: Dict


class ThreatDetectionEngine:
    """Main threat detection and analysis engine"""
    
    def __init__(self, config_path: str = "config/threat_detection.json"):
        """Initialize the threat detection engine"""
        self.config = self._load_config(config_path)
        self.ml_model = self._initialize_ml_model()
        self.threat_intel_cache = {}
        self.baseline_metrics = {}
        self.alert_threshold = self.config.get('alert_threshold', 0.7)
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found at {config_path}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            'alert_threshold': 0.7,
            'ml_contamination': 0.1,
            'max_events_per_second': 1000,
            'threat_intel_sources': [
                'https://api.threatintel.example.com',
                'https://feeds.security.example.com'
            ],
            'baseline_window_hours': 24,
            'anomaly_detection_features': [
                'bytes_transferred',
                'connection_duration',
                'packet_count',
                'unique_destinations'
            ]
        }
    
    def _initialize_ml_model(self) -> IsolationForest:
        """Initialize the machine learning model for anomaly detection"""
        return IsolationForest(
            contamination=self.config.get('ml_contamination', 0.1),
            random_state=42,
            n_estimators=100
        )
    
    async def analyze_event(self, event: SecurityEvent) -> Tuple[float, ThreatLevel, List[str]]:
        """
        Analyze a security event and return risk score, threat level, and indicators
        """
        indicators = []
        risk_factors = []
        
        # Check against threat intelligence
        intel_score = await self._check_threat_intelligence(event)
        if intel_score > 0:
            risk_factors.append(f"Threat intel match: {intel_score:.2f}")
            indicators.append("Known malicious indicator")
        
        # Behavioral analysis
        behavior_score = self._analyze_behavior(event)
        if behavior_score > 0.5:
            risk_factors.append(f"Suspicious behavior: {behavior_score:.2f}")
            indicators.append("Behavioral anomaly detected")
        
        # Protocol-specific checks
        protocol_score = self._check_protocol_anomalies(event)
        if protocol_score > 0:
            risk_factors.append(f"Protocol anomaly: {protocol_score:.2f}")
        
        # Machine learning anomaly detection
        ml_score = self._ml_anomaly_detection(event)
        if ml_score > 0.6:
            risk_factors.append(f"ML anomaly score: {ml_score:.2f}")
            indicators.append("Machine learning anomaly")
        
        # Calculate final risk score
        risk_score = self._calculate_risk_score(
            intel_score, behavior_score, protocol_score, ml_score
        )
        
        # Determine threat level
        threat_level = self._determine_threat_level(risk_score)
        
        # Update event
        event.risk_score = risk_score
        event.threat_level = threat_level
        
        logger.info(f"Event {event.event_id} analyzed - Risk: {risk_score:.2f}, Level: {threat_level.value}")
        
        return risk_score, threat_level, indicators
    
    async def _check_threat_intelligence(self, event: SecurityEvent) -> float:
        """Check event against threat intelligence feeds"""
        score = 0.0
        
        # Check IP reputation
        if event.source_ip in self.threat_intel_cache:
            intel = self.threat_intel_cache[event.source_ip]
            score = intel.confidence
        
        # Check for known attack patterns
        if self._matches_known_pattern(event):
            score = max(score, 0.8)
        
        return score
    
    def _analyze_behavior(self, event: SecurityEvent) -> float:
        """Analyze behavioral patterns"""
        score = 0.0
        
        # Check for brute force patterns
        if self._is_brute_force_pattern(event):
            score = max(score, 0.9)
        
        # Check for data exfiltration patterns
        if self._is_data_exfiltration_pattern(event):
            score = max(score, 0.85)
        
        # Check for scanning activity
        if self._is_scanning_pattern(event):
            score = max(score, 0.7)
        
        return score
    
    def _check_protocol_anomalies(self, event: SecurityEvent) -> float:
        """Check for protocol-specific anomalies"""
        score = 0.0
        
        # HTTP/HTTPS anomalies
        if event.protocol in ['HTTP', 'HTTPS']:
            if self._check_http_anomalies(event):
                score = 0.7
        
        # DNS anomalies
        elif event.protocol == 'DNS':
            if self._check_dns_anomalies(event):
                score = 0.8
        
        # SSH anomalies
        elif event.protocol == 'SSH':
            if self._check_ssh_anomalies(event):
                score = 0.75
        
        return score
    
    def _ml_anomaly_detection(self, event: SecurityEvent) -> float:
        """Use machine learning for anomaly detection"""
        try:
            # Extract features
            features = self._extract_ml_features(event)
            
            # Predict anomaly score
            anomaly_score = self.ml_model.decision_function([features])[0]
            
            # Normalize to 0-1 range
            normalized_score = 1 / (1 + np.exp(anomaly_score))
            
            return normalized_score
        except Exception as e:
            logger.error(f"ML anomaly detection failed: {e}")
            return 0.0
    
    def _calculate_risk_score(self, intel: float, behavior: float, protocol: float, ml: float) -> float:
        """Calculate weighted risk score"""
        weights = {
            'intel': 0.35,
            'behavior': 0.30,
            'protocol': 0.20,
            'ml': 0.15
        }
        
        risk_score = (
            weights['intel'] * intel +
            weights['behavior'] * behavior +
            weights['protocol'] * protocol +
            weights['ml'] * ml
        )
        
        return min(risk_score, 1.0)
    
    def _determine_threat_level(self, risk_score: float) -> ThreatLevel:
        """Determine threat level based on risk score"""
        if risk_score >= 0.9:
            return ThreatLevel.CRITICAL
        elif risk_score >= 0.7:
            return ThreatLevel.HIGH
        elif risk_score >= 0.5:
            return ThreatLevel.MEDIUM
        elif risk_score >= 0.3:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO
    
    def _matches_known_pattern(self, event: SecurityEvent) -> bool:
        """Check if event matches known attack patterns"""
        # Implement pattern matching logic
        known_patterns = [
            {'type': 'SQL_INJECTION', 'pattern': r"('|(--|#)|(/\*|(--|\#|\/\*))|(%27)|(%23))"},
            {'type': 'XSS', 'pattern': r"(<script|javascript:|onerror=|onload=)"},
            {'type': 'PATH_TRAVERSAL', 'pattern': r"(\.\./|\.\.\\)"}
        ]
        
        event_data = json.dumps(event.payload).lower()
        for pattern in known_patterns:
            if pattern['pattern'] in event_data:
                return True
        
        return False
    
    def _is_brute_force_pattern(self, event: SecurityEvent) -> bool:
        """Detect brute force attack patterns"""
        # Check for multiple failed login attempts
        if event.event_type == 'AUTHENTICATION_FAILURE':
            # In production, check historical data
            return True
        return False
    
    def _is_data_exfiltration_pattern(self, event: SecurityEvent) -> bool:
        """Detect data exfiltration patterns"""
        # Check for unusual data transfer volumes
        if 'bytes_transferred' in event.payload:
            if event.payload['bytes_transferred'] > 1000000000:  # 1GB
                return True
        return False
    
    def _is_scanning_pattern(self, event: SecurityEvent) -> bool:
        """Detect scanning activity"""
        # Check for port scanning patterns
        if event.event_type == 'CONNECTION_ATTEMPT':
            # In production, check for multiple ports from same source
            return True
        return False
    
    def _check_http_anomalies(self, event: SecurityEvent) -> bool:
        """Check for HTTP/HTTPS anomalies"""
        payload = event.payload
        
        # Check for suspicious user agents
        if 'user_agent' in payload:
            suspicious_agents = ['sqlmap', 'nikto', 'nmap', 'masscan']
            if any(agent in payload['user_agent'].lower() for agent in suspicious_agents):
                return True
        
        # Check for suspicious methods
        if 'method' in payload and payload['method'] not in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']:
            return True
        
        return False
    
    def _check_dns_anomalies(self, event: SecurityEvent) -> bool:
        """Check for DNS anomalies"""
        payload = event.payload
        
        # Check for suspicious domains
        if 'domain' in payload:
            # Check for DGA domains
            if self._is_dga_domain(payload['domain']):
                return True
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
            if any(payload['domain'].endswith(tld) for tld in suspicious_tlds):
                return True
        
        return False
    
    def _check_ssh_anomalies(self, event: SecurityEvent) -> bool:
        """Check for SSH anomalies"""
        payload = event.payload
        
        # Check for unusual SSH versions
        if 'version' in payload and 'SSH' in payload['version']:
            # Check for outdated or suspicious versions
            return True
        
        return False
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Detect Domain Generation Algorithm (DGA) domains"""
        # Simple entropy check
        domain_parts = domain.split('.')
        if len(domain_parts) > 1:
            subdomain = domain_parts[0]
            # High entropy indicates possible DGA
            entropy = self._calculate_entropy(subdomain)
            return entropy > 3.5
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(text)]
        entropy = -sum([p * np.log2(p) for p in prob if p > 0])
        
        return entropy
    
    def _extract_ml_features(self, event: SecurityEvent) -> List[float]:
        """Extract features for ML model"""
        features = []
        
        # Time-based features
        hour = event.timestamp.hour
        day_of_week = event.timestamp.weekday()
        features.extend([hour, day_of_week])
        
        # Network features
        features.append(event.port)
        features.append(len(event.payload.get('data', '')))
        
        # Add more features as needed
        # Ensure feature count matches training data
        
        return features
    
    async def update_threat_intelligence(self):
        """Update threat intelligence from external sources"""
        logger.info("Updating threat intelligence...")
        
        for source in self.config.get('threat_intel_sources', []):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(source) as response:
                        if response.status == 200:
                            data = await response.json()
                            self._process_threat_intel(data)
            except Exception as e:
                logger.error(f"Failed to update from {source}: {e}")
    
    def _process_threat_intel(self, data: Dict):
        """Process threat intelligence data"""
        for indicator in data.get('indicators', []):
            intel = ThreatIntelligence(
                indicator=indicator['value'],
                indicator_type=indicator['type'],
                threat_type=AttackType[indicator['threat_type']],
                confidence=indicator['confidence'],
                source=indicator['source'],
                last_seen=datetime.datetime.fromisoformat(indicator['last_seen']),
                metadata=indicator.get('metadata', {})
            )
            self.threat_intel_cache[intel.indicator] = intel
    
    def generate_alert(self, event: SecurityEvent, indicators: List[str]) -> Dict:
        """Generate security alert"""
        alert = {
            'alert_id': hashlib.sha256(f"{event.event_id}{datetime.datetime.now()}".encode()).hexdigest()[:16],
            'timestamp': datetime.datetime.now().isoformat(),
            'event_id': event.event_id,
            'threat_level': event.threat_level.value,
            'risk_score': event.risk_score,
            'source_ip': event.source_ip,
            'destination_ip': event.destination_ip,
            'attack_type': self._identify_attack_type(event, indicators),
            'indicators': indicators,
            'recommended_actions': self._get_recommended_actions(event),
            'auto_response': self._should_auto_respond(event)
        }
        
        return alert
    
    def _identify_attack_type(self, event: SecurityEvent, indicators: List[str]) -> str:
        """Identify the type of attack"""
        # Logic to determine attack type based on event and indicators
        if 'brute force' in str(indicators).lower():
            return AttackType.BRUTE_FORCE.value
        elif 'sql' in str(event.payload).lower():
            return AttackType.SQL_INJECTION.value
        # Add more attack type identification logic
        
        return "Unknown"
    
    def _get_recommended_actions(self, event: SecurityEvent) -> List[str]:
        """Get recommended actions for the alert"""
        actions = []
        
        if event.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
            actions.append("Block source IP immediately")
            actions.append("Initiate incident response procedure")
            actions.append("Preserve forensic evidence")
        
        if event.threat_level == ThreatLevel.MEDIUM:
            actions.append("Monitor source IP for further activity")
            actions.append("Review firewall rules")
            actions.append("Check for similar patterns")
        
        return actions
    
    def _should_auto_respond(self, event: SecurityEvent) -> bool:
        """Determine if automatic response should be triggered"""
        return event.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]


async def main():
    """Main execution function for testing"""
    # Initialize the threat detection engine
    engine = ThreatDetectionEngine()
    
    # Create a sample security event
    sample_event = SecurityEvent(
        event_id="EVT-001",
        timestamp=datetime.datetime.now(),
        source_ip="192.168.1.100",
        destination_ip="10.0.0.5",
        port=22,
        protocol="SSH",
        event_type="AUTHENTICATION_FAILURE",
        payload={
            "username": "admin",
            "attempts": 5,
            "method": "password"
        }
    )
    
    # Analyze the event
    risk_score, threat_level, indicators = await engine.analyze_event(sample_event)
    
    # Generate alert if needed
    if risk_score > engine.alert_threshold:
        alert = engine.generate_alert(sample_event, indicators)
        print(f"\n🚨 SECURITY ALERT 🚨")
        print(json.dumps(alert, indent=2))
    
    # Print event details
    print(f"\nEvent Analysis Complete:")
    print(f"Event ID: {sample_event.event_id}")
    print(f"Risk Score: {risk_score:.2f}")
    print(f"Threat Level: {threat_level.value}")
    print(f"Indicators: {', '.join(indicators)}")


if __name__ == "__main__":
    asyncio.run(main())