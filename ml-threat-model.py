#!/usr/bin/env python3
"""
CyberPulse Analytics Platform - Advanced ML Threat Detection Model
Author: Justin Christopher Weaver
Description: Deep learning model for anomaly detection and threat classification
"""

import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, callbacks
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import json
import logging
from typing import Dict, List, Tuple, Optional, Union
from datetime import datetime, timedelta
import hashlib
from dataclasses import dataclass
import asyncio
import aiofiles

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ThreatPrediction:
    """Threat prediction result"""
    threat_type: str
    confidence: float
    risk_score: float
    anomaly_score: float
    recommended_action: str
    indicators: List[str]


class AdvancedThreatDetector:
    """Advanced ML-based threat detection system"""
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        self.encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.threat_classifier = None
        self.anomaly_detector = None
        self.feature_extractor = None
        self.behavior_analyzer = None
        self.threat_types = [
            "BENIGN",
            "BRUTE_FORCE",
            "DOS_ATTACK", 
            "SQL_INJECTION",
            "XSS",
            "MALWARE",
            "DATA_EXFILTRATION",
            "PRIVILEGE_ESCALATION",
            "LATERAL_MOVEMENT",
            "COMMAND_CONTROL"
        ]
        
    def build_threat_classifier(self, input_shape: int) -> keras.Model:
        """Build deep neural network for threat classification"""
        model = models.Sequential([
            layers.Input(shape=(input_shape,)),
            layers.Dense(512, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            
            layers.Dense(256, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.3),
            
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.2),
            
            layers.Dense(64, activation='relu'),
            layers.BatchNormalization(),
            
            layers.Dense(len(self.threat_types), activation='softmax')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy', keras.metrics.Precision(), keras.metrics.Recall()]
        )
        
        return model
    
    def build_anomaly_detector(self, input_shape: int) -> keras.Model:
        """Build autoencoder for anomaly detection"""
        # Encoder
        encoder = models.Sequential([
            layers.Input(shape=(input_shape,)),
            layers.Dense(256, activation='relu'),
            layers.BatchNormalization(),
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dense(64, activation='relu'),
            layers.BatchNormalization(),
            layers.Dense(32, activation='relu')  # Latent space
        ])
        
        # Decoder
        decoder = models.Sequential([
            layers.Input(shape=(32,)),
            layers.Dense(64, activation='relu'),
            layers.BatchNormalization(),
            layers.Dense(128, activation='relu'),
            layers.BatchNormalization(),
            layers.Dense(256, activation='relu'),
            layers.BatchNormalization(),
            layers.Dense(input_shape, activation='sigmoid')
        ])
        
        # Autoencoder
        autoencoder = models.Sequential([encoder, decoder])
        autoencoder.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='mse',
            metrics=['mae']
        )
        
        return autoencoder
    
    def build_lstm_behavior_analyzer(self, sequence_length: int, features: int) -> keras.Model:
        """Build LSTM for behavioral analysis"""
        model = models.Sequential([
            layers.LSTM(128, return_sequences=True, input_shape=(sequence_length, features)),
            layers.Dropout(0.2),
            layers.LSTM(64, return_sequences=True),
            layers.Dropout(0.2),
            layers.LSTM(32),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(len(self.threat_types), activation='softmax')
        ])
        
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def extract_features(self, event_data: Dict) -> np.ndarray:
        """Extract features from raw event data"""
        features = []
        
        # Network features
        features.append(self._ip_to_numeric(event_data.get('source_ip', '0.0.0.0')))
        features.append(self._ip_to_numeric(event_data.get('destination_ip', '0.0.0.0')))
        features.append(event_data.get('source_port', 0))
        features.append(event_data.get('destination_port', 0))
        
        # Protocol encoding
        protocol = event_data.get('protocol', 'UNKNOWN')
        protocol_map = {'TCP': 1, 'UDP': 2, 'ICMP': 3, 'HTTP': 4, 'HTTPS': 5, 'SSH': 6, 'DNS': 7}
        features.append(protocol_map.get(protocol, 0))
        
        # Time-based features
        timestamp = event_data.get('timestamp', datetime.now())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        features.append(timestamp.hour)
        features.append(timestamp.weekday())
        features.append(timestamp.day)
        
        # Packet/data features
        features.append(event_data.get('packet_size', 0))
        features.append(event_data.get('packet_count', 1))
        features.append(event_data.get('bytes_transferred', 0))
        features.append(event_data.get('duration', 0))
        
        # Behavioral features
        features.append(event_data.get('failed_attempts', 0))
        features.append(event_data.get('success_ratio', 1.0))
        features.append(event_data.get('connection_rate', 0))
        
        # Payload analysis (simplified)
        payload = str(event_data.get('payload', ''))
        features.append(len(payload))
        features.append(self._calculate_entropy(payload))
        features.append(int(any(pattern in payload.lower() for pattern in ['select', 'union', 'drop', 'script', '../'])))
        
        # Additional security features
        features.append(event_data.get('is_encrypted', 0))
        features.append(event_data.get('has_authentication', 0))
        features.append(event_data.get('is_internal', 0))
        
        return np.array(features, dtype=np.float32)
    
    def _ip_to_numeric(self, ip: str) -> float:
        """Convert IP address to numeric value"""
        try:
            parts = ip.split('.')
            return sum(int(part) * (256 ** (3 - i)) for i, part in enumerate(parts))
        except:
            return 0
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(text)]
        entropy = -sum([p * np.log2(p) for p in prob if p > 0])
        return entropy
    
    async def train_models(self, training_data: pd.DataFrame):
        """Train all ML models"""
        logger.info("Starting model training...")
        
        # Prepare data
        X = np.array([self.extract_features(row) for _, row in training_data.iterrows()])
        y = self.encoder.fit_transform(training_data['threat_type'])
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train threat classifier
        logger.info("Training threat classifier...")
        self.threat_classifier = self.build_threat_classifier(X_train.shape[1])
        
        early_stopping = callbacks.EarlyStopping(
            monitor='val_loss',
            patience=10,
            restore_best_weights=True
        )
        
        history = self.threat_classifier.fit(
            X_train, y_train,
            epochs=100,
            batch_size=64,
            validation_split=0.2,
            callbacks=[early_stopping],
            verbose=1
        )
        
        # Evaluate classifier
        test_loss, test_accuracy, test_precision, test_recall = self.threat_classifier.evaluate(
            X_test, y_test, verbose=0
        )
        logger.info(f"Threat Classifier - Accuracy: {test_accuracy:.4f}, "
                   f"Precision: {test_precision:.4f}, Recall: {test_recall:.4f}")
        
        # Train anomaly detector
        logger.info("Training anomaly detector...")
        # Use only benign data for anomaly detection training
        X_benign = X_scaled[y == self.encoder.transform(['BENIGN'])[0]]
        
        self.anomaly_detector = self.build_anomaly_detector(X_train.shape[1])
        self.anomaly_detector.fit(
            X_benign, X_benign,
            epochs=50,
            batch_size=32,
            validation_split=0.1,
            callbacks=[early_stopping],
            verbose=1
        )
        
        # Save models
        await self.save_models()
        
    async def predict(self, event_data: Dict) -> ThreatPrediction:
        """Predict threat type and risk level"""
        # Extract features
        features = self.extract_features(event_data)
        features_scaled = self.scaler.transform([features])
        
        # Threat classification
        threat_probs = self.threat_classifier.predict(features_scaled, verbose=0)[0]
        threat_idx = np.argmax(threat_probs)
        threat_type = self.encoder.inverse_transform([threat_idx])[0]
        confidence = float(threat_probs[threat_idx])
        
        # Anomaly detection
        reconstruction = self.anomaly_detector.predict(features_scaled, verbose=0)
        reconstruction_error = np.mean(np.square(features_scaled - reconstruction))
        anomaly_score = min(1.0, reconstruction_error / 0.1)  # Normalize to 0-1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            threat_type, confidence, anomaly_score, event_data
        )
        
        # Get indicators
        indicators = self._extract_indicators(event_data, threat_type, anomaly_score)
        
        # Recommend action
        action = self._recommend_action(threat_type, risk_score)
        
        return ThreatPrediction(
            threat_type=threat_type,
            confidence=confidence,
            risk_score=risk_score,
            anomaly_score=anomaly_score,
            recommended_action=action,
            indicators=indicators
        )
    
    def _calculate_risk_score(self, threat_type: str, confidence: float, 
                            anomaly_score: float, event_data: Dict) -> float:
        """Calculate comprehensive risk score"""
        # Base risk from threat type
        threat_weights = {
            "BENIGN": 0.0,
            "BRUTE_FORCE": 0.7,
            "DOS_ATTACK": 0.8,
            "SQL_INJECTION": 0.85,
            "XSS": 0.75,
            "MALWARE": 0.9,
            "DATA_EXFILTRATION": 0.95,
            "PRIVILEGE_ESCALATION": 0.9,
            "LATERAL_MOVEMENT": 0.85,
            "COMMAND_CONTROL": 0.95
        }
        
        base_risk = threat_weights.get(threat_type, 0.5)
        
        # Adjust for confidence and anomaly
        risk = base_risk * confidence * 0.7 + anomaly_score * 0.3
        
        # Additional factors
        if event_data.get('is_internal', False):
            risk *= 1.2  # Internal threats are more serious
        
        if event_data.get('failed_attempts', 0) > 10:
            risk *= 1.1
        
        if event_data.get('bytes_transferred', 0) > 1000000:  # 1MB
            risk *= 1.15
        
        return min(1.0, risk)
    
    def _extract_indicators(self, event_data: Dict, threat_type: str, 
                          anomaly_score: float) -> List[str]:
        """Extract threat indicators"""
        indicators = []
        
        if threat_type != "BENIGN":
            indicators.append(f"Detected {threat_type.replace('_', ' ').lower()}")
        
        if anomaly_score > 0.7:
            indicators.append("Highly anomalous behavior detected")
        
        if event_data.get('failed_attempts', 0) > 5:
            indicators.append(f"Multiple failed attempts ({event_data['failed_attempts']})")
        
        payload = str(event_data.get('payload', ''))
        if any(pattern in payload.lower() for pattern in ['select', 'union', 'drop']):
            indicators.append("SQL injection patterns detected")
        
        if any(pattern in payload.lower() for pattern in ['<script', 'javascript:', 'onerror']):
            indicators.append("XSS patterns detected")
        
        if event_data.get('connection_rate', 0) > 100:
            indicators.append("Abnormally high connection rate")
        
        return indicators
    
    def _recommend_action(self, threat_type: str, risk_score: float) -> str:
        """Recommend security action based on threat"""
        if threat_type == "BENIGN":
            return "Continue monitoring"
        
        if risk_score > 0.9:
            return "IMMEDIATE ACTION: Block source IP and initiate incident response"
        elif risk_score > 0.7:
            return "HIGH PRIORITY: Investigate immediately and consider blocking"
        elif risk_score > 0.5:
            return "MEDIUM PRIORITY: Monitor closely and gather more evidence"
        else:
            return "LOW PRIORITY: Log and monitor for patterns"
    
    async def save_models(self):
        """Save trained models to disk"""
        # Save neural networks
        self.threat_classifier.save(f"{self.model_path}/threat_classifier.h5")
        self.anomaly_detector.save(f"{self.model_path}/anomaly_detector.h5")
        
        # Save preprocessors
        joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
        joblib.dump(self.encoder, f"{self.model_path}/encoder.pkl")
        
        # Save metadata
        metadata = {
            "version": "1.0.0",
            "trained_at": datetime.now().isoformat(),
            "threat_types": self.threat_types,
            "feature_count": self.scaler.n_features_in_
        }
        
        async with aiofiles.open(f"{self.model_path}/metadata.json", 'w') as f:
            await f.write(json.dumps(metadata, indent=2))
        
        logger.info("Models saved successfully")
    
    async def load_models(self):
        """Load trained models from disk"""
        try:
            self.threat_classifier = keras.models.load_model(
                f"{self.model_path}/threat_classifier.h5"
            )
            self.anomaly_detector = keras.models.load_model(
                f"{self.model_path}/anomaly_detector.h5"
            )
            self.scaler = joblib.load(f"{self.model_path}/scaler.pkl")
            self.encoder = joblib.load(f"{self.model_path}/encoder.pkl")
            
            logger.info("Models loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            return False
    
    def explain_prediction(self, event_data: Dict, prediction: ThreatPrediction) -> Dict:
        """Generate explainable AI insights"""
        features = self.extract_features(event_data)
        features_scaled = self.scaler.transform([features])
        
        # Feature importance (simplified - in production use SHAP/LIME)
        feature_names = [
            'source_ip', 'destination_ip', 'source_port', 'destination_port',
            'protocol', 'hour', 'weekday', 'day', 'packet_size', 'packet_count',
            'bytes_transferred', 'duration', 'failed_attempts', 'success_ratio',
            'connection_rate', 'payload_length', 'payload_entropy', 'suspicious_patterns',
            'is_encrypted', 'has_authentication', 'is_internal'
        ]
        
        # Calculate feature contributions (simplified)
        feature_importance = np.abs(features_scaled[0] - np.mean(features_scaled))
        top_features_idx = np.argsort(feature_importance)[-5:][::-1]
        
        explanation = {
            "prediction": {
                "threat_type": prediction.threat_type,
                "confidence": prediction.confidence,
                "risk_score": prediction.risk_score
            },
            "top_contributing_features": [
                {
                    "feature": feature_names[idx],
                    "value": float(features[idx]),
                    "importance": float(feature_importance[idx])
                }
                for idx in top_features_idx
            ],
            "risk_factors": prediction.indicators,
            "recommended_action": prediction.recommended_action,
            "explanation": self._generate_explanation(prediction, event_data)
        }
        
        return explanation
    
    def _generate_explanation(self, prediction: ThreatPrediction, event_data: Dict) -> str:
        """Generate human-readable explanation"""
        if prediction.threat_type == "BENIGN":
            return "This event appears to be normal network activity with no signs of malicious intent."
        
        explanation = f"This event has been classified as {prediction.threat_type.replace('_', ' ').lower()} "
        explanation += f"with {prediction.confidence:.1%} confidence. "
        
        if prediction.anomaly_score > 0.7:
            explanation += "The behavior is highly anomalous compared to baseline patterns. "
        
        if event_data.get('failed_attempts', 0) > 5:
            explanation += f"There were {event_data['failed_attempts']} failed attempts, suggesting persistent attack behavior. "
        
        explanation += f"The overall risk score is {prediction.risk_score:.1%}. "
        explanation += prediction.recommended_action
        
        return explanation


class ThreatIntelligenceAggregator:
    """Aggregate threat intelligence from multiple sources"""
    
    def __init__(self):
        self.sources = []
        self.threat_cache = {}
        self.ioc_database = {}  # Indicators of Compromise
        
    async def update_threat_intelligence(self):
        """Update threat intelligence from various sources"""
        # In production, integrate with real threat feeds
        # Example: MISP, AlienVault OTX, VirusTotal, etc.
        
        logger.info("Updating threat intelligence...")
        
        # Simulated threat intel update
        new_threats = {
            "192.168.1.100": {
                "reputation": "malicious",
                "threat_type": "botnet",
                "confidence": 0.9,
                "last_seen": datetime.now()
            },
            "evil.malware.com": {
                "reputation": "malicious",
                "threat_type": "c2_server",
                "confidence": 0.95,
                "last_seen": datetime.now()
            }
        }
        
        self.threat_cache.update(new_threats)
        logger.info(f"Updated {len(new_threats)} threat indicators")
    
    def check_ioc(self, indicator: str) -> Optional[Dict]:
        """Check if indicator is known malicious"""
        return self.threat_cache.get(indicator)
    
    async def correlate_threats(self, events: List[Dict]) -> List[Dict]:
        """Correlate events with threat intelligence"""
        correlated = []
        
        for event in events:
            threat_info = self.check_ioc(event.get('source_ip', ''))
            if threat_info:
                event['threat_intelligence'] = threat_info
                event['risk_score'] = max(
                    event.get('risk_score', 0),
                    threat_info['confidence']
                )
            correlated.append(event)
        
        return correlated


# Example usage and testing
async def main():
    """Test the ML threat detection system"""
    # Initialize detector
    detector = AdvancedThreatDetector()
    
    # Generate sample training data
    sample_data = []
    
    # Benign traffic
    for _ in range(1000):
        sample_data.append({
            'source_ip': f"192.168.1.{np.random.randint(1, 255)}",
            'destination_ip': f"10.0.0.{np.random.randint(1, 255)}",
            'source_port': np.random.randint(1024, 65535),
            'destination_port': np.random.choice([80, 443, 22, 3306]),
            'protocol': np.random.choice(['HTTP', 'HTTPS', 'SSH']),
            'timestamp': datetime.now() - timedelta(hours=np.random.randint(0, 24)),
            'packet_size': np.random.randint(64, 1500),
            'bytes_transferred': np.random.randint(100, 10000),
            'threat_type': 'BENIGN'
        })
    
    # Attack traffic
    attack_types = ['BRUTE_FORCE', 'SQL_INJECTION', 'DOS_ATTACK', 'DATA_EXFILTRATION']
    for attack in attack_types:
        for _ in range(200):
            event = {
                'source_ip': f"10.10.10.{np.random.randint(1, 255)}",
                'destination_ip': f"192.168.1.{np.random.randint(1, 255)}",
                'source_port': np.random.randint(1024, 65535),
                'destination_port': 22 if attack == 'BRUTE_FORCE' else 80,
                'protocol': 'SSH' if attack == 'BRUTE_FORCE' else 'HTTP',
                'timestamp': datetime.now() - timedelta(hours=np.random.randint(0, 24)),
                'threat_type': attack
            }
            
            if attack == 'BRUTE_FORCE':
                event['failed_attempts'] = np.random.randint(10, 100)
            elif attack == 'SQL_INJECTION':
                event['payload'] = "' OR '1'='1"
            elif attack == 'DOS_ATTACK':
                event['connection_rate'] = np.random.randint(100, 1000)
            elif attack == 'DATA_EXFILTRATION':
                event['bytes_transferred'] = np.random.randint(1000000, 10000000)
            
            sample_data.append(event)
    
    # Convert to DataFrame
    df = pd.DataFrame(sample_data)
    
    # Train models
    await detector.train_models(df)
    
    # Test prediction
    test_event = {
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.5',
        'source_port': 45123,
        'destination_port': 22,
        'protocol': 'SSH',
        'timestamp': datetime.now(),
        'failed_attempts': 50,
        'connection_rate': 200
    }
    
    prediction = await detector.predict(test_event)
    print(f"\nPrediction: {prediction}")
    
    # Get explanation
    explanation = detector.explain_prediction(test_event, prediction)
    print(f"\nExplanation: {json.dumps(explanation, indent=2)}")


if __name__ == "__main__":
    asyncio.run(main())