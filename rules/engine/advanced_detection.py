#!/usr/bin/env python3
"""
Advanced Detection Algorithms for the Detector Project

This module implements sophisticated detection algorithms including:
- ML-based anomaly detection
- Behavioral analysis
- Statistical correlation
- Time-series analysis
"""

import numpy as np
import json
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging
import statistics
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AnomalyScore:
    """Represents an anomaly detection result"""
    score: float
    confidence: float
    algorithm: str
    features_used: List[str]
    explanation: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class BehaviorProfile:
    """Represents a baseline behavior profile"""
    source: str
    metric_name: str
    baseline_values: deque = field(default_factory=lambda: deque(maxlen=1000))
    mean: float = 0.0
    std_dev: float = 0.0
    last_updated: datetime = field(default_factory=datetime.utcnow)

    def update_baseline(self, value: float):
        """Update the baseline with a new value"""
        self.baseline_values.append(value)
        if len(self.baseline_values) > 10:  # Need minimum samples for statistics
            self.mean = statistics.mean(self.baseline_values)
            self.std_dev = statistics.stdev(self.baseline_values) if len(self.baseline_values) > 1 else 0
        self.last_updated = datetime.utcnow()

    def is_anomalous(self, value: float, threshold: float = 2.0) -> Tuple[bool, float]:
        """Check if a value is anomalous compared to baseline"""
        if self.std_dev == 0:
            return False, 0.0

        z_score = abs(value - self.mean) / self.std_dev
        return z_score > threshold, z_score


class AnomalyDetector:
    """ML-based anomaly detection using multiple algorithms"""

    def __init__(self):
        self.isolation_forest = None
        self.scaler = StandardScaler()
        self.training_data = []
        self.feature_columns = ['hour', 'day_of_week', 'message_length', 'source_entropy']
        self.min_samples = 100
        self.fitted = False

    def extract_features(self, log_entry: Dict[str, Any]) -> np.array:
        """Extract numerical features from log entry"""
        features = []

        # Hour of day (0-23)
        try:
            timestamp = log_entry.get('timestamp')
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = datetime.utcnow()
            features.append(dt.hour)
        except:
            features.append(0)

        # Day of week (0-6, Monday=0)
        try:
            timestamp = log_entry.get('timestamp')
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = datetime.utcnow()
            features.append(dt.weekday())
        except:
            features.append(0)

        # Message length
        message = log_entry.get('message', '')
        features.append(len(str(message)))

        # Source entropy (measure of randomness in source field)
        source = log_entry.get('source', '')
        if source:
            # Simple entropy calculation
            char_counts = defaultdict(int)
            for char in str(source):
                char_counts[char] += 1
            entropy = 0
            for count in char_counts.values():
                p = count / len(str(source))
                entropy -= p * math.log2(p)
            features.append(entropy)
        else:
            features.append(0)

        return np.array(features).reshape(1, -1)

    def train(self, log_entries: List[Dict[str, Any]]) -> bool:
        """Train the anomaly detection model"""
        if len(log_entries) < self.min_samples:
            logger.warning(f"Insufficient data for training. Need at least {self.min_samples} samples.")
            return False

        # Extract features
        features = []
        for entry in log_entries[-self.min_samples:]:  # Use most recent samples
            feat = self.extract_features(entry)
            features.append(feat[0])

        if not features:
            return False

        # Train Isolation Forest
        X = np.array(features)

        # Handle constant features
        if np.all(X == X[0, :]):
            logger.warning("All features are constant. Cannot train anomaly detection.")
            return False

        X_scaled = self.scaler.fit_transform(X)
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Assume 10% anomalies
            random_state=42,
            n_estimators=100
        )
        self.isolation_forest.fit(X_scaled)
        self.fitted = True

        logger.info(f"Trained anomaly detection model with {len(features)} samples")
        return True

    def detect_anomaly(self, log_entry: Dict[str, Any]) -> Optional[AnomalyScore]:
        """Detect if a log entry is anomalous"""
        if not self.fitted or self.isolation_forest is None:
            return None

        try:
            features = self.extract_features(log_entry)

            # Handle constant features
            if np.all(features == features[0]):
                return None

            features_scaled = self.scaler.transform(features)

            # Get anomaly score (-1 for anomalies, 1 for normal)
            raw_score = self.isolation_forest.decision_function(features_scaled)[0]

            # Convert to 0-1 scale (higher = more anomalous)
            anomaly_score = max(0, (1 - raw_score) / 2)

            confidence = min(1.0, anomaly_score * 2)  # Scale confidence

            explanation = f"Isolation Forest anomaly score: {anomaly_score:.3f}"

            return AnomalyScore(
                score=anomaly_score,
                confidence=confidence,
                algorithm="isolation_forest",
                features_used=self.feature_columns.copy(),
                explanation=explanation
            )

        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return None


class BehavioralAnalyzer:
    """Analyzes behavior patterns and detects deviations"""

    def __init__(self):
        self.behavior_profiles = {}  # source -> metric -> profile
        self.source_activity = defaultdict(list)  # Track activity patterns
        self.anomaly_threshold = 2.5

    def update_behavior_profile(self, log_entry: Dict[str, Any]):
        """Update behavioral profiles with new log entry"""
        source = log_entry.get('source', 'unknown')
        timestamp = log_entry.get('timestamp')

        # Update activity patterns
        current_hour = datetime.utcnow().hour
        self.source_activity[source].append(current_hour)

        # Keep only last 24 hours of activity
        cutoff = datetime.utcnow() - timedelta(hours=24)
        if isinstance(timestamp, str):
            try:
                entry_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if entry_time < cutoff:
                    return
            except:
                pass

        # Update numeric metrics
        numeric_fields = ['cpu_percent', 'memory_percent', 'disk_usage_percent', 'response_time_ms']

        for field in numeric_fields:
            if field in log_entry:
                try:
                    value = float(log_entry[field])
                    profile_key = f"{source}:{field}"

                    if profile_key not in self.behavior_profiles:
                        self.behavior_profiles[profile_key] = BehaviorProfile(source, field)

                    self.behavior_profiles[profile_key].update_baseline(value)
                except (ValueError, TypeError):
                    continue

    def analyze_behavior(self, log_entry: Dict[str, Any]) -> List[AnomalyScore]:
        """Analyze log entry for behavioral anomalies"""
        anomalies = []
        source = log_entry.get('source', 'unknown')

        # Check numeric field anomalies
        numeric_fields = ['cpu_percent', 'memory_percent', 'disk_usage_percent', 'response_time_ms']

        for field in numeric_fields:
            if field in log_entry:
                try:
                    value = float(log_entry[field])
                    profile_key = f"{source}:{field}"

                    if profile_key in self.behavior_profiles:
                        profile = self.behavior_profiles[profile_key]
                        is_anomalous, z_score = profile.is_anomalous(value, self.anomaly_threshold)

                        if is_anomalous:
                            confidence = min(1.0, z_score / 5.0)  # Scale confidence
                            anomalies.append(AnomalyScore(
                                score=z_score,
                                confidence=confidence,
                                algorithm="behavioral_analysis",
                                features_used=[field],
                                explanation=f"Value {value} deviates {z_score:.2f} standard deviations from baseline"
                            ))
                except (ValueError, TypeError):
                    continue

        # Check activity pattern anomalies
        current_hour = datetime.utcnow().hour
        if source in self.source_activity:
            recent_hours = list(self.source_activity[source])[-50:]  # Last 50 entries

            if len(recent_hours) > 10:
                # Check if current activity is unusual for this hour
                hour_counts = defaultdict(int)
                for hour in recent_hours:
                    hour_counts[hour] += 1

                expected_count = statistics.mean(hour_counts.values()) if hour_counts else 0
                current_count = hour_counts.get(current_hour, 0)

                if expected_count > 0:
                    deviation = abs(current_count - expected_count) / expected_count
                    if deviation > 2.0:  # More than 2x expected activity
                        anomalies.append(AnomalyScore(
                            score=deviation,
                            confidence=min(1.0, deviation / 5.0),
                            algorithm="activity_pattern",
                            features_used=['hourly_activity'],
                            explanation=f"Unusual activity level for hour {current_hour}: {deviation:.2f}x deviation"
                        ))

        return anomalies


class CorrelationEngine:
    """Detects correlated events across multiple sources"""

    def __init__(self):
        self.event_window = deque(maxlen=1000)  # Last 1000 events
        self.correlation_rules = [
            {
                'name': 'multiple_auth_failures',
                'description': 'Multiple authentication failures across different services',
                'time_window': 300,  # 5 minutes
                'min_events': 5,
                'keywords': ['Failed password', 'Authentication failed', 'Invalid credentials'],
                'source_pattern': r'.*',  # Any source
                'severity': 'high'
            },
            {
                'name': 'coordinated_attack',
                'description': 'Suspicious coordinated activity from multiple IPs',
                'time_window': 60,   # 1 minute
                'min_events': 3,
                'keywords': ['attack', 'exploit', 'intrusion'],
                'source_pattern': r'.*',
                'severity': 'critical'
            }
        ]

    def add_event(self, log_entry: Dict[str, Any]):
        """Add an event to the correlation window"""
        self.event_window.append({
            'timestamp': datetime.utcnow(),
            'entry': log_entry
        })

    def find_correlations(self) -> List[Dict[str, Any]]:
        """Find correlated events based on rules"""
        correlations = []
        current_time = datetime.utcnow()

        for rule in self.correlation_rules:
            window_seconds = rule['time_window']
            cutoff_time = current_time - timedelta(seconds=window_seconds)

            # Get events in time window
            window_events = [
                event for event in self.event_window
                if event['timestamp'] > cutoff_time
            ]

            if len(window_events) >= rule['min_events']:
                matching_events = []

                for event in window_events:
                    entry = event['entry']
                    message = str(entry.get('message', '')).lower()

                    # Check if message contains any keywords
                    if any(keyword.lower() in message for keyword in rule['keywords']):
                        matching_events.append(event)

                if len(matching_events) >= rule['min_events']:
                    correlations.append({
                        'rule_name': rule['name'],
                        'description': rule['description'],
                        'severity': rule['severity'],
                        'event_count': len(matching_events),
                        'time_window': window_seconds,
                        'matched_events': matching_events[-5:],  # Last 5 events
                        'confidence': min(1.0, len(matching_events) / rule['min_events'])
                    })

        return correlations


class AdvancedDetectionEngine:
    """Combines multiple sophisticated detection algorithms"""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.correlation_engine = CorrelationEngine()

        # Training data for anomaly detection
        self.training_buffer = []
        self.min_training_samples = 200

    def process_log_entry(self, log_entry: Dict[str, Any]) -> List[AnomalyScore]:
        """Process a log entry through all detection algorithms"""
        all_anomalies = []

        # Update behavioral profiles
        self.behavioral_analyzer.update_behavior_profile(log_entry)

        # Add to training buffer for anomaly detection
        self.training_buffer.append(log_entry)

        # Add to correlation engine
        self.correlation_engine.add_event(log_entry)

        # Run anomaly detection if trained
        anomaly_result = self.anomaly_detector.detect_anomaly(log_entry)
        if anomaly_result:
            all_anomalies.append(anomaly_result)

        # Run behavioral analysis
        behavioral_anomalies = self.behavioral_analyzer.analyze_behavior(log_entry)
        all_anomalies.extend(behavioral_anomalies)

        # Auto-train anomaly detector if we have enough data
        if (len(self.training_buffer) >= self.min_training_samples and
            not self.anomaly_detector.fitted):
            self._train_anomaly_detector()

        return all_anomalies

    def _train_anomaly_detector(self):
        """Train the anomaly detection model with accumulated data"""
        if len(self.training_buffer) >= self.min_training_samples:
            success = self.anomaly_detector.train(self.training_buffer[-self.min_training_samples:])
            if success:
                logger.info("Advanced anomaly detection model trained and ready")

    def get_correlations(self) -> List[Dict[str, Any]]:
        """Get current correlation findings"""
        return self.correlation_engine.find_correlations()

    def process_batch(self, log_entries: List[Dict[str, Any]]) -> Dict[str, List]:
        """Process a batch of log entries"""
        all_anomalies = []
        correlations = []

        for entry in log_entries:
            anomalies = self.process_log_entry(entry)
            all_anomalies.extend(anomalies)

        correlations = self.get_correlations()

        return {
            'anomalies': all_anomalies,
            'correlations': correlations
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the detection engine"""
        return {
            'training_samples': len(self.training_buffer),
            'behavioral_profiles': len(self.behavioral_analyzer.behavior_profiles),
            'anomaly_detector_trained': self.anomaly_detector.fitted,
            'correlation_window_size': len(self.correlation_engine.event_window)
        }


def main():
    """Test the advanced detection algorithms"""
    print("Testing Advanced Detection Algorithms...")

    # Create sample log entries
    sample_logs = [
        {
            'timestamp': '2023-10-15T14:30:45Z',
            'level': 'warning',
            'message': 'Failed password for invalid user admin',
            'source': 'ssh-service',
            'source_ip': '192.168.1.100'
        },
        {
            'timestamp': '2023-10-15T14:31:00Z',
            'level': 'warning',
            'message': 'High CPU usage detected',
            'source': 'monitoring',
            'cpu_percent': 95.5
        },
        {
            'timestamp': '2023-10-15T14:32:00Z',
            'level': 'error',
            'message': 'Suspicious network activity detected',
            'source': 'firewall',
            'attack_type': 'port_scan'
        }
    ]

    # Initialize detection engine
    engine = AdvancedDetectionEngine()

    # Process logs
    for log in sample_logs:
        anomalies = engine.process_log_entry(log)
        print(f"\nLog: {log['message']}")
        if anomalies:
            for anomaly in anomalies:
                print(f"  -> ANOMALY: {anomaly.algorithm} (score: {anomaly.score:.3f})")
                print(f"     Explanation: {anomaly.explanation}")
        else:
            print("  -> Normal")

    # Check correlations
    correlations = engine.get_correlations()
    if correlations:
        print(f"\nFound {len(correlations)} correlations:")
        for corr in correlations:
            print(f"  - {corr['rule_name']}: {corr['description']}")

    # Print statistics
    stats = engine.get_statistics()
    print(f"\nDetection Engine Statistics: {stats}")


if __name__ == '__main__':
    main()
