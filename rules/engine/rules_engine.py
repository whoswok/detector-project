#!/usr/bin/env python3
"""
Detection Rules Engine for the Detector Project

This module provides a flexible rules engine for detecting security threats,
anomalies, and other patterns in log data.
"""

import re
import json
import yaml
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Callable, Union
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Represents a match result from a detection rule"""
    rule_id: str
    rule_name: str
    severity: str
    description: str
    matched_log: Dict[str, Any]
    matched_fields: Dict[str, Any]
    confidence: float
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DetectionRule:
    """Represents a detection rule"""
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low, info
    category: str  # authentication, network, system, application, etc.

    # Rule conditions
    conditions: Dict[str, Any]

    # Rule actions
    actions: List[str] = field(default_factory=list)

    # Metadata
    author: str = "detector"
    version: str = "1.0"
    enabled: bool = True
    tags: List[str] = field(default_factory=list)

    # Performance settings
    timeout_seconds: int = 30
    max_matches: int = 100


class RuleCondition(ABC):
    """Abstract base class for rule conditions"""

    @abstractmethod
    def evaluate(self, log_entry: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        """
        Evaluate the condition against a log entry
        Returns: (is_match, matched_fields)
        """
        pass


class FieldMatchCondition(RuleCondition):
    """Matches if a field has a specific value or pattern"""

    def __init__(self, field: str, value: Union[str, int, float, bool],
                 operator: str = "equals", case_sensitive: bool = True):
        self.field = field
        self.value = value
        self.operator = operator
        self.case_sensitive = case_sensitive

    def evaluate(self, log_entry: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        if self.field not in log_entry:
            return False, {}

        field_value = log_entry[self.field]

        if self.operator == "equals":
            if not self.case_sensitive and isinstance(field_value, str) and isinstance(self.value, str):
                match = field_value.lower() == str(self.value).lower()
            else:
                match = field_value == self.value
        elif self.operator == "contains":
            if not self.case_sensitive and isinstance(field_value, str):
                match = str(self.value).lower() in field_value.lower()
            else:
                match = str(self.value) in str(field_value)
        elif self.operator == "regex":
            try:
                flags = 0 if self.case_sensitive else re.IGNORECASE
                match = bool(re.search(str(self.value), str(field_value), flags))
            except re.error:
                return False, {}
        elif self.operator == "greater_than":
            try:
                match = float(field_value) > float(self.value)
            except (ValueError, TypeError):
                return False, {}
        elif self.operator == "less_than":
            try:
                match = float(field_value) < float(self.value)
            except (ValueError, TypeError):
                return False, {}
        elif self.operator == "in":
            if isinstance(self.value, list):
                match = field_value in self.value
            else:
                return False, {}
        else:
            return False, {}

        matched_fields = {self.field: field_value} if match else {}
        return match, matched_fields


class CompositeCondition(RuleCondition):
    """Combines multiple conditions with logical operators"""

    def __init__(self, conditions: List[RuleCondition], operator: str = "AND"):
        self.conditions = conditions
        self.operator = operator.upper()

    def evaluate(self, log_entry: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        all_matched_fields = {}

        if self.operator == "AND":
            for condition in self.conditions:
                match, matched_fields = condition.evaluate(log_entry)
                if not match:
                    return False, {}
                all_matched_fields.update(matched_fields)
            return True, all_matched_fields

        elif self.operator == "OR":
            for condition in self.conditions:
                match, matched_fields = condition.evaluate(log_entry)
                if match:
                    all_matched_fields.update(matched_fields)
                    return True, all_matched_fields
            return False, {}

        elif self.operator == "NOT":
            if len(self.conditions) == 1:
                match, matched_fields = self.conditions[0].evaluate(log_entry)
                return not match, matched_fields
            else:
                raise ValueError("NOT operator can only have one condition")

        return False, {}


class TimeWindowCondition(RuleCondition):
    """Matches events within a time window"""

    def __init__(self, field: str, window_seconds: int, min_occurrences: int = 1):
        self.field = field
        self.window_seconds = window_seconds
        self.min_occurrences = min_occurrences
        self.recent_events = []

    def evaluate(self, log_entry: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(seconds=self.window_seconds)

        # Add current event
        event_time = log_entry.get(self.field)
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            except ValueError:
                return False, {}

        if event_time:
            self.recent_events.append((current_time, log_entry))

        # Clean old events
        self.recent_events = [(time, event) for time, event in self.recent_events
                            if time > cutoff_time]

        # Check if we have enough events
        match = len(self.recent_events) >= self.min_occurrences

        return match, {"event_count": len(self.recent_events)}


class RuleEngine:
    """Main rules engine for processing detection rules"""

    def __init__(self, rules: List[DetectionRule]):
        self.rules = {rule.id: rule for rule in rules if rule.enabled}
        self.conditions_cache = {}

    def add_rule(self, rule: DetectionRule):
        """Add a new rule to the engine"""
        if rule.enabled:
            self.rules[rule.id] = rule

    def remove_rule(self, rule_id: str):
        """Remove a rule from the engine"""
        self.rules.pop(rule_id, None)

    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """Get a rule by ID"""
        return self.rules.get(rule_id)

    def list_rules(self) -> List[DetectionRule]:
        """List all active rules"""
        return list(self.rules.values())

    def build_condition(self, condition_config: Dict[str, Any]) -> RuleCondition:
        """Build a condition from configuration"""
        condition_type = condition_config.get('type', 'field_match')

        if condition_type == 'field_match':
            return FieldMatchCondition(
                field=condition_config['field'],
                value=condition_config['value'],
                operator=condition_config.get('operator', 'equals'),
                case_sensitive=condition_config.get('case_sensitive', True)
            )

        elif condition_type == 'composite':
            sub_conditions = [
                self.build_condition(sub_config)
                for sub_config in condition_config['conditions']
            ]
            return CompositeCondition(
                conditions=sub_conditions,
                operator=condition_config.get('operator', 'AND')
            )

        elif condition_type == 'time_window':
            return TimeWindowCondition(
                field=condition_config['field'],
                window_seconds=condition_config['window_seconds'],
                min_occurrences=condition_config.get('min_occurrences', 1)
            )

        else:
            raise ValueError(f"Unknown condition type: {condition_type}")

    def evaluate_rule(self, rule: DetectionRule, log_entry: Dict[str, Any]) -> List[RuleMatch]:
        """Evaluate a single rule against a log entry"""
        matches = []

        try:
            # Build condition if not cached
            if rule.id not in self.conditions_cache:
                self.conditions_cache[rule.id] = self.build_condition(rule.conditions)

            condition = self.conditions_cache[rule.id]
            is_match, matched_fields = condition.evaluate(log_entry)

            if is_match:
                # Calculate confidence based on matched fields
                confidence = min(1.0, len(matched_fields) * 0.2)

                match = RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    matched_log=log_entry,
                    matched_fields=matched_fields,
                    confidence=confidence
                )
                matches.append(match)

        except Exception as e:
            logger.error(f"Error evaluating rule {rule.id}: {e}")

        return matches

    def process_log_entry(self, log_entry: Dict[str, Any]) -> List[RuleMatch]:
        """Process a single log entry against all rules"""
        all_matches = []

        for rule in self.rules.values():
            matches = self.evaluate_rule(rule, log_entry)
            all_matches.extend(matches)

        return all_matches

    def process_log_batch(self, log_entries: List[Dict[str, Any]]) -> List[RuleMatch]:
        """Process a batch of log entries"""
        all_matches = []

        for entry in log_entries:
            matches = self.process_log_entry(entry)
            all_matches.extend(matches)

        return all_matches

    def save_rules(self, file_path: str, format: str = 'yaml'):
        """Save rules to a file"""
        rules_data = [rule.__dict__ for rule in self.rules.values()]

        if format.lower() == 'yaml':
            with open(file_path, 'w') as f:
                yaml.dump(rules_data, f, default_flow_style=False)
        elif format.lower() == 'json':
            with open(file_path, 'w') as f:
                json.dump(rules_data, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {format}")

    @classmethod
    def load_rules(cls, file_path: str) -> List[DetectionRule]:
        """Load rules from a file"""
        with open(file_path, 'r') as f:
            if file_path.endswith('.yaml') or file_path.endswith('.yml'):
                rules_data = yaml.safe_load(f)
            elif file_path.endswith('.json'):
                rules_data = json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {file_path}")

        rules = []
        for rule_data in rules_data:
            rule = DetectionRule(**rule_data)
            rules.append(rule)

        return rules


def create_sample_rules() -> List[DetectionRule]:
    """Create sample detection rules for testing"""

    rules = [
        # SSH brute force detection
        DetectionRule(
            id="ssh_brute_force",
            name="SSH Brute Force Attack",
            description="Multiple failed SSH login attempts from same IP",
            severity="high",
            category="authentication",
            conditions={
                'type': 'composite',
                'operator': 'AND',
                'conditions': [
                    {
                        'type': 'field_match',
                        'field': 'message',
                        'value': 'Failed password',
                        'operator': 'contains'
                    },
                    {
                        'type': 'field_match',
                        'field': 'source',
                        'value': 'sshd',
                        'operator': 'contains'
                    }
                ]
            },
            actions=['alert', 'block_ip'],
            tags=['ssh', 'brute-force', 'authentication']
        ),

        # High CPU usage
        DetectionRule(
            id="high_cpu_usage",
            name="High CPU Usage",
            description="CPU usage exceeds 90%",
            severity="medium",
            category="system",
            conditions={
                'type': 'field_match',
                'field': 'cpu_percent',
                'value': 90,
                'operator': 'greater_than'
            },
            actions=['alert', 'scale_resources'],
            tags=['performance', 'cpu', 'monitoring']
        ),

        # Security breach detection
        DetectionRule(
            id="security_breach",
            name="Security Breach Detected",
            description="Critical security events",
            severity="critical",
            category="security",
            conditions={
                'type': 'composite',
                'operator': 'OR',
                'conditions': [
                    {
                        'type': 'field_match',
                        'field': 'message',
                        'value': 'Security breach detected',
                        'operator': 'contains'
                    },
                    {
                        'type': 'field_match',
                        'field': 'threat_level',
                        'value': 'high',
                        'operator': 'equals'
                    }
                ]
            },
            actions=['alert', 'escalate', 'investigate'],
            tags=['security', 'breach', 'critical']
        ),

        # Database connection failures
        DetectionRule(
            id="db_connection_failure",
            name="Database Connection Failure",
            description="Multiple database connection failures",
            severity="medium",
            category="application",
            conditions={
                'type': 'field_match',
                'field': 'message',
                'value': 'Database connection failed',
                'operator': 'contains'
            },
            actions=['alert', 'restart_service'],
            tags=['database', 'connection', 'failure']
        ),

        # Suspicious login pattern (time-based)
        DetectionRule(
            id="suspicious_login_time",
            name="Suspicious Login Time",
            description="Login attempts outside normal business hours",
            severity="low",
            category="authentication",
            conditions={
                'type': 'time_window',
                'field': 'timestamp',
                'window_seconds': 300,  # 5 minutes
                'min_occurrences': 3
            },
            actions=['log', 'monitor'],
            tags=['authentication', 'time-based', 'suspicious']
        )
    ]

    return rules


def main():
    """Main function for testing the rules engine"""
    print("Creating sample rules...")
    rules = create_sample_rules()

    print(f"Created {len(rules)} detection rules:")
    for rule in rules:
        print(f"- {rule.name} ({rule.severity})")

    print("\nCreating rules engine...")
    engine = RuleEngine(rules)

    # Test with sample log entries
    print("\nTesting with sample log entries...")

    sample_logs = [
        {
            'timestamp': '2023-10-15T14:30:45Z',
            'level': 'warning',
            'message': 'Failed password for invalid user admin from 192.168.1.100',
            'source': 'sshd'
        },
        {
            'timestamp': '2023-10-15T14:31:00Z',
            'level': 'warning',
            'message': 'High CPU usage detected',
            'source': 'monitoring',
            'cpu_percent': 95.5
        },
        {
            'timestamp': '2023-10-15T14:35:00Z',
            'level': 'critical',
            'message': 'Security breach detected',
            'source': 'security-service',
            'threat_level': 'high'
        }
    ]

    for log in sample_logs:
        matches = engine.process_log_entry(log)
        if matches:
            print(f"\nLog: {log['message']}")
            for match in matches:
                print(f"  -> MATCH: {match.rule_name} (confidence: {match.confidence:.2f})")
        else:
            print(f"\nLog: {log['message']} -> No matches")


if __name__ == '__main__':
    main()
