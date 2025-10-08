#!/usr/bin/env python3
"""
Alerting and Webhook System for the Detector Project

This module provides a comprehensive alerting system that can send notifications
to various services including Slack, email, PagerDuty, and custom webhooks.
"""

import json
import smtplib
import requests
import asyncio
import aiohttp
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging
import os
from abc import ABC, abstractmethod

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class Alert:
    """Represents an alert to be sent"""
    id: str
    title: str
    message: str
    severity: str  # critical, high, medium, low, info
    source: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)


@dataclass
class AlertChannel:
    """Configuration for an alert channel"""
    name: str
    type: str  # slack, email, pagerduty, webhook, etc.
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    severity_filter: List[str] = field(default_factory=lambda: ['critical', 'high', 'medium'])


class AlertChannelBase(ABC):
    """Abstract base class for alert channels"""

    @abstractmethod
    def send_alert(self, alert: Alert) -> bool:
        """Send an alert through this channel"""
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """Test if the channel connection is working"""
        pass


class SlackChannel(AlertChannelBase):
    """Slack webhook integration"""

    def __init__(self, webhook_url: str, channel: str = None, username: str = "Detector Alert"):
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username

    def send_alert(self, alert: Alert) -> bool:
        """Send alert to Slack"""
        try:
            # Color based on severity
            color_map = {
                'critical': '#FF0000',
                'high': '#FF8C00',
                'medium': '#FFD700',
                'low': '#32CD32',
                'info': '#87CEEB'
            }
            color = color_map.get(alert.severity, '#87CEEB')

            # Format message
            payload = {
                "username": self.username,
                "attachments": [
                    {
                        "color": color,
                        "title": alert.title,
                        "text": alert.message,
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert.severity.upper(),
                                "short": True
                            },
                            {
                                "title": "Source",
                                "value": alert.source,
                                "short": True
                            },
                            {
                                "title": "Timestamp",
                                "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                "short": True
                            }
                        ],
                        "footer": "Detector Security System",
                        "ts": int(alert.timestamp.timestamp())
                    }
                ]
            }

            if self.channel:
                payload["channel"] = self.channel

            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"Alert sent to Slack: {alert.title}")
                return True
            else:
                logger.error(f"Failed to send Slack alert: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test Slack webhook connection"""
        try:
            payload = {
                "username": self.username,
                "text": "🧪 Detector Alert System - Test message"
            }
            if self.channel:
                payload["channel"] = self.channel

            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Slack connection test failed: {e}")
            return False


class EmailChannel(AlertChannelBase):
    """Email notification integration"""

    def __init__(self, smtp_server: str, smtp_port: int, username: str, password: str,
                 from_email: str, to_emails: List[str]):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_emails = to_emails

    def send_alert(self, alert: Alert) -> bool:
        """Send alert via email"""
        try:
            msg = MimeMultipart()
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            msg['Subject'] = f"[DETECTOR ALERT - {alert.severity.upper()}] {alert.title}"

            # Email body
            body = f"""
Detector Security Alert

Title: {alert.title}
Severity: {alert.severity.upper()}
Source: {alert.source}
Timestamp: {alert.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}

Message:
{alert.message}

Metadata:
{json.dumps(alert.metadata, indent=2)}

Tags: {', '.join(alert.tags)}

---
This alert was generated by the Detector Security System.
"""

            msg.attach(MimeText(body, 'plain'))

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f"Alert email sent: {alert.title}")
            return True

        except Exception as e:
            logger.error(f"Error sending email alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test email connection"""
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                return True
        except Exception as e:
            logger.error(f"Email connection test failed: {e}")
            return False


class PagerDutyChannel(AlertChannelBase):
    """PagerDuty integration"""

    def __init__(self, routing_key: str, api_base: str = "https://events.pagerduty.com"):
        self.routing_key = routing_key
        self.api_base = api_base

    def send_alert(self, alert: Alert) -> bool:
        """Send alert to PagerDuty"""
        try:
            # Map severity levels
            severity_map = {
                'critical': 'critical',
                'high': 'error',
                'medium': 'warning',
                'low': 'info',
                'info': 'info'
            }
            pagerduty_severity = severity_map.get(alert.severity, 'info')

            payload = {
                "routing_key": self.routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": alert.title,
                    "source": alert.source,
                    "severity": pagerduty_severity,
                    "component": "Detector Security System",
                    "group": alert.metadata.get('rule_id', 'detector'),
                    "class": alert.severity,
                    "custom_details": {
                        "message": alert.message,
                        "metadata": alert.metadata,
                        "tags": alert.tags,
                        "actions": alert.actions
                    }
                }
            }

            response = requests.post(
                f"{self.api_base}/v2/enqueue",
                json=payload,
                timeout=10
            )

            if response.status_code == 202:
                logger.info(f"PagerDuty alert sent: {alert.title}")
                return True
            else:
                logger.error(f"Failed to send PagerDuty alert: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Error sending PagerDuty alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test PagerDuty connection"""
        try:
            # Send a test event
            payload = {
                "routing_key": self.routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": "Detector Test Alert",
                    "source": "test",
                    "severity": "info",
                    "component": "Detector Test"
                }
            }

            response = requests.post(
                f"{self.api_base}/v2/enqueue",
                json=payload,
                timeout=5
            )
            return response.status_code == 202
        except Exception as e:
            logger.error(f"PagerDuty connection test failed: {e}")
            return False


class WebhookChannel(AlertChannelBase):
    """Generic webhook integration"""

    def __init__(self, webhook_url: str, headers: Dict[str, str] = None,
                 template: str = None, method: str = "POST"):
        self.webhook_url = webhook_url
        self.headers = headers or {"Content-Type": "application/json"}
        self.template = template
        self.method = method

    def send_alert(self, alert: Alert) -> bool:
        """Send alert via webhook"""
        try:
            # Prepare payload
            payload = {
                "alert_id": alert.id,
                "title": alert.title,
                "message": alert.message,
                "severity": alert.severity,
                "source": alert.source,
                "timestamp": alert.timestamp.isoformat(),
                "metadata": alert.metadata,
                "tags": alert.tags,
                "actions": alert.actions
            }

            # Apply custom template if provided
            if self.template:
                try:
                    payload = json.loads(self.template.format(**payload))
                except Exception as e:
                    logger.warning(f"Failed to apply webhook template: {e}")

            response = requests.request(
                method=self.method,
                url=self.webhook_url,
                json=payload,
                headers=self.headers,
                timeout=10
            )

            if response.status_code in [200, 201, 202, 204]:
                logger.info(f"Webhook alert sent: {alert.title}")
                return True
            else:
                logger.error(f"Webhook alert failed: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Error sending webhook alert: {e}")
            return False

    def test_connection(self) -> bool:
        """Test webhook connection"""
        try:
            payload = {
                "test": True,
                "message": "Detector webhook test",
                "timestamp": datetime.utcnow().isoformat()
            }

            response = requests.request(
                method=self.method,
                url=self.webhook_url,
                json=payload,
                headers=self.headers,
                timeout=5
            )
            return response.status_code in [200, 201, 202, 204]
        except Exception as e:
            logger.error(f"Webhook connection test failed: {e}")
            return False


class AlertManager:
    """Manages multiple alert channels and routing"""

    def __init__(self):
        self.channels = {}  # name -> channel instance
        self.default_channels = ['slack', 'email']  # Default channels to use

    def add_channel(self, channel: AlertChannel) -> bool:
        """Add an alert channel"""
        try:
            if channel.test_connection():
                self.channels[channel.name] = channel
                logger.info(f"Added alert channel: {channel.name} ({channel.type})")
                return True
            else:
                logger.error(f"Failed to add channel {channel.name}: connection test failed")
                return False
        except Exception as e:
            logger.error(f"Error adding alert channel {channel.name}: {e}")
            return False

    def remove_channel(self, name: str):
        """Remove an alert channel"""
        if name in self.channels:
            del self.channels[name]
            logger.info(f"Removed alert channel: {name}")

    def send_alert(self, alert: Alert, channels: List[str] = None) -> Dict[str, bool]:
        """Send alert to specified channels or default channels"""
        if channels is None:
            channels = self.default_channels

        results = {}

        for channel_name in channels:
            if channel_name in self.channels:
                channel = self.channels[channel_name]
                if channel.enabled:
                    # Check severity filter
                    if alert.severity in channel.severity_filter:
                        success = channel.send_alert(alert)
                        results[channel_name] = success
                    else:
                        results[channel_name] = True  # Skipped due to filter
                        logger.debug(f"Alert skipped for {channel_name}: severity {alert.severity} not in filter")
                else:
                    results[channel_name] = False
                    logger.debug(f"Alert skipped for {channel_name}: channel disabled")
            else:
                results[channel_name] = False
                logger.warning(f"Alert channel not found: {channel_name}")

        return results

    def send_alerts_batch(self, alerts: List[Alert], channels: List[str] = None) -> Dict[str, List[bool]]:
        """Send multiple alerts to specified channels"""
        results = {channel: [] for channel in (channels or self.default_channels)}

        for alert in alerts:
            alert_results = self.send_alert(alert, channels)
            for channel, success in alert_results.items():
                results[channel].append(success)

        return results

    def test_all_channels(self) -> Dict[str, bool]:
        """Test all configured channels"""
        results = {}
        for name, channel in self.channels.items():
            results[name] = channel.test_connection()
        return results

    def get_channel_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all channels"""
        status = {}
        for name, channel in self.channels.items():
            status[name] = {
                'type': channel.type,
                'enabled': channel.enabled,
                'severity_filter': channel.severity_filter,
                'test_connection': channel.test_connection()
            }
        return status


def create_sample_channels() -> Dict[str, AlertChannel]:
    """Create sample alert channels for testing"""
    channels = {}

    # Slack channel (requires webhook URL)
    if 'SLACK_WEBHOOK_URL' in os.environ:
        channels['slack'] = AlertChannel(
            name='slack',
            type='slack',
            config={'webhook_url': os.environ['SLACK_WEBHOOK_URL']}
        )

    # Email channel (requires SMTP settings)
    if all(k in os.environ for k in ['SMTP_SERVER', 'SMTP_USERNAME', 'SMTP_PASSWORD']):
        channels['email'] = AlertChannel(
            name='email',
            type='email',
            config={
                'smtp_server': os.environ['SMTP_SERVER'],
                'smtp_port': int(os.environ.get('SMTP_PORT', 587)),
                'username': os.environ['SMTP_USERNAME'],
                'password': os.environ['SMTP_PASSWORD'],
                'from_email': os.environ.get('FROM_EMAIL', os.environ['SMTP_USERNAME']),
                'to_emails': os.environ.get('TO_EMAILS', 'admin@example.com').split(',')
            }
        )

    # PagerDuty channel (requires routing key)
    if 'PAGERDUTY_ROUTING_KEY' in os.environ:
        channels['pagerduty'] = AlertChannel(
            name='pagerduty',
            type='pagerduty',
            config={'routing_key': os.environ['PAGERDUTY_ROUTING_KEY']}
        )

    # Generic webhook channel
    if 'WEBHOOK_URL' in os.environ:
        channels['webhook'] = AlertChannel(
            name='webhook',
            type='webhook',
            config={
                'webhook_url': os.environ['WEBHOOK_URL'],
                'headers': json.loads(os.environ.get('WEBHOOK_HEADERS', '{}')),
                'method': os.environ.get('WEBHOOK_METHOD', 'POST')
            }
        )

    return channels


def main():
    """Test the alerting system"""
    print("Testing Alerting System...")

    # Create alert manager
    alert_manager = AlertManager()

    # Add sample channels (will only work if environment variables are set)
    channels = create_sample_channels()

    for name, channel in channels.items():
        success = alert_manager.add_channel(channel)
        print(f"Added {name} channel: {'✅' if success else '❌'}")

    if not alert_manager.channels:
        print("No channels configured. Set environment variables to test:")
        print("- SLACK_WEBHOOK_URL")
        print("- SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD")
        print("- PAGERDUTY_ROUTING_KEY")
        print("- WEBHOOK_URL")
        return

    # Create test alert
    test_alert = Alert(
        id="test-alert-001",
        title="Test Security Alert",
        message="This is a test alert from the Detector system",
        severity="high",
        source="test-system",
        timestamp=datetime.utcnow(),
        metadata={"test": True, "category": "test"},
        tags=["test", "security"]
    )

    # Send test alert
    print(f"\nSending test alert: {test_alert.title}")
    results = alert_manager.send_alert(test_alert)

    for channel, success in results.items():
        status = "✅" if success else "❌"
        print(f"  {channel}: {status}")

    # Test all channels
    print("\nTesting all channel connections...")
    test_results = alert_manager.test_all_channels()

    for channel, working in test_results.items():
        status = "✅" if working else "❌"
        print(f"  {channel}: {status}")


if __name__ == '__main__':
    main()
