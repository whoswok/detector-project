#!/usr/bin/env python3
"""
Detector Parser Service

This service parses various log formats and sends structured data to Elasticsearch.
Supports syslog, JSON, and CSV log formats with extensible architecture.
"""

import json
import re
import csv
import sys
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from elasticsearch import Elasticsearch
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """Represents a parsed log entry"""
    timestamp: Optional[datetime]
    level: str
    message: str
    source: str
    metadata: Dict[str, Any]
    raw_log: str


class LogParser(ABC):
    """Abstract base class for log parsers"""

    @abstractmethod
    def can_parse(self, log_line: str) -> bool:
        """Check if this parser can handle the given log line"""
        pass

    @abstractmethod
    def parse(self, log_line: str) -> Optional[LogEntry]:
        """Parse the log line into a LogEntry"""
        pass


class SyslogParser(LogParser):
    """Parser for syslog format logs"""

    # Syslog pattern: <priority>timestamp hostname process: message
    SYSLOG_PATTERN = re.compile(
        r'<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+):\s*(.+)',
        re.IGNORECASE
    )

    PRIORITY_MAP = {
        0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
        4: 'warning', 5: 'notice', 6: 'info', 7: 'debug'
    }

    def can_parse(self, log_line: str) -> bool:
        return self.SYSLOG_PATTERN.match(log_line.strip()) is not None

    def parse(self, log_line: str) -> Optional[LogEntry]:
        match = self.SYSLOG_PATTERN.match(log_line.strip())
        if not match:
            return None

        priority, timestamp_str, hostname, process, message = match.groups()

        try:
            # Parse syslog timestamp (e.g., "Jan 15 10:30:45")
            dt = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
            # Assume current year if not specified
            now = datetime.now()
            timestamp = dt.replace(year=now.year)
        except ValueError:
            timestamp = None

        priority_num = int(priority) & 0x07  # Extract facility
        level = self.PRIORITY_MAP.get(priority_num, 'unknown')

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=message,
            source=f"{hostname}:{process}",
            metadata={'priority': priority, 'facility': int(priority) >> 3},
            raw_log=log_line.strip()
        )


class JSONLogParser(LogParser):
    """Parser for JSON format logs"""

    def can_parse(self, log_line: str) -> bool:
        stripped = log_line.strip()
        return stripped.startswith('{') and stripped.endswith('}')

    def parse(self, log_line: str) -> Optional[LogEntry]:
        try:
            data = json.loads(log_line.strip())

            # Extract common fields
            timestamp_str = data.get('timestamp', data.get('time', data.get('@timestamp')))
            timestamp = None
            if timestamp_str:
                try:
                    if isinstance(timestamp_str, str):
                        # Try ISO format first
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    else:
                        timestamp = datetime.fromtimestamp(timestamp_str)
                except (ValueError, TypeError):
                    pass

            level = data.get('level', data.get('severity', 'info')).lower()
            message = data.get('message', data.get('msg', str(data)))
            source = data.get('source', data.get('hostname', 'unknown'))

            # Remove known fields from metadata
            metadata = {k: v for k, v in data.items()
                       if k not in ['timestamp', 'time', '@timestamp', 'level', 'severity',
                                  'message', 'msg', 'source', 'hostname']}

            return LogEntry(
                timestamp=timestamp,
                level=level,
                message=message,
                source=source,
                metadata=metadata,
                raw_log=log_line.strip()
            )
        except json.JSONDecodeError:
            return None


class CSVLogParser(LogParser):
    """Parser for CSV format logs (first row should be headers)"""

    def __init__(self):
        self.headers = None

    def can_parse(self, log_line: str) -> bool:
        # Assume CSV if it contains commas and doesn't match other patterns
        stripped = log_line.strip()
        return ',' in stripped and not stripped.startswith('<') and not stripped.startswith('{')

    def parse(self, log_line: str) -> Optional[LogEntry]:
        try:
            # Simple CSV parsing (assumes quoted values with comma separator)
            reader = csv.reader([log_line.strip()], quotechar='"')
            values = next(reader)

            if self.headers is None:
                self.headers = values
                return None  # Skip header row

            if len(values) != len(self.headers):
                return None

            data = dict(zip(self.headers, values))

            # Extract common fields
            timestamp_str = data.get('timestamp', data.get('time'))
            timestamp = None
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except (ValueError, TypeError):
                    pass

            level = data.get('level', data.get('severity', 'info')).lower()
            message = data.get('message', data.get('msg', log_line.strip()))
            source = data.get('source', data.get('hostname', 'csv-import'))

            # Remove known fields from metadata
            metadata = {k: v for k, v in data.items()
                       if k not in ['timestamp', 'time', 'level', 'severity',
                                  'message', 'msg', 'source', 'hostname']}

            return LogEntry(
                timestamp=timestamp,
                level=level,
                message=message,
                source=source,
                metadata=metadata,
                raw_log=log_line.strip()
            )
        except (csv.Error, StopIteration):
            return None


class DetectorParser:
    """Main parser class that coordinates multiple log parsers"""

    def __init__(self, elasticsearch_host='localhost', elasticsearch_port=9200):
        self.parsers = [
            JSONLogParser(),
            SyslogParser(),
            CSVLogParser()
        ]
        self.es = Elasticsearch([f'http://{elasticsearch_host}:{elasticsearch_port}'])
        self.index_name = 'detector-logs'

    def parse_log_line(self, log_line: str) -> Optional[LogEntry]:
        """Parse a single log line using appropriate parser"""
        for parser in self.parsers:
            if parser.can_parse(log_line):
                return parser.parse(log_line)
        return None

    def send_to_elasticsearch(self, entry: LogEntry) -> bool:
        """Send parsed log entry to Elasticsearch"""
        try:
            doc = {
                'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                'level': entry.level,
                'message': entry.message,
                'source': entry.source,
                'metadata': entry.metadata,
                'raw_log': entry.raw_log,
                '@timestamp': datetime.utcnow().isoformat() + 'Z'
            }

            response = self.es.index(
                index=self.index_name,
                document=doc
            )
            logger.info(f"Indexed document: {response['_id']}")
            return True
        except Exception as e:
            logger.error(f"Failed to index document: {e}")
            return False

    def process_log_file(self, file_path: str) -> int:
        """Process an entire log file"""
        processed = 0
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    entry = self.parse_log_line(line)
                    if entry:
                        if self.send_to_elasticsearch(entry):
                            processed += 1

        except FileNotFoundError:
            logger.error(f"Log file not found: {file_path}")
        except Exception as e:
            logger.error(f"Error processing log file: {e}")

        return processed

    def process_log_stream(self, log_lines: List[str]) -> int:
        """Process a list of log lines"""
        processed = 0
        for line in log_lines:
            line = line.strip()
            if not line:
                continue

            entry = self.parse_log_line(line)
            if entry:
                if self.send_to_elasticsearch(entry):
                    processed += 1

        return processed


def main():
    """Main entry point for the parser service"""
    import argparse

    parser = argparse.ArgumentParser(description='Detector Log Parser')
    parser.add_argument('--file', '-f', help='Log file to process')
    parser.add_argument('--host', default='localhost', help='Elasticsearch host')
    parser.add_argument('--port', type=int, default=9200, help='Elasticsearch port')
    parser.add_argument('--index', default='detector-logs', help='Elasticsearch index name')

    args = parser.parse_args()

    detector_parser = DetectorParser(args.host, args.port)

    if args.file:
        logger.info(f"Processing log file: {args.file}")
        processed = detector_parser.process_log_file(args.file)
        logger.info(f"Processed {processed} log entries")
    else:
        logger.info("Reading from stdin...")
        import sys
        lines = sys.stdin.readlines()
        processed = detector_parser.process_log_stream(lines)
        logger.info(f"Processed {processed} log entries from stdin")


if __name__ == '__main__':
    main()
