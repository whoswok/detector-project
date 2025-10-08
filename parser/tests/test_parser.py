#!/usr/bin/env python3
"""
Comprehensive tests for the Detector Parser Service
"""

import pytest
import json
from datetime import datetime
from unittest.mock import Mock, patch
from parser import (
    LogEntry, LogParser, SyslogParser, JSONLogParser,
    CSVLogParser, DetectorParser
)


class TestLogEntry:
    """Test the LogEntry dataclass"""

    def test_log_entry_creation(self):
        """Test creating a LogEntry instance"""
        entry = LogEntry(
            timestamp=datetime.now(),
            level='info',
            message='Test message',
            source='test-source',
            metadata={'key': 'value'},
            raw_log='raw log line'
        )

        assert entry.level == 'info'
        assert entry.message == 'Test message'
        assert entry.source == 'test-source'
        assert entry.metadata == {'key': 'value'}
        assert entry.raw_log == 'raw log line'


class TestSyslogParser:
    """Test the SyslogParser class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.parser = SyslogParser()

    def test_can_parse_valid_syslog(self):
        """Test that valid syslog lines are recognized"""
        valid_syslog = '<34>Oct 15 14:30:45 server1 sshd[12345]: Failed password for invalid user admin'
        assert self.parser.can_parse(valid_syslog) is True

    def test_can_parse_invalid_syslog(self):
        """Test that invalid syslog lines are not recognized"""
        invalid_syslog = 'This is not a syslog line'
        assert self.parser.can_parse(invalid_syslog) is False

        json_line = '{"timestamp": "2023-10-15T14:30:45Z", "message": "test"}'
        assert self.parser.can_parse(json_line) is False

    def test_parse_valid_syslog(self):
        """Test parsing a valid syslog line"""
        syslog_line = '<34>Oct 15 14:30:45 server1 sshd[12345]: Failed password for invalid user admin'

        entry = self.parser.parse(syslog_line)

        assert entry is not None
        assert entry.level == 'warning'  # Priority 34 & 0x07 = 2 (warning)
        assert entry.message == 'Failed password for invalid user admin'
        assert entry.source == 'server1:sshd[12345]'
        assert entry.metadata['priority'] == '34'
        assert entry.metadata['facility'] == 4  # 34 >> 3 = 4
        assert entry.raw_log == syslog_line

    def test_parse_syslog_with_different_priority(self):
        """Test parsing syslog with different priority levels"""
        test_cases = [
            ('<0>Oct 15 14:30:45 server1 kernel: Emergency situation', 'emergency'),
            ('<1>Oct 15 14:30:45 server1 kernel: Alert message', 'alert'),
            ('<2>Oct 15 14:30:45 server1 kernel: Critical error', 'critical'),
            ('<3>Oct 15 14:30:45 server1 kernel: Error occurred', 'error'),
            ('<4>Oct 15 14:30:45 server1 kernel: Warning message', 'warning'),
            ('<5>Oct 15 14:30:45 server1 kernel: Notice message', 'notice'),
            ('<6>Oct 15 14:30:45 server1 kernel: Info message', 'info'),
            ('<7>Oct 15 14:30:45 server1 kernel: Debug message', 'debug'),
        ]

        for syslog_line, expected_level in test_cases:
            entry = self.parser.parse(syslog_line)
            assert entry is not None
            assert entry.level == expected_level

    def test_parse_invalid_syslog(self):
        """Test that invalid syslog lines return None"""
        invalid_cases = [
            'Not a syslog line',
            '<invalid>Oct 15 14:30:45 server1 process: message',
            '<34>Invalid timestamp server1 process: message',
        ]

        for invalid_line in invalid_cases:
            assert self.parser.parse(invalid_line) is None


class TestJSONLogParser:
    """Test the JSONLogParser class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.parser = JSONLogParser()

    def test_can_parse_valid_json(self):
        """Test that valid JSON lines are recognized"""
        valid_json = '{"timestamp": "2023-10-15T14:30:45Z", "level": "error", "message": "Test error"}'
        assert self.parser.can_parse(valid_json) is True

    def test_can_parse_invalid_json(self):
        """Test that invalid JSON lines are not recognized"""
        invalid_cases = [
            'Not JSON',
            '{invalid json}',
            '<34>Oct 15 14:30:45 server1 process: message',
        ]

        for invalid_line in invalid_cases:
            assert self.parser.can_parse(invalid_line) is False

    def test_parse_valid_json(self):
        """Test parsing a valid JSON log line"""
        json_line = '{"timestamp": "2023-10-15T14:30:45Z", "level": "error", "message": "Database connection failed", "source": "web-app"}'

        entry = self.parser.parse(json_line)

        assert entry is not None
        assert entry.level == 'error'
        assert entry.message == 'Database connection failed'
        assert entry.source == 'web-app'
        assert entry.metadata == {}
        assert entry.raw_log == json_line

    def test_parse_json_with_metadata(self):
        """Test parsing JSON with additional metadata"""
        json_line = '''
        {
            "timestamp": "2023-10-15T14:30:45Z",
            "level": "warning",
            "message": "High CPU usage",
            "source": "monitoring",
            "cpu_percent": 95.5,
            "server_id": "srv-001"
        }
        '''.strip()

        entry = self.parser.parse(json_line)

        assert entry is not None
        assert entry.level == 'warning'
        assert entry.message == 'High CPU usage'
        assert entry.source == 'monitoring'
        assert entry.metadata == {'cpu_percent': 95.5, 'server_id': 'srv-001'}

    def test_parse_json_with_different_timestamp_formats(self):
        """Test parsing JSON with different timestamp field names"""
        test_cases = [
            '{"@timestamp": "2023-10-15T14:30:45Z", "message": "test"}',
            '{"time": "2023-10-15T14:30:45Z", "message": "test"}',
            '{"timestamp": 1697377845.123, "message": "test"}',
        ]

        for json_line in test_cases:
            entry = self.parser.parse(json_line)
            assert entry is not None
            assert entry.message == 'test'

    def test_parse_invalid_json(self):
        """Test that invalid JSON returns None"""
        invalid_cases = [
            '{invalid json}',
            '{"missing": "closing brace"',
            'not json at all',
        ]

        for invalid_line in invalid_cases:
            assert self.parser.parse(invalid_line) is None


class TestCSVLogParser:
    """Test the CSVLogParser class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.parser = CSVLogParser()

    def test_can_parse_csv(self):
        """Test that CSV lines are recognized"""
        csv_line = '2023-10-15T14:30:45Z,warning,High CPU usage,monitoring,95.5'
        assert self.parser.can_parse(csv_line) is True

    def test_can_parse_non_csv(self):
        """Test that non-CSV lines are not recognized"""
        non_csv_cases = [
            'Not CSV',
            '<34>Oct 15 14:30:45 server1 process: message',
            '{"timestamp": "2023-10-15T14:30:45Z", "message": "test"}',
        ]

        for line in non_csv_cases:
            assert self.parser.can_parse(line) is False

    def test_parse_csv_header(self):
        """Test that header row is handled correctly"""
        header_line = 'timestamp,level,message,source,cpu_percent'

        # First call should set headers and return None
        result = self.parser.parse(header_line)
        assert result is None
        assert self.parser.headers == ['timestamp', 'level', 'message', 'source', 'cpu_percent']

    def test_parse_csv_data(self):
        """Test parsing CSV data row"""
        # First set up headers
        self.parser.parse('timestamp,level,message,source,cpu_percent')

        # Then parse data row
        data_line = '2023-10-15T14:30:45Z,warning,High CPU usage,monitoring,95.5'
        entry = self.parser.parse(data_line)

        assert entry is not None
        assert entry.level == 'warning'
        assert entry.message == 'High CPU usage'
        assert entry.source == 'monitoring'
        assert entry.metadata == {'cpu_percent': '95.5'}

    def test_parse_csv_without_headers(self):
        """Test parsing CSV without explicit headers"""
        # Parse data row first (this should fail)
        data_line = '2023-10-15T14:30:45Z,warning,High CPU usage'
        entry = self.parser.parse(data_line)

        # Should return None because we don't have headers yet
        assert entry is None


class TestDetectorParser:
    """Test the main DetectorParser class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.parser = DetectorParser()

    @patch('parser.Elasticsearch')
    def test_initialization(self, mock_es):
        """Test DetectorParser initialization"""
        parser = DetectorParser('localhost', 9200)

        assert len(parser.parsers) == 3
        assert isinstance(parser.parsers[0], JSONLogParser)
        assert isinstance(parser.parsers[1], SyslogParser)
        assert isinstance(parser.parsers[2], CSVLogParser)

    @patch('parser.Elasticsearch')
    def test_parse_log_line_json(self, mock_es):
        """Test parsing JSON log lines"""
        json_line = '{"timestamp": "2023-10-15T14:30:45Z", "level": "error", "message": "Test error"}'
        entry = self.parser.parse_log_line(json_line)

        assert entry is not None
        assert entry.level == 'error'
        assert entry.message == 'Test error'

    @patch('parser.Elasticsearch')
    def test_parse_log_line_syslog(self, mock_es):
        """Test parsing syslog lines"""
        syslog_line = '<34>Oct 15 14:30:45 server1 sshd[12345]: Failed password'
        entry = self.parser.parse_log_line(syslog_line)

        assert entry is not None
        assert entry.level == 'warning'
        assert entry.message == 'Failed password'

    @patch('parser.Elasticsearch')
    def test_parse_log_line_csv(self, mock_es):
        """Test parsing CSV lines"""
        # First set up CSV headers
        self.parser.parsers[2].parse('timestamp,level,message,source')
        csv_line = '2023-10-15T14:30:45Z,info,Test message,test-source'
        entry = self.parser.parse_log_line(csv_line)

        assert entry is not None
        assert entry.level == 'info'
        assert entry.message == 'Test message'

    @patch('parser.Elasticsearch')
    def test_parse_log_line_unparseable(self, mock_es):
        """Test that unparseable lines return None"""
        unparseable_line = 'This line cannot be parsed by any parser'
        entry = self.parser.parse_log_line(unparseable_line)

        assert entry is None

    @patch('parser.Elasticsearch')
    def test_send_to_elasticsearch_success(self, mock_es):
        """Test successful sending to Elasticsearch"""
        mock_es_instance = Mock()
        mock_es.return_value = mock_es_instance
        mock_response = {'_id': 'test-id'}
        mock_es_instance.index.return_value = mock_response

        self.parser = DetectorParser()
        entry = LogEntry(
            timestamp=datetime.now(),
            level='info',
            message='Test message',
            source='test',
            metadata={},
            raw_log='test log'
        )

        result = self.parser.send_to_elasticsearch(entry)

        assert result is True
        mock_es_instance.index.assert_called_once()

    @patch('parser.Elasticsearch')
    def test_send_to_elasticsearch_failure(self, mock_es):
        """Test failure when sending to Elasticsearch"""
        mock_es_instance = Mock()
        mock_es.return_value = mock_es_instance
        mock_es_instance.index.side_effect = Exception("Connection error")

        self.parser = DetectorParser()
        entry = LogEntry(
            timestamp=datetime.now(),
            level='info',
            message='Test message',
            source='test',
            metadata={},
            raw_log='test log'
        )

        result = self.parser.send_to_elasticsearch(entry)

        assert result is False

    @patch('parser.Elasticsearch')
    @patch('builtins.open', new_callable=Mock)
    def test_process_log_file_success(self, mock_file, mock_es):
        """Test successful log file processing"""
        mock_es_instance = Mock()
        mock_es.return_value = mock_es_instance
        mock_response = {'_id': 'test-id'}
        mock_es_instance.index.return_value = mock_response

        # Mock file reading
        mock_file_instance = Mock()
        mock_file_instance.__enter__.return_value = mock_file_instance
        mock_file_instance.__iter__.return_value = [
            '{"level": "info", "message": "Test message 1"}\n',
            '<34>Oct 15 14:30:45 server1 process: Test message 2\n',
            'invalid line\n',
        ]
        mock_file.return_value = mock_file_instance

        self.parser = DetectorParser()
        processed = self.parser.process_log_file('/path/to/logfile.log')

        assert processed == 2  # Two valid lines processed

    @patch('parser.Elasticsearch')
    def test_process_log_file_not_found(self, mock_es):
        """Test handling of missing log file"""
        self.parser = DetectorParser()

        with patch('builtins.open', side_effect=FileNotFoundError()):
            processed = self.parser.process_log_file('/nonexistent/file.log')

        assert processed == 0

    @patch('parser.Elasticsearch')
    def test_process_log_stream(self, mock_es):
        """Test processing log lines from a stream"""
        mock_es_instance = Mock()
        mock_es.return_value = mock_es_instance
        mock_response = {'_id': 'test-id'}
        mock_es_instance.index.return_value = mock_response

        self.parser = DetectorParser()
        log_lines = [
            '{"level": "info", "message": "Test message 1"}',
            '<34>Oct 15 14:30:45 server1 process: Test message 2',
            'invalid line',
        ]

        processed = self.parser.process_log_stream(log_lines)

        assert processed == 2  # Two valid lines processed


# Integration tests
class TestParserIntegration:
    """Integration tests for the complete parser system"""

    @patch('parser.Elasticsearch')
    def test_multiple_log_formats_in_stream(self, mock_es):
        """Test processing a stream with multiple log formats"""
        mock_es_instance = Mock()
        mock_es.return_value = mock_es_instance
        mock_response = {'_id': 'test-id'}
        mock_es_instance.index.return_value = mock_response

        parser = DetectorParser()

        # Set up CSV parser with headers first
        parser.parsers[2].parse('timestamp,level,message,source')

        log_lines = [
            '{"timestamp": "2023-10-15T14:30:45Z", "level": "error", "message": "JSON error"}',
            '<34>Oct 15 14:31:45 server1 sshd[12345]: Failed login attempt',
            '2023-10-15T14:32:45Z,warning,High memory usage,monitoring',
        ]

        processed = parser.process_log_stream(log_lines)

        # All three lines should be parsed successfully
        assert processed == 3

        # Verify that Elasticsearch was called 3 times
        assert mock_es_instance.index.call_count == 3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
