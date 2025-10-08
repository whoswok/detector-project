class WindowsEventLogParser(LogParser):
    """Parser for Windows Event Log format"""

    # Windows Event Log pattern
    WINDOWS_PATTERN = re.compile(
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),\s*(\w+),\s*(\w+),\s*([^,]+),\s*([^,]+),\s*([^,]*),\s*(.+)?',
        re.IGNORECASE
    )

    SEVERITY_MAP = {
        '1': 'critical',
        '2': 'error',
        '3': 'warning',
        '4': 'info',
        '5': 'verbose'
    }

    def can_parse(self, log_line: str) -> bool:
        stripped = log_line.strip()
        # Look for Windows Event Log timestamp format
        return (',' in stripped and
                len(stripped.split(',')) >= 5 and
                re.match(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', stripped.split(',')[0]))

    def parse(self, log_line: str) -> Optional[LogEntry]:
        match = self.WINDOWS_PATTERN.match(log_line.strip())
        if not match:
            return None

        timestamp_str, severity_num, source, event_id, user, computer, message = match.groups()

        try:
            # Parse Windows timestamp format: 2023-10-15 14:30:45
            dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            # Assume current year if needed
            now = datetime.now()
            if dt.year == 1900:  # Sometimes Windows logs use this
                dt = dt.replace(year=now.year)
        except ValueError:
            dt = None

        level = self.SEVERITY_MAP.get(severity_num, 'info')
        source_clean = source.strip()
        message_clean = message.strip() if message else ''

        metadata = {
            'event_id': event_id.strip(),
            'user': user.strip(),
            'computer': computer.strip(),
            'windows_severity': severity_num
        }

        return LogEntry(
            timestamp=dt,
            level=level,
            message=message_clean,
            source=f"Windows-{source_clean}",
            metadata=metadata,
            raw_log=log_line.strip()
        )


class ApacheLogParser(LogParser):
    """Parser for Apache HTTP Server access logs"""

    # Common Apache log format (CLF)
    APACHE_CLF_PATTERN = re.compile(
        r'(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)?',
        re.IGNORECASE
    )

    # Extended Apache log format
    APACHE_EXTENDED_PATTERN = re.compile(
        r'(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)\s+"([^"]+)"\s+"([^"]+)"',
        re.IGNORECASE
    )

    def can_parse(self, log_line: str) -> bool:
        stripped = log_line.strip()
        # Apache logs typically start with IP address and have bracketed timestamps
        return (re.match(r'\d+\.\d+\.\d+\.\d+', stripped) and
                '[' in stripped and ']' in stripped)

    def parse(self, log_line: str) -> Optional[LogEntry]:
        # Try extended format first
        match = self.APACHE_EXTENDED_PATTERN.match(log_line.strip())
        if match:
            ip, identity, userid, timestamp_str, request, status, size, referer, user_agent = match.groups()
        else:
            # Try common format
            match = self.APACHE_CLF_PATTERN.match(log_line.strip())
            if match:
                ip, identity, userid, timestamp_str, request, status, size = match.groups()
                referer, user_agent = '-', '-'
            else:
                return None

        try:
            # Parse Apache timestamp: [15/Oct/2023:14:30:45 +0000]
            timestamp_str = timestamp_str.replace('[', '').replace(']', '')
            dt = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            dt = None

        # Extract HTTP method and path from request
        request_parts = request.split()
        method = request_parts[0] if request_parts else 'UNKNOWN'
        url = request_parts[1] if len(request_parts) > 1 else ''

        level = 'info'
        if status.startswith('4'):
            level = 'warning'
        elif status.startswith('5'):
            level = 'error'

        metadata = {
            'client_ip': ip,
            'identity': identity,
            'userid': userid,
            'http_method': method,
            'url': url,
            'http_status': status,
            'response_size': size,
            'referer': referer,
            'user_agent': user_agent
        }

        return LogEntry(
            timestamp=dt,
            level=level,
            message=f"HTTP {method} {url} - {status}",
            source=f"Apache-{ip}",
            metadata=metadata,
            raw_log=log_line.strip()
        )


class NginxLogParser(LogParser):
    """Parser for Nginx access logs"""

    # Nginx log format (similar to Apache but with different fields)
    NGINX_PATTERN = re.compile(
        r'(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)\s+"([^"]+)"\s+"([^"]+)"\s+"([^"]+)"',
        re.IGNORECASE
    )

    def can_parse(self, log_line: str) -> bool:
        stripped = log_line.strip()
        # Nginx logs have similar format to Apache but often include request time
        return (re.match(r'\d+\.\d+\.\d+\.\d+', stripped) and
                '[' in stripped and ']' in stripped and
                'nginx' in stripped.lower())

    def parse(self, log_line: str) -> Optional[LogEntry]:
        match = self.NGINX_PATTERN.match(log_line.strip())
        if not match:
            return None

        ip, dash1, userid, timestamp_str, request, status, size, referer, user_agent, request_time = match.groups()

        try:
            # Parse Nginx timestamp (similar to Apache)
            timestamp_str = timestamp_str.replace('[', '').replace(']', '')
            dt = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            dt = None

        request_parts = request.split()
        method = request_parts[0] if request_parts else 'UNKNOWN'
        url = request_parts[1] if len(request_parts) > 1 else ''

        level = 'info'
        if status.startswith('4'):
            level = 'warning'
        elif status.startswith('5'):
            level = 'error'

        metadata = {
            'client_ip': ip,
            'userid': userid,
            'http_method': method,
            'url': url,
            'http_status': status,
            'response_size': size,
            'referer': referer,
            'user_agent': user_agent,
            'request_time': request_time
        }

        return LogEntry(
            timestamp=dt,
            level=level,
            message=f"Nginx {method} {url} - {status} ({request_time}s)",
            source=f"Nginx-{ip}",
            metadata=metadata,
            raw_log=log_line.strip()
        )


class FirewallLogParser(LogParser):
    """Parser for firewall logs (iptables, ufw, etc.)"""

    # iptables pattern
    IPTABLES_PATTERN = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+kernel:\s+\[.*\]\s+(\w+):\s+IN=(\S+)\s+OUT=(\S+)\s+.*SRC=(\S+)\s+DST=(\S+)\s+.*PROTO=(\S+)',
        re.IGNORECASE
    )

    def can_parse(self, log_line: str) -> bool:
        stripped = log_line.strip()
        # Firewall logs typically contain IN=, OUT=, SRC=, DST=, PROTO=
        return ('IN=' in stripped and 'OUT=' in stripped and
                'SRC=' in stripped and 'DST=' in stripped and 'PROTO=' in stripped)

    def parse(self, log_line: str) -> Optional[LogEntry]:
        match = self.IPTABLES_PATTERN.match(log_line.strip())
        if not match:
            return None

        timestamp_str, hostname, action, interface_in, interface_out, src_ip, dst_ip, protocol = match.groups()

        try:
            # Parse syslog timestamp format
            dt = datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
            now = datetime.now()
            timestamp = dt.replace(year=now.year)
        except ValueError:
            timestamp = None

        level = 'info'
        if action.upper() in ['DROP', 'REJECT', 'DENY']:
            level = 'warning'
        elif action.upper() in ['BLOCK']:
            level = 'error'

        metadata = {
            'hostname': hostname,
            'action': action,
            'interface_in': interface_in,
            'interface_out': interface_out,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'protocol': protocol
        }

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=f"Firewall {action}: {src_ip} -> {dst_ip} ({protocol})",
            source=f"Firewall-{hostname}",
            metadata=metadata,
            raw_log=log_line.strip()
        )
