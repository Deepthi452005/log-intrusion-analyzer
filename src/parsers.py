import re
from datetime import datetime
import pandas as pd
from pathlib import Path


APACHE_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) '          # IP address
    r'\S+ \S+ '              # ident, authuser (ignored)
    r'\[(?P<time>.+?)\] '    # [time]
    r'"(?P<method>\S+) '     # "METHOD
    r'(?P<url>\S+) '         # URL
    r'(?P<protocol>[^"]+)" ' # PROTOCOL"
    r'(?P<status>\d{3}) '    # status code
    r'(?P<size>\S+)'         # response size
)

# Typical Ubuntu auth.log failed password line:
# Jan 10 06:32:15 hostname sshd[12345]: Failed password for invalid user admin from 1.2.3.4 port 54321 ssh2
SSH_FAILED_PATTERN = re.compile(
    r'(?P<month>\w{3})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)


def parse_apache_log(file_path: str) -> pd.DataFrame:
    """
    Parse Apache access.log into a DataFrame.
    Columns: ip, time, method, url, protocol, status, size
    """
    file = Path(file_path)
    rows = []

    with file.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = APACHE_LOG_PATTERN.match(line)
            if not m:
                continue

            data = m.groupdict()

            # Parse timestamp: 10/Oct/2000:13:55:36 -0700
            raw_time = data['time']
            try:
                dt = datetime.strptime(raw_time.split()[0], "%d/%b/%Y:%H:%M:%S")
            except ValueError:
                dt = None

            rows.append({
                "source": "apache",
                "ip": data['ip'],
                "time": dt,
                "method": data['method'],
                "url": data['url'],
                "protocol": data['protocol'],
                "status": int(data['status']),
                "size": int(data['size']) if data['size'].isdigit() else 0
            })

    return pd.DataFrame(rows)


def parse_ssh_log(file_path: str, year: int = None) -> pd.DataFrame:
    """
    Parse SSH auth.log failed password entries into a DataFrame.
    Columns: ip, time, user
    """
    file = Path(file_path)
    rows = []

    if year is None:
        year = datetime.now().year

    with file.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = SSH_FAILED_PATTERN.search(line)
            if not m:
                continue

            data = m.groupdict()
            timestamp_str = f"{data['day']} {data['month']} {year} {data['time']}"
            try:
                dt = datetime.strptime(timestamp_str, "%d %b %Y %H:%M:%S")
            except ValueError:
                dt = None

            rows.append({
                "source": "ssh",
                "ip": data['ip'],
                "time": dt,
                "user": data['user'],
                "host": data['host'],
                "raw_line": line.strip()
            })

    return pd.DataFrame(rows)
