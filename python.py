import os
import re
from pathlib import Path

# Very common real locations (Linux/server focused - adapt for Windows)
COMMON_LOG_PATHS = [
    "/var/log",
    "/var/log/apache2",
    "/var/log/nginx",
    "/var/log/httpd",
    "/var/log/mysql",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/audit/audit.log",
]

# Very common filename patterns (regex)
LOG_FILENAME_PATTERNS = [
    r'.*\.log$',
    r'.*\.log\.\d+$',           # rotated logs
    r'.*\.log\.[0-9]{8}$',      # date rotated
    r'access\.log.*',
    r'error\.log.*',
    r'auth\.log.*',
    r'secure.*',
    r'syslog.*',
    r'messages.*',
    r'audit\.log.*',
    r'winlogbeat/.*',           # if using beats agents
]

def is_probable_log_file(path: str | Path) -> bool:
    path = Path(path)
    
    # 1. Is in known log directory?
    if any(str(path).startswith(p) for p in COMMON_LOG_PATHS):
        return True
    
    # 2. Filename pattern match?
    name = path.name.lower()
    if any(re.match(pattern, name) for pattern in LOG_FILENAME_PATTERNS):
        return True
    
    # 3. Bonus weak check: is text file + recent modification + decent size?
    try:
        if not path.is_file():
            return False
        stat = path.stat()
        if stat.st_size < 100:                    # too small
            return False
        if stat.st_mtime < (time.time() - 86400*30):  # older than ~1 month
            return False
        
        # Quick content sniff (first 4KB)
        with path.open('rb') as f:
            head = f.read(4096)
            try:
                head.decode('utf-8', errors='ignore')
                return b'\x00' not in head[:512]   # no null bytes → probably text
            except:
                return False
    except Exception:
        return False
    
    return False


# Example usage: find logs recursively
def find_logs(start_dir: str = "/var/log", max_depth=4):
    logs = []
    for root, dirs, files in os.walk(start_dir, followlinks=False):
        depth = root[len(start_dir):].count(os.sep)
        if depth > max_depth:
            continue
        for file in files:
            full = Path(root) / file
            if is_probable_log_file(full):
                logs.append(str(full))
    return logs
