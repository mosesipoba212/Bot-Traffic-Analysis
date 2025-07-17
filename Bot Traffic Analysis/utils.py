"""
Utility functions for log analysis and bot detection.
"""

import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs
import pandas as pd


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single log line in Combined Log Format.
    
    Args:
        line: Raw log line string
        
    Returns:
        Dictionary with parsed fields or None if parsing fails
    """
    # Combined Log Format regex pattern
    log_pattern = re.compile(
        r'(?P<ip>\S+) '                     # IP address
        r'(?P<ident>\S+) '                  # Identity
        r'(?P<user>\S+) '                   # User
        r'\[(?P<timestamp>[^\]]+)\] '       # Timestamp
        r'"(?P<request>[^"]*)" '            # Request
        r'(?P<status>\d+) '                 # Status code
        r'(?P<size>\S+) '                   # Response size
        r'"(?P<referrer>[^"]*)" '           # Referrer
        r'"(?P<user_agent>[^"]*)"'          # User agent
    )
    
    match = log_pattern.match(line.strip())
    if not match:
        return None
    
    try:
        data = match.groupdict()
        
        # Parse timestamp
        timestamp_str = data['timestamp']
        timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        
        # Parse request
        request_parts = data['request'].split(' ')
        method = request_parts[0] if len(request_parts) > 0 else ''
        path = request_parts[1] if len(request_parts) > 1 else ''
        protocol = request_parts[2] if len(request_parts) > 2 else ''
        
        # Parse size
        size = int(data['size']) if data['size'].isdigit() else 0
        
        return {
            'ip': data['ip'],
            'timestamp': timestamp,
            'method': method,
            'path': path,
            'protocol': protocol,
            'status': int(data['status']),
            'size': size,
            'referrer': data['referrer'] if data['referrer'] != '-' else None,
            'user_agent': data['user_agent'] if data['user_agent'] != '-' else None
        }
    except Exception as e:
        print(f"Error parsing log line: {e}")
        return None


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private/internal.
    
    Args:
        ip: IP address string
        
    Returns:
        True if IP is private, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def extract_file_extension(path: str) -> str:
    """
    Extract file extension from URL path.
    
    Args:
        path: URL path
        
    Returns:
        File extension or empty string
    """
    parsed = urlparse(path)
    path_parts = parsed.path.split('.')
    return f".{path_parts[-1].lower()}" if len(path_parts) > 1 else ""


def calculate_request_rate(requests: List[datetime], window_minutes: int = 5) -> float:
    """
    Calculate request rate per minute for a list of timestamps.
    
    Args:
        requests: List of datetime objects
        window_minutes: Time window in minutes
        
    Returns:
        Requests per minute
    """
    if not requests:
        return 0.0
    
    requests_sorted = sorted(requests)
    end_time = requests_sorted[-1]
    start_time = end_time - timedelta(minutes=window_minutes)
    
    # Count requests in the time window
    recent_requests = [r for r in requests_sorted if r >= start_time]
    
    return len(recent_requests) / window_minutes


def detect_burst_pattern(requests: List[datetime], burst_threshold: int = 50) -> bool:
    """
    Detect if there's a burst pattern in requests (many requests in short time).
    
    Args:
        requests: List of datetime objects
        burst_threshold: Number of requests to consider a burst
        
    Returns:
        True if burst pattern detected
    """
    if len(requests) < burst_threshold:
        return False
    
    requests_sorted = sorted(requests)
    
    # Check for burst in any 30-second window
    for i in range(len(requests_sorted) - burst_threshold + 1):
        window_start = requests_sorted[i]
        window_end = requests_sorted[i + burst_threshold - 1]
        
        if (window_end - window_start).total_seconds() <= 30:
            return True
    
    return False


def is_suspicious_user_agent(user_agent: str, suspicious_patterns: List[str]) -> bool:
    """
    Check if user agent string contains suspicious patterns.
    
    Args:
        user_agent: User agent string
        suspicious_patterns: List of patterns to check
        
    Returns:
        True if suspicious patterns found
    """
    if not user_agent:
        return True  # Empty user agent is suspicious
    
    user_agent_lower = user_agent.lower()
    return any(pattern in user_agent_lower for pattern in suspicious_patterns)


def is_suspicious_path(path: str, suspicious_paths: List[str]) -> bool:
    """
    Check if request path is suspicious.
    
    Args:
        path: Request path
        suspicious_paths: List of suspicious path patterns
        
    Returns:
        True if path is suspicious
    """
    if not path:
        return False
    
    path_lower = path.lower()
    return any(pattern in path_lower for pattern in suspicious_paths)


def calculate_bot_score(ip_data: Dict[str, Any], config: Dict[str, Any]) -> float:
    """
    Calculate a bot confidence score for an IP address.
    
    Args:
        ip_data: Dictionary containing IP analysis data
        config: Configuration dictionary
        
    Returns:
        Bot confidence score between 0.0 and 1.0
    """
    score = 0.0
    
    # Request rate factor (0.3 weight)
    rate = ip_data.get('request_rate', 0)
    rate_threshold = config.get('RATE_LIMIT_THRESHOLD', 10)
    if rate > rate_threshold:
        score += 0.3
    elif rate > rate_threshold * 0.5:
        score += 0.15
    
    # User agent factor (0.2 weight)
    if ip_data.get('suspicious_user_agent', False):
        score += 0.2
    
    # Request pattern factor (0.2 weight)
    if ip_data.get('burst_pattern', False):
        score += 0.2
    
    # Path suspiciousness factor (0.1 weight)
    if ip_data.get('suspicious_paths_ratio', 0) > 0.5:
        score += 0.1
    elif ip_data.get('suspicious_paths_ratio', 0) > 0.2:
        score += 0.05
    
    # Status code factor (0.1 weight)
    if ip_data.get('error_rate', 0) > 0.3:
        score += 0.1
    elif ip_data.get('error_rate', 0) > 0.1:
        score += 0.05
    
    # Diversity factor (0.1 weight) - bots often hit many different paths
    unique_paths = ip_data.get('unique_paths', 0)
    if unique_paths > 20:  # Adjusted for sample data
        score += 0.1
    elif unique_paths > 10:
        score += 0.05
    
    return min(score, 1.0)


def format_bytes(bytes_value: int) -> str:
    """
    Format bytes into human-readable format.
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.2 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def get_time_distribution(timestamps: List[datetime]) -> Dict[str, int]:
    """
    Get distribution of requests across hours of the day.
    
    Args:
        timestamps: List of datetime objects
        
    Returns:
        Dictionary with hour -> count mapping
    """
    distribution = {}
    for ts in timestamps:
        hour = ts.hour
        distribution[hour] = distribution.get(hour, 0) + 1
    return distribution


def detect_scraping_pattern(paths: List[str]) -> bool:
    """
    Detect if request paths indicate scraping behavior.
    
    Args:
        paths: List of request paths
        
    Returns:
        True if scraping pattern detected
    """
    if len(paths) < 10:
        return False
    
    # Check for sequential patterns
    sequential_count = 0
    for i in range(len(paths) - 1):
        if paths[i] and paths[i + 1]:
            # Simple check for sequential IDs or pages
            if re.search(r'/(\d+)', paths[i]) and re.search(r'/(\d+)', paths[i + 1]):
                sequential_count += 1
    
    return sequential_count > len(paths) * 0.3  # 30% of requests are sequential
