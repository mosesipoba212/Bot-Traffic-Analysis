"""
Bot detection algorithms and analysis functions.
"""

from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re

from utils import (
    calculate_request_rate, detect_burst_pattern, is_suspicious_user_agent,
    is_suspicious_path, calculate_bot_score, detect_scraping_pattern,
    get_time_distribution, is_private_ip
)
import config


class BotDetector:
    """
    Main bot detection class with various analysis methods.
    """
    
    def __init__(self, config_override: Optional[Dict[str, Any]] = None):
        """
        Initialize bot detector with configuration.
        
        Args:
            config_override: Optional configuration overrides
        """
        self.config = {
            'RATE_LIMIT_THRESHOLD': config.RATE_LIMIT_THRESHOLD,
            'TIME_WINDOW_MINUTES': config.TIME_WINDOW_MINUTES,
            'BURST_THRESHOLD': config.BURST_THRESHOLD,
            'SUSPICIOUS_USER_AGENTS': config.SUSPICIOUS_USER_AGENTS,
            'SUSPICIOUS_STATUS_CODES': config.SUSPICIOUS_STATUS_CODES,
            'SUSPICIOUS_PATHS': config.SUSPICIOUS_PATHS,
            'SUSPICIOUS_EXTENSIONS': config.SUSPICIOUS_EXTENSIONS,
            'MIN_REQUESTS_FOR_ANALYSIS': config.MIN_REQUESTS_FOR_ANALYSIS,
            'HUMAN_REQUEST_INTERVAL': config.HUMAN_REQUEST_INTERVAL
        }
        
        if config_override:
            self.config.update(config_override)
    
    def analyze_ip_behavior(self, ip_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze behavior patterns for a single IP address.
        
        Args:
            ip_requests: List of request dictionaries for an IP
            
        Returns:
            Dictionary containing analysis results
        """
        if len(ip_requests) < self.config['MIN_REQUESTS_FOR_ANALYSIS']:
            return {'insufficient_data': True}
        
        timestamps = [req['timestamp'] for req in ip_requests]
        paths = [req['path'] for req in ip_requests]
        user_agents = [req['user_agent'] for req in ip_requests if req['user_agent']]
        status_codes = [req['status'] for req in ip_requests]
        
        # Calculate request rate
        request_rate = calculate_request_rate(timestamps, self.config['TIME_WINDOW_MINUTES'])
        
        # Detect burst patterns
        burst_pattern = detect_burst_pattern(timestamps, self.config['BURST_THRESHOLD'])
        
        # Check user agent suspiciousness
        suspicious_ua = False
        if user_agents:
            most_common_ua = Counter(user_agents).most_common(1)[0][0]
            suspicious_ua = is_suspicious_user_agent(
                most_common_ua, self.config['SUSPICIOUS_USER_AGENTS']
            )
        else:
            suspicious_ua = True  # No user agent is suspicious
        
        # Check path suspiciousness
        suspicious_path_count = sum(
            1 for path in paths 
            if is_suspicious_path(path, self.config['SUSPICIOUS_PATHS'])
        )
        suspicious_paths_ratio = suspicious_path_count / len(paths)
        
        # Calculate error rate
        error_count = sum(
            1 for status in status_codes 
            if status in self.config['SUSPICIOUS_STATUS_CODES']
        )
        error_rate = error_count / len(status_codes)
        
        # Check for scraping patterns
        scraping_pattern = detect_scraping_pattern(paths)
        
        # Calculate request intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            intervals.append(interval)
        
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        min_interval = min(intervals) if intervals else 0
        
        # Time distribution analysis
        time_distribution = get_time_distribution(timestamps)
        
        # Calculate diversity metrics
        unique_paths = len(set(paths))
        unique_user_agents = len(set(user_agents)) if user_agents else 0
        
        analysis = {
            'total_requests': len(ip_requests),
            'request_rate': request_rate,
            'burst_pattern': burst_pattern,
            'suspicious_user_agent': suspicious_ua,
            'suspicious_paths_ratio': suspicious_paths_ratio,
            'error_rate': error_rate,
            'scraping_pattern': scraping_pattern,
            'avg_request_interval': avg_interval,
            'min_request_interval': min_interval,
            'unique_paths': unique_paths,
            'unique_user_agents': unique_user_agents,
            'time_distribution': time_distribution,
            'most_common_ua': Counter(user_agents).most_common(1)[0][0] if user_agents else None,
            'most_common_paths': Counter(paths).most_common(5),
            'status_code_distribution': Counter(status_codes)
        }
        
        # Calculate bot confidence score
        analysis['bot_score'] = calculate_bot_score(analysis, self.config)
        
        return analysis
    
    def detect_coordinated_attacks(self, ip_analyses: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect coordinated attacks from multiple IPs.
        
        Args:
            ip_analyses: Dictionary mapping IP -> analysis results
            
        Returns:
            List of detected attack patterns
        """
        attacks = []
        
        # Group IPs by user agent
        ua_groups = defaultdict(list)
        for ip, analysis in ip_analyses.items():
            ua = analysis.get('most_common_ua')
            if ua:
                ua_groups[ua].append(ip)
        
        # Look for suspicious user agents with multiple IPs
        for ua, ips in ua_groups.items():
            if len(ips) > 5 and is_suspicious_user_agent(ua, self.config['SUSPICIOUS_USER_AGENTS']):
                attacks.append({
                    'type': 'coordinated_bot_attack',
                    'pattern': f'Multiple IPs using suspicious user agent: {ua}',
                    'ips': ips,
                    'severity': 'high'
                })
        
        # Look for similar request patterns across IPs
        path_patterns = defaultdict(list)
        for ip, analysis in ip_analyses.items():
            paths = [path for path, count in analysis.get('most_common_paths', [])]
            if paths:
                pattern_key = tuple(sorted(paths))
                path_patterns[pattern_key].append(ip)
        
        for pattern, ips in path_patterns.items():
            if len(ips) > 3 and len(pattern) > 1:
                attacks.append({
                    'type': 'coordinated_scraping',
                    'pattern': f'Multiple IPs targeting same paths: {pattern[:3]}',
                    'ips': ips,
                    'severity': 'medium'
                })
        
        return attacks
    
    def classify_bot_type(self, analysis: Dict[str, Any]) -> str:
        """
        Classify the type of bot based on behavior patterns.
        
        Args:
            analysis: IP analysis results
            
        Returns:
            Bot type classification
        """
        if analysis.get('bot_score', 0) < 0.3:
            return 'human'
        
        ua = analysis.get('most_common_ua', '').lower()
        paths = [path for path, count in analysis.get('most_common_paths', [])]
        
        # Search engine bots
        if any(term in ua for term in ['googlebot', 'bingbot', 'yahoobot', 'duckduckbot']):
            return 'search_engine'
        
        # Social media bots
        if any(term in ua for term in ['facebookexternalhit', 'twitterbot', 'linkedinbot']):
            return 'social_media'
        
        # SEO/monitoring tools
        if any(term in ua for term in ['ahrefs', 'semrush', 'moz', 'pingdom', 'uptimerobot']):
            return 'seo_monitoring'
        
        # Content scrapers
        if analysis.get('scraping_pattern', False) or analysis.get('unique_paths', 0) > 50:
            return 'content_scraper'
        
        # Vulnerability scanners
        if any(path for path in paths if any(vuln in path.lower() for vuln in [
            'admin', 'wp-admin', 'phpmyadmin', '.env', 'backup', 'config'
        ])):
            return 'vulnerability_scanner'
        
        # High-frequency bots
        if analysis.get('request_rate', 0) > self.config['RATE_LIMIT_THRESHOLD']:
            return 'high_frequency_bot'
        
        return 'unknown_bot'
    
    def generate_recommendations(self, bot_analyses: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate cost-effective recommendations based on bot analysis.
        
        Args:
            bot_analyses: Dictionary of bot analysis results
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Count bot types and severity
        bot_types = Counter()
        high_risk_ips = []
        
        for ip, analysis in bot_analyses.items():
            if analysis.get('bot_score', 0) > 0.5:
                bot_type = self.classify_bot_type(analysis)
                bot_types[bot_type] += 1
                
                if analysis.get('bot_score', 0) > 0.7:
                    high_risk_ips.append(ip)
        
        # Rate limiting recommendation
        if bot_types['high_frequency_bot'] > 0 or any(
            analysis.get('request_rate', 0) > self.config['RATE_LIMIT_THRESHOLD'] 
            for analysis in bot_analyses.values()
        ):
            recommendations.append({
                'priority': 'high',
                'solution': 'rate_limiting',
                'description': config.SOLUTIONS['rate_limiting']['description'],
                'cost': config.SOLUTIONS['rate_limiting']['cost'],
                'implementation': config.SOLUTIONS['rate_limiting']['implementation'],
                'affected_ips': len(high_risk_ips)
            })
        
        # CAPTCHA recommendation
        if bot_types['vulnerability_scanner'] > 0 or bot_types['content_scraper'] > 0:
            recommendations.append({
                'priority': 'medium',
                'solution': 'captcha',
                'description': config.SOLUTIONS['captcha']['description'],
                'cost': config.SOLUTIONS['captcha']['cost'],
                'implementation': config.SOLUTIONS['captcha']['implementation'],
                'affected_ips': bot_types['vulnerability_scanner'] + bot_types['content_scraper']
            })
        
        # Cloudflare recommendation
        if len(high_risk_ips) > 10:
            recommendations.append({
                'priority': 'high',
                'solution': 'cloudflare',
                'description': config.SOLUTIONS['cloudflare']['description'],
                'cost': config.SOLUTIONS['cloudflare']['cost'],
                'implementation': config.SOLUTIONS['cloudflare']['implementation'],
                'affected_ips': len(high_risk_ips)
            })
        
        # User agent filtering
        if any(analysis.get('suspicious_user_agent', False) for analysis in bot_analyses.values()):
            recommendations.append({
                'priority': 'low',
                'solution': 'user_agent_filtering',
                'description': config.SOLUTIONS['user_agent_filtering']['description'],
                'cost': config.SOLUTIONS['user_agent_filtering']['cost'],
                'implementation': config.SOLUTIONS['user_agent_filtering']['implementation'],
                'affected_ips': sum(1 for a in bot_analyses.values() if a.get('suspicious_user_agent', False))
            })
        
        # Fail2ban recommendation
        if bot_types['vulnerability_scanner'] > 0:
            recommendations.append({
                'priority': 'medium',
                'solution': 'fail2ban',
                'description': config.SOLUTIONS['fail2ban']['description'],
                'cost': config.SOLUTIONS['fail2ban']['cost'],
                'implementation': config.SOLUTIONS['fail2ban']['implementation'],
                'affected_ips': bot_types['vulnerability_scanner']
            })
        
        return sorted(recommendations, key=lambda x: {'high': 3, 'medium': 2, 'low': 1}[x['priority']], reverse=True)
