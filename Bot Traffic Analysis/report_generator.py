"""
Report generation and visualization functions.
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import Counter
import os

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    print("Warning: matplotlib/seaborn not available. Visualizations will be disabled.")

from utils import format_bytes


class ReportGenerator:
    """
    Generates comprehensive reports and visualizations for bot analysis.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize report generator.
        
        Args:
            output_dir: Directory to save reports and visualizations
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_summary_report(self, 
                              bot_analyses: Dict[str, Any], 
                              recommendations: List[Dict[str, Any]],
                              coordinated_attacks: List[Dict[str, Any]],
                              total_requests: int,
                              analysis_period: str) -> Dict[str, Any]:
        """
        Generate a comprehensive summary report.
        
        Args:
            bot_analyses: Dictionary of bot analysis results
            recommendations: List of recommendations
            coordinated_attacks: List of detected attacks
            total_requests: Total number of requests analyzed
            analysis_period: Time period of analysis
            
        Returns:
            Dictionary containing the full report
        """
        # Calculate statistics
        total_ips = len(bot_analyses)
        bot_ips = sum(1 for analysis in bot_analyses.values() if analysis.get('bot_score', 0) > 0.5)
        high_risk_ips = sum(1 for analysis in bot_analyses.values() if analysis.get('bot_score', 0) > 0.8)
        
        # Bot type distribution
        bot_types = Counter()
        detector = None  # Import BotDetector when needed
        
        for analysis in bot_analyses.values():
            if analysis.get('bot_score', 0) > 0.5:
                if detector is None:
                    from bot_detector import BotDetector
                    detector = BotDetector()
                bot_type = detector.classify_bot_type(analysis)
                bot_types[bot_type] += 1
        
        # Top suspicious IPs
        top_suspicious = []
        for ip, analysis in sorted(bot_analyses.items(), 
                                 key=lambda x: x[1].get('bot_score', 0), 
                                 reverse=True)[:20]:
            if analysis.get('bot_score', 0) > 0.3:
                if detector is None:
                    from bot_detector import BotDetector
                    detector = BotDetector()
                top_suspicious.append({
                    'ip': ip,
                    'bot_score': round(analysis.get('bot_score', 0), 3),
                    'total_requests': analysis.get('total_requests', 0),
                    'request_rate': round(analysis.get('request_rate', 0), 2),
                    'most_common_ua': analysis.get('most_common_ua', 'Unknown'),
                    'classification': detector.classify_bot_type(analysis)
                })
        
        # Request volume analysis
        total_bot_requests = sum(
            analysis.get('total_requests', 0) 
            for analysis in bot_analyses.values() 
            if analysis.get('bot_score', 0) > 0.5
        )
        
        report = {
            'report_generated': datetime.now().isoformat(),
            'analysis_period': analysis_period,
            'summary': {
                'total_requests': total_requests,
                'total_unique_ips': total_ips,
                'bot_ips_detected': bot_ips,
                'high_risk_ips': high_risk_ips,
                'bot_traffic_percentage': round((total_bot_requests / total_requests) * 100, 2) if total_requests > 0 else 0,
                'coordinated_attacks': len(coordinated_attacks)
            },
            'bot_classification': dict(bot_types),
            'top_suspicious_ips': top_suspicious,
            'coordinated_attacks': coordinated_attacks,
            'recommendations': recommendations,
            'cost_analysis': self._calculate_cost_analysis(recommendations),
            'implementation_priority': self._prioritize_implementations(recommendations)
        }
        
        return report
    
    def _calculate_cost_analysis(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate cost analysis for recommendations.
        
        Args:
            recommendations: List of recommendations
            
        Returns:
            Cost analysis dictionary
        """
        free_solutions = []
        low_cost_solutions = []
        
        for rec in recommendations:
            if 'free' in rec['cost'].lower():
                free_solutions.append(rec['solution'])
            else:
                low_cost_solutions.append(rec['solution'])
        
        return {
            'free_solutions': free_solutions,
            'low_cost_solutions': low_cost_solutions,
            'total_free_solutions': len(free_solutions),
            'estimated_monthly_cost': 0 if not low_cost_solutions else 'Contact providers for pricing'
        }
    
    def _prioritize_implementations(self, recommendations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize implementations based on impact and cost.
        
        Args:
            recommendations: List of recommendations
            
        Returns:
            Prioritized implementation list
        """
        prioritized = []
        
        # Immediate actions (free, high impact)
        immediate = [r for r in recommendations if r['priority'] == 'high' and 'free' in r['cost'].lower()]
        
        # Short-term actions (low cost, medium-high impact)
        short_term = [r for r in recommendations if r['priority'] in ['high', 'medium'] and 'free' not in r['cost'].lower()]
        
        # Long-term actions (low priority or complex implementation)
        long_term = [r for r in recommendations if r['priority'] == 'low']
        
        if immediate:
            prioritized.append({
                'timeframe': 'immediate',
                'actions': immediate,
                'description': 'Implement these free solutions immediately'
            })
        
        if short_term:
            prioritized.append({
                'timeframe': 'short_term',
                'actions': short_term,
                'description': 'Implement within 1-2 weeks'
            })
        
        if long_term:
            prioritized.append({
                'timeframe': 'long_term',
                'actions': long_term,
                'description': 'Consider for future implementation'
            })
        
        return prioritized
    
    def save_json_report(self, report: Dict[str, Any], filename: str = "bot_analysis_report.json") -> str:
        """
        Save report as JSON file.
        
        Args:
            report: Report dictionary
            filename: Output filename
            
        Returns:
            Path to saved file
        """
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filepath
    
    def generate_text_report(self, report: Dict[str, Any]) -> str:
        """
        Generate a human-readable text report.
        
        Args:
            report: Report dictionary
            
        Returns:
            Text report string
        """
        text = []
        text.append("=" * 60)
        text.append("WEB SERVER LOG ANALYSIS - BOT DETECTION REPORT")
        text.append("=" * 60)
        text.append(f"Generated: {report['report_generated']}")
        text.append(f"Analysis Period: {report['analysis_period']}")
        text.append("")
        
        # Summary
        summary = report['summary']
        text.append("SUMMARY")
        text.append("-" * 20)
        text.append(f"Total Requests: {summary['total_requests']:,}")
        text.append(f"Unique IP Addresses: {summary['total_unique_ips']:,}")
        text.append(f"Bot IPs Detected: {summary['bot_ips_detected']:,}")
        text.append(f"High Risk IPs: {summary['high_risk_ips']:,}")
        text.append(f"Bot Traffic: {summary['bot_traffic_percentage']:.1f}%")
        text.append(f"Coordinated Attacks: {summary['coordinated_attacks']}")
        text.append("")
        
        # Bot Classification
        if report['bot_classification']:
            text.append("BOT CLASSIFICATION")
            text.append("-" * 20)
            for bot_type, count in report['bot_classification'].items():
                text.append(f"{bot_type.replace('_', ' ').title()}: {count}")
            text.append("")
        
        # Top Suspicious IPs
        if report['top_suspicious_ips']:
            text.append("TOP SUSPICIOUS IPs")
            text.append("-" * 20)
            for ip_info in report['top_suspicious_ips'][:10]:
                text.append(f"IP: {ip_info['ip']}")
                text.append(f"  Bot Score: {ip_info['bot_score']:.3f}")
                text.append(f"  Requests: {ip_info['total_requests']:,}")
                text.append(f"  Rate: {ip_info['request_rate']:.1f} req/min")
                text.append(f"  Classification: {ip_info['classification']}")
                text.append("")
        
        # Recommendations
        if report['recommendations']:
            text.append("RECOMMENDATIONS")
            text.append("-" * 20)
            for i, rec in enumerate(report['recommendations'], 1):
                text.append(f"{i}. {rec['solution'].replace('_', ' ').title()} ({rec['priority'].upper()} PRIORITY)")
                text.append(f"   {rec['description']}")
                text.append(f"   Cost: {rec['cost']}")
                text.append(f"   Implementation: {rec['implementation']}")
                text.append("")
        
        # Implementation Priority
        if report['implementation_priority']:
            text.append("IMPLEMENTATION ROADMAP")
            text.append("-" * 20)
            for phase in report['implementation_priority']:
                text.append(f"{phase['timeframe'].replace('_', ' ').upper()}: {phase['description']}")
                for action in phase['actions']:
                    text.append(f"  - {action['solution'].replace('_', ' ').title()}")
                text.append("")
        
        return "\n".join(text)
    
    def save_text_report(self, report: Dict[str, Any], filename: str = "bot_analysis_report.txt") -> str:
        """
        Save report as text file.
        
        Args:
            report: Report dictionary
            filename: Output filename
            
        Returns:
            Path to saved file
        """
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            f.write(self.generate_text_report(report))
        
        return filepath
    
    def create_visualizations(self, bot_analyses: Dict[str, Any], report: Dict[str, Any]) -> List[str]:
        """
        Create visualization charts for the analysis.
        
        Args:
            bot_analyses: Dictionary of bot analysis results
            report: Report dictionary
            
        Returns:
            List of paths to generated visualization files
        """
        if not VISUALIZATION_AVAILABLE:
            print("Visualizations skipped - matplotlib/seaborn not available")
            return []
        
        filepaths = []
        
        # Set style
        plt.style.use('seaborn-v0_8')
        
        # 1. Bot Score Distribution
        bot_scores = [analysis.get('bot_score', 0) for analysis in bot_analyses.values()]
        
        plt.figure(figsize=(10, 6))
        plt.hist(bot_scores, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
        plt.xlabel('Bot Confidence Score')
        plt.ylabel('Number of IP Addresses')
        plt.title('Distribution of Bot Confidence Scores')
        plt.axvline(x=0.5, color='red', linestyle='--', label='Bot Threshold (0.5)')
        plt.legend()
        
        filepath = os.path.join(self.output_dir, 'bot_score_distribution.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        filepaths.append(filepath)
        
        # 2. Request Rate Analysis
        request_rates = [analysis.get('request_rate', 0) for analysis in bot_analyses.values() if analysis.get('request_rate', 0) > 0]
        
        if request_rates:  # Only create chart if we have data
            plt.figure(figsize=(10, 6))
            plt.hist(request_rates, bins=30, alpha=0.7, color='lightcoral', edgecolor='black')
            plt.xlabel('Request Rate (requests/minute)')
            plt.ylabel('Number of IP Addresses')
            plt.title('Request Rate Distribution')
            plt.axvline(x=100, color='red', linestyle='--', label='Rate Limit Threshold')
            plt.legend()
            plt.xlim(0, min(max(request_rates), 500))  # Limit x-axis for better visibility
            
            filepath = os.path.join(self.output_dir, 'request_rate_distribution.png')
            plt.savefig(filepath, dpi=300, bbox_inches='tight')
            plt.close()
            filepaths.append(filepath)
        
        # 3. Bot Type Distribution
        if report['bot_classification']:
            bot_types = list(report['bot_classification'].keys())
            counts = list(report['bot_classification'].values())
            
            plt.figure(figsize=(10, 6))
            bars = plt.bar(bot_types, counts, color='lightgreen', edgecolor='black')
            plt.xlabel('Bot Type')
            plt.ylabel('Number of IPs')
            plt.title('Bot Type Classification')
            plt.xticks(rotation=45, ha='right')
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom')
            
            filepath = os.path.join(self.output_dir, 'bot_type_distribution.png')
            plt.savefig(filepath, dpi=300, bbox_inches='tight')
            plt.close()
            filepaths.append(filepath)
        
        # 4. Top Suspicious IPs
        if report['top_suspicious_ips']:
            top_10 = report['top_suspicious_ips'][:10]
            ips = [ip_info['ip'] for ip_info in top_10]
            scores = [ip_info['bot_score'] for ip_info in top_10]
            
            plt.figure(figsize=(12, 6))
            bars = plt.barh(range(len(ips)), scores, color='orange', edgecolor='black')
            plt.yticks(range(len(ips)), ips)
            plt.xlabel('Bot Confidence Score')
            plt.title('Top 10 Suspicious IP Addresses')
            plt.xlim(0, 1)
            
            # Add value labels
            for i, bar in enumerate(bars):
                width = bar.get_width()
                plt.text(width + 0.01, bar.get_y() + bar.get_height()/2,
                        f'{scores[i]:.3f}', ha='left', va='center')
            
            filepath = os.path.join(self.output_dir, 'top_suspicious_ips.png')
            plt.savefig(filepath, dpi=300, bbox_inches='tight')
            plt.close()
            filepaths.append(filepath)
        
        # 5. Time-based Analysis (if we have timestamp data)
        time_distributions = []
        for analysis in bot_analyses.values():
            if analysis.get('time_distribution'):
                time_distributions.append(analysis['time_distribution'])
        
        if time_distributions:
            # Aggregate hourly activity
            hourly_activity = {}
            for hour in range(24):
                hourly_activity[hour] = sum(dist.get(hour, 0) for dist in time_distributions)
            
            plt.figure(figsize=(12, 6))
            hours = list(hourly_activity.keys())
            activity = list(hourly_activity.values())
            
            plt.plot(hours, activity, marker='o', linewidth=2, markersize=6, color='purple')
            plt.xlabel('Hour of Day')
            plt.ylabel('Number of Requests')
            plt.title('Hourly Request Activity (All IPs)')
            plt.grid(True, alpha=0.3)
            plt.xticks(range(0, 24, 2))
            
            filepath = os.path.join(self.output_dir, 'hourly_activity.png')
            plt.savefig(filepath, dpi=300, bbox_inches='tight')
            plt.close()
            filepaths.append(filepath)
        
        return filepaths
