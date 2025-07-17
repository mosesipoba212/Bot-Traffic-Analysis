"""
Main web server log analyzer for bot detection.
"""

import argparse
import sys
from typing import Dict, List, Any, Optional
from collections import defaultdict
from datetime import datetime
import os

from utils import parse_log_line, is_private_ip
from bot_detector import BotDetector
from report_generator import ReportGenerator
import config


class LogAnalyzer:
    """
    Main log analyzer class that orchestrates the bot detection process.
    """
    
    def __init__(self, config_override: Optional[Dict[str, Any]] = None):
        """
        Initialize the log analyzer.
        
        Args:
            config_override: Optional configuration overrides
        """
        self.detector = BotDetector(config_override)
        self.reporter = ReportGenerator()
        self.config = config_override or {}
    
    def parse_log_file(self, log_file: str) -> List[Dict[str, Any]]:
        """
        Parse a log file and return structured data.
        
        Args:
            log_file: Path to the log file
            
        Returns:
            List of parsed log entries
        """
        entries = []
        failed_lines = 0
        
        print(f"Parsing log file: {log_file}")
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip():
                        parsed = parse_log_line(line)
                        if parsed:
                            entries.append(parsed)
                        else:
                            failed_lines += 1
                            if failed_lines <= 5:  # Show first 5 failed lines
                                print(f"Warning: Failed to parse line {line_num}: {line.strip()[:100]}...")
        
        except FileNotFoundError:
            print(f"Error: Log file '{log_file}' not found.")
            return []
        except Exception as e:
            print(f"Error reading log file: {e}")
            return []
        
        print(f"Successfully parsed {len(entries)} entries")
        if failed_lines > 0:
            print(f"Warning: {failed_lines} lines failed to parse")
        
        return entries
    
    def group_by_ip(self, entries: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group log entries by IP address.
        
        Args:
            entries: List of parsed log entries
            
        Returns:
            Dictionary mapping IP addresses to their requests
        """
        ip_groups = defaultdict(list)
        
        for entry in entries:
            ip = entry.get('ip')
            if ip:  # Include all IPs for analysis (including private ones for testing)
                ip_groups[ip].append(entry)
        
        return dict(ip_groups)
    
    def analyze_logs(self, log_file: str) -> Dict[str, Any]:
        """
        Perform complete log analysis.
        
        Args:
            log_file: Path to the log file
            
        Returns:
            Complete analysis results
        """
        print("Starting log analysis...")
        
        # Parse log file
        entries = self.parse_log_file(log_file)
        if not entries:
            return {'error': 'No entries found or failed to parse log file'}
        
        # Group by IP
        ip_groups = self.group_by_ip(entries)
        print(f"Found {len(ip_groups)} unique IP addresses")
        
        # Analyze each IP
        print("Analyzing IP behavior patterns...")
        bot_analyses = {}
        for ip, requests in ip_groups.items():
            analysis = self.detector.analyze_ip_behavior(requests)
            if not analysis.get('insufficient_data', False):
                bot_analyses[ip] = analysis
        
        print(f"Analyzed {len(bot_analyses)} IP addresses")
        
        # Detect coordinated attacks
        coordinated_attacks = self.detector.detect_coordinated_attacks(bot_analyses)
        
        # Generate recommendations
        recommendations = self.detector.generate_recommendations(bot_analyses)
        
        # Calculate analysis period
        timestamps = [entry['timestamp'] for entry in entries]
        analysis_period = f"{min(timestamps).strftime('%Y-%m-%d %H:%M')} to {max(timestamps).strftime('%Y-%m-%d %H:%M')}"
        
        # Generate summary report
        report = self.reporter.generate_summary_report(
            bot_analyses, 
            recommendations, 
            coordinated_attacks, 
            len(entries), 
            analysis_period
        )
        
        return {
            'report': report,
            'bot_analyses': bot_analyses,
            'entries': entries
        }
    
    def save_reports(self, analysis_results: Dict[str, Any], output_format: str = 'json', visualize: bool = False) -> List[str]:
        """
        Save analysis reports to files.
        
        Args:
            analysis_results: Results from analyze_logs
            output_format: Output format ('json', 'text', or 'both')
            visualize: Whether to create visualizations
            
        Returns:
            List of paths to generated files
        """
        if 'report' not in analysis_results:
            return []
        
        generated_files = []
        report = analysis_results['report']
        
        # Save JSON report
        if output_format in ['json', 'both']:
            json_path = self.reporter.save_json_report(report)
            generated_files.append(json_path)
            print(f"JSON report saved: {json_path}")
        
        # Save text report
        if output_format in ['text', 'both']:
            text_path = self.reporter.save_text_report(report)
            generated_files.append(text_path)
            print(f"Text report saved: {text_path}")
        
        # Create visualizations
        if visualize:
            viz_files = self.reporter.create_visualizations(
                analysis_results['bot_analyses'], 
                report
            )
            generated_files.extend(viz_files)
            if viz_files:
                print(f"Visualizations created: {len(viz_files)} files")
        
        return generated_files


def analyze_logs(log_file: str, config_override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Convenience function for simple log analysis.
    
    Args:
        log_file: Path to the log file
        config_override: Optional configuration overrides
        
    Returns:
        Dictionary with analysis results
    """
    analyzer = LogAnalyzer(config_override)
    results = analyzer.analyze_logs(log_file)
    
    if 'error' in results:
        return results
    
    # Return simplified results for backward compatibility
    report = results['report']
    return {
        'suspicious_ips': [ip['ip'] for ip in report['top_suspicious_ips']],
        'bot_count': report['summary']['bot_ips_detected'],
        'total_requests': report['summary']['total_requests'],
        'bot_traffic_percentage': report['summary']['bot_traffic_percentage'],
        'recommendations': [rec['solution'] for rec in report['recommendations']],
        'detailed_report': report
    }


def main():
    """
    Main function for command-line interface.
    """
    parser = argparse.ArgumentParser(description='Analyze web server logs for bot detection')
    parser.add_argument('--log-file', required=True, help='Path to log file')
    parser.add_argument('--output', default='both', choices=['json', 'text', 'both'], 
                       help='Output format (default: both)')
    parser.add_argument('--visualize', action='store_true', help='Create visualizations')
    parser.add_argument('--rate-limit', type=int, default=100, 
                       help='Rate limit threshold (requests/minute)')
    parser.add_argument('--time-window', type=int, default=5, 
                       help='Time window for rate analysis (minutes)')
    parser.add_argument('--output-dir', default='reports', 
                       help='Output directory for reports')
    
    args = parser.parse_args()
    
    # Configuration overrides
    config_override = {
        'RATE_LIMIT_THRESHOLD': args.rate_limit,
        'TIME_WINDOW_MINUTES': args.time_window
    }
    
    # Create analyzer
    analyzer = LogAnalyzer(config_override)
    analyzer.reporter.output_dir = args.output_dir
    
    # Analyze logs
    results = analyzer.analyze_logs(args.log_file)
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        sys.exit(1)
    
    # Display summary
    report = results['report']
    summary = report['summary']
    
    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    print(f"Total Requests: {summary['total_requests']:,}")
    print(f"Unique IPs: {summary['total_unique_ips']:,}")
    print(f"Bot IPs Detected: {summary['bot_ips_detected']:,}")
    print(f"Bot Traffic: {summary['bot_traffic_percentage']:.1f}%")
    print(f"Recommendations: {len(report['recommendations'])}")
    
    # Save reports
    files = analyzer.save_reports(results, args.output, args.visualize)
    
    print(f"\nGenerated {len(files)} output files in '{args.output_dir}' directory")
    
    # Display top recommendations
    if report['recommendations']:
        print("\nTOP RECOMMENDATIONS:")
        for i, rec in enumerate(report['recommendations'][:3], 1):
            print(f"{i}. {rec['solution'].replace('_', ' ').title()} ({rec['priority']} priority)")
            print(f"   Cost: {rec['cost']}")


if __name__ == "__main__":
    main()
