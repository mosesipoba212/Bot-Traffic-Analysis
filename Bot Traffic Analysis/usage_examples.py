"""
Example usage of the web server log analyzer.
This script demonstrates various ways to use the bot detection system.
"""

from log_analyzer import LogAnalyzer, analyze_logs
from bot_detector import BotDetector
from report_generator import ReportGenerator
import os

def basic_usage_example():
    """
    Basic usage example - analyze a log file and get simple results.
    """
    print("=== Basic Usage Example ===")
    
    # Simple function call
    results = analyze_logs("sample_logs/access.log")
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        return
    
    print(f"Found {len(results['suspicious_ips'])} suspicious IPs:")
    for ip in results['suspicious_ips'][:5]:
        print(f"  - {ip}")
    
    print(f"Bot traffic: {results['bot_traffic_percentage']:.1f}%")
    print(f"Recommendations: {', '.join(results['recommendations'])}")
    print()

def advanced_usage_example():
    """
    Advanced usage example - custom configuration and detailed analysis.
    """
    print("=== Advanced Usage Example ===")
    
    # Custom configuration
    config_override = {
        'RATE_LIMIT_THRESHOLD': 50,  # Lower threshold
        'TIME_WINDOW_MINUTES': 1,    # Shorter window
        'SUSPICIOUS_USER_AGENTS': ['bot', 'crawler', 'python-requests', 'curl']
    }
    
    # Create analyzer with custom config
    analyzer = LogAnalyzer(config_override)
    
    # Analyze logs
    results = analyzer.analyze_logs("sample_logs/access.log")
    
    if 'error' in results:
        print(f"Error: {results['error']}")
        return
    
    # Display detailed results
    report = results['report']
    print(f"Analysis Period: {report['analysis_period']}")
    print(f"Total Requests: {report['summary']['total_requests']}")
    print(f"Unique IPs: {report['summary']['total_unique_ips']}")
    print(f"Bot IPs: {report['summary']['bot_ips_detected']}")
    print(f"High Risk IPs: {report['summary']['high_risk_ips']}")
    
    # Show top suspicious IPs with details
    print("\nTop Suspicious IPs:")
    for ip_info in report['top_suspicious_ips'][:3]:
        print(f"  IP: {ip_info['ip']} (Score: {ip_info['bot_score']:.3f})")
        print(f"      Requests: {ip_info['total_requests']}, Rate: {ip_info['request_rate']:.1f}/min")
        print(f"      Classification: {ip_info['classification']}")
    
    # Show recommendations
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  - {rec['solution'].replace('_', ' ').title()} ({rec['priority']} priority)")
        print(f"    Cost: {rec['cost']}")
        print(f"    Description: {rec['description']}")
    
    print()

def component_usage_example():
    """
    Example of using individual components.
    """
    print("=== Component Usage Example ===")
    
    # Use bot detector directly
    detector = BotDetector()
    
    # Example IP request data
    sample_requests = [
        {
            'ip': '203.0.113.100',
            'timestamp': '2025-07-16 10:00:00',
            'path': '/robots.txt',
            'status': 200,
            'user_agent': 'Mozilla/5.0 (compatible; Bot)'
        }
    ]
    
    # This would normally be called with real parsed log data
    # analysis = detector.analyze_ip_behavior(sample_requests)
    # print(f"Bot score: {analysis.get('bot_score', 0):.3f}")
    
    # Use report generator
    reporter = ReportGenerator()
    
    # Example of generating a custom report
    sample_report = {
        'summary': {
            'total_requests': 1000,
            'bot_ips_detected': 15,
            'bot_traffic_percentage': 25.5
        },
        'top_suspicious_ips': [
            {'ip': '203.0.113.100', 'bot_score': 0.85, 'total_requests': 200}
        ],
        'recommendations': [
            {'solution': 'rate_limiting', 'priority': 'high', 'cost': 'Free'}
        ]
    }
    
    text_report = reporter.generate_text_report(sample_report)
    print("Generated text report preview:")
    print(text_report[:200] + "...")
    print()

def batch_analysis_example():
    """
    Example of analyzing multiple log files.
    """
    print("=== Batch Analysis Example ===")
    
    log_files = ["sample_logs/access.log"]
    
    # Check if large log exists
    if os.path.exists("sample_logs/large_access.log"):
        log_files.append("sample_logs/large_access.log")
    
    analyzer = LogAnalyzer()
    
    for log_file in log_files:
        print(f"\nAnalyzing {log_file}...")
        results = analyzer.analyze_logs(log_file)
        
        if 'error' in results:
            print(f"Error: {results['error']}")
            continue
        
        summary = results['report']['summary']
        print(f"  Total Requests: {summary['total_requests']}")
        print(f"  Bot IPs: {summary['bot_ips_detected']}")
        print(f"  Bot Traffic: {summary['bot_traffic_percentage']:.1f}%")
        
        # Save individual reports
        output_dir = f"reports/{os.path.basename(log_file)}_analysis"
        analyzer.reporter.output_dir = output_dir
        files = analyzer.save_reports(results, 'both', False)
        print(f"  Saved {len(files)} report files to {output_dir}")

def main():
    """
    Run all usage examples.
    """
    print("Web Server Log Analysis - Usage Examples")
    print("=" * 50)
    
    # Check if sample log exists
    if not os.path.exists("sample_logs/access.log"):
        print("Error: Sample log file not found!")
        print("Please run 'python generate_sample_logs.py' first to create sample data.")
        return
    
    try:
        basic_usage_example()
        advanced_usage_example()
        component_usage_example()
        batch_analysis_example()
        
        print("All examples completed successfully!")
        print("\nTo run the full analysis:")
        print("python log_analyzer.py --log-file sample_logs/access.log --visualize")
        
    except Exception as e:
        print(f"Error running examples: {e}")
        print("Make sure all dependencies are installed: pip install -r requirements.txt")

if __name__ == "__main__":
    main()
