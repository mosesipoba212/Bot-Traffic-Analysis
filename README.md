# Web Server Log Analysis for Bot Detection

A Python tool to analyze web server logs, detect bot traffic, and propose cost-effective solutions for startups experiencing server overloads.

## Features

- **Log Parsing**: Supports standard Combined Log Format (CLF) and Common Log Format
- **Bot Detection**: Identifies traffic patterns including:
  - High-frequency requests from single IPs
  - Suspicious User-Agent strings
  - Scraping patterns and behaviors
- **Cost-Effective Solutions**: Proposes budget-friendly mitigation strategies
- **Reporting**: Generates detailed analysis reports with visualizations
- **Error Handling**: Robust parsing of malformed log entries

## Quick Start

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run analysis on your log file:
```bash
python log_analyzer.py --log-file access.log
```

3. Generate a detailed report:
```bash
python log_analyzer.py --log-file access.log --output report.json --visualize
```

## Sample Log Format

The tool expects logs in Combined Log Format:
```
192.168.1.1 - - [17/Jul/2025:10:00:00 +0000] "GET /podcast HTTP/1.1" 200 1234 "Mozilla/5.0 (compatible; Bot)"
```

## Configuration

Customize detection thresholds in `config.py`:
- Request rate limits
- Bot detection patterns
- Suspicious User-Agent keywords

## Output

The analysis generates:
- Top suspicious IPs with requests
- Bot detection confidence scores
- Request pattern visualizations
- Recommended mitigation actions

## Cost-Effective Solutions

The tool recommends:
- Rate limiting implementations
- CAPTCHA integration points
- Free-tier CDN/firewall setups (Cloudflare)
- Server configuration optimizations

## Project Structure

```
├── log_analyzer.py          # Main analysis script
├── bot_detector.py          # Bot detection algorithms
├── report_generator.py      # Report and visualization generation
├── config.py               # Configuration settings
├── utils.py                # Helper functions
├── sample_logs/            # Sample log files for testing
└── requirements.txt        # Dependencies
```

### Basic Analysis
```python
from log_analyzer import analyze_logs

results = analyze_logs("access.log")
print(f"Found {len(results['suspicious_ips'])} suspicious IPs")
```

### Advanced Configuration
```python
from log_analyzer import LogAnalyzer

analyzer = LogAnalyzer(
    rate_limit_threshold=100,
    time_window_minutes=5,
    suspicious_ua_patterns=["bot", "crawler", "spider"]
)
results = analyzer.analyze("access.log")
```
