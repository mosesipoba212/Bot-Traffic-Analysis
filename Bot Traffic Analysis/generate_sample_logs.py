# Generate a larger sample log file with realistic bot patterns
import random
from datetime import datetime, timedelta

# Sample data
legitimate_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "10.0.0.5", "10.0.0.10"]
bot_ips = ["203.0.113.45", "198.51.100.10", "203.0.113.100", "198.51.100.50", "203.0.113.200"]
paths = ["/", "/index.html", "/about.html", "/products", "/contact", "/blog", "/login", "/search"]
bot_paths = ["/robots.txt", "/sitemap.xml", "/admin/login", "/wp-admin/", "/.env", "/config.php", "/backup/"]

legitimate_ua = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1"
]

bot_ua = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "python-requests/2.28.0",
    "Mozilla/5.0 (compatible; Bot)",
    "curl/7.68.0",
    "Scrapy/2.5.1",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]

def generate_log_entry(ip, timestamp, path, status, size, referer, user_agent):
    return f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size} "{referer}" "{user_agent}"'

# Generate log entries
entries = []
base_time = datetime(2025, 7, 16, 10, 0, 0)

# Generate legitimate traffic
for i in range(200):
    ip = random.choice(legitimate_ips)
    timestamp = base_time + timedelta(seconds=random.randint(0, 3600))
    path = random.choice(paths)
    status = random.choice([200, 200, 200, 200, 404])  # Mostly 200s
    size = random.randint(1000, 5000)
    referer = "http://example.com/" if random.random() > 0.3 else "-"
    user_agent = random.choice(legitimate_ua)
    
    entries.append(generate_log_entry(ip, timestamp, path, status, size, referer, user_agent))

# Generate bot traffic
for i in range(300):
    ip = random.choice(bot_ips)
    timestamp = base_time + timedelta(seconds=random.randint(0, 3600))
    
    # Bots more likely to hit suspicious paths
    if random.random() < 0.4:
        path = random.choice(bot_paths)
        status = random.choice([403, 404, 500])
    else:
        path = random.choice(paths)
        status = 200
    
    size = random.randint(100, 1000)
    referer = "-"
    user_agent = random.choice(bot_ua)
    
    entries.append(generate_log_entry(ip, timestamp, path, status, size, referer, user_agent))

# Sort by timestamp
entries.sort(key=lambda x: x.split('[')[1].split(']')[0])

# Write to file
with open('sample_logs/large_access.log', 'w') as f:
    f.write('\n'.join(entries))

print("Generated large_access.log with realistic bot patterns")
