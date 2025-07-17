# Configuration settings for bot detection and analysis

# Rate limiting thresholds
RATE_LIMIT_THRESHOLD = 10   # requests per minute (lowered for sample data)
TIME_WINDOW_MINUTES = 5     # time window for rate analysis
BURST_THRESHOLD = 5         # requests in a short burst (30 seconds)

# Bot detection patterns
SUSPICIOUS_USER_AGENTS = [
    "bot", "crawler", "spider", "scraper", "wget", "curl",
    "python-requests", "python-urllib", "scrapy", "selenium",
    "phantomjs", "headless", "automated", "robot"
]

# HTTP status codes that might indicate bot behavior
SUSPICIOUS_STATUS_CODES = [403, 404, 429, 500, 502, 503]

# Suspicious request patterns
SUSPICIOUS_PATHS = [
    "/wp-admin", "/admin", "/.env", "/robots.txt", "/sitemap.xml",
    "/backup", "/config", "/database", "/phpMyAdmin", "/wp-config.php"
]

# File extensions that bots commonly target
SUSPICIOUS_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".py",
    ".sql", ".bak", ".backup", ".old", ".tmp"
]

# Geolocation patterns (countries with high bot activity)
HIGH_RISK_COUNTRIES = ["CN", "RU", "BR", "IN", "TR", "PK", "BD"]

# Request frequency analysis
MIN_REQUESTS_FOR_ANALYSIS = 5   # minimum requests to consider an IP (lowered)
HUMAN_REQUEST_INTERVAL = 2      # minimum seconds between human requests

# Report generation settings
MAX_SUSPICIOUS_IPS = 20         # maximum IPs to include in reports
VISUALIZATION_ENABLED = True    # enable chart generation

# Cost-effective solution recommendations
SOLUTIONS = {
    "rate_limiting": {
        "description": "Implement rate limiting to block excessive requests",
        "cost": "Free (server configuration)",
        "implementation": "nginx/apache configuration or application-level limiting"
    },
    "captcha": {
        "description": "Add CAPTCHA to protect sensitive endpoints",
        "cost": "Free (Google reCAPTCHA)",
        "implementation": "Integrate reCAPTCHA v2/v3 on login/signup pages"
    },
    "cloudflare": {
        "description": "Use Cloudflare's free tier for bot protection",
        "cost": "Free tier available",
        "implementation": "DNS change + enable bot fight mode"
    },
    "fail2ban": {
        "description": "Automatically ban IPs with suspicious activity",
        "cost": "Free (open source)",
        "implementation": "Install and configure fail2ban with custom rules"
    },
    "user_agent_filtering": {
        "description": "Block requests with suspicious User-Agent headers",
        "cost": "Free (server configuration)",
        "implementation": "nginx/apache mod_security rules"
    }
}
