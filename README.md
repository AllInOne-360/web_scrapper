# Advanced Web Crawler & Vulnerability Scanner for Penetration Testing

A comprehensive, asynchronous web crawler and vulnerability scanner designed specifically for penetration testing and security assessments. Features depth control, SSL handling, site map generation, and advanced vulnerability detection capabilities.

## Features

### Crawling Features
- **Asynchronous crawling** with configurable concurrent requests
- **Depth control** to limit crawling scope
- **SSL/TLS handling** with certificate verification options
- **Site map generation** in XML (sitemaps.org compliant) and JSON formats
- **URL filtering** with include/exclude patterns
- **Rate limiting** and politeness controls
- **User agent rotation** for stealth operations
- **Custom HTTP headers** support
- **robots.txt compliance** (optional)
- **Comprehensive logging** and error tracking
- **Command-line interface** with extensive options

### Vulnerability Scanning Features
- **SQL Injection Detection** with multiple payload types
- **Cross-Site Scripting (XSS) Detection** with reflected/stored payload testing
- **Command Injection Detection** for OS command execution vulnerabilities
- **Directory Traversal Detection** for file inclusion vulnerabilities
- **Open Redirect Detection** for URL redirection vulnerabilities
- **Security Headers Analysis** with missing header detection
- **HTTP Methods Testing** for dangerous method exposure
- **Multiple Report Formats** (JSON, HTML, Text)
- **Confidence Scoring** for vulnerability detection accuracy
- **Severity Classification** (Critical, High, Medium, Low)

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Quick Install

#### Linux/macOS/Kali Linux
```bash
git clone <repository-url>
cd web-crawler
chmod +x install.sh
./install.sh
```

#### Windows
```cmd
git clone <repository-url>
cd web-crawler
install.bat
```

### Manual Installation
1. Clone or download the repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```
or
```bash
pip3 install -r requirements.txt
```

### Platform Compatibility
- ✅ **Linux** (Ubuntu, CentOS, Kali Linux, etc.)
- ✅ **macOS** (10.12+)
- ✅ **Windows** (7, 8, 10, 11 with Python installed)
- ✅ **WSL** (Windows Subsystem for Linux)

### Verification
After installation, verify everything works:
```bash
python3 web.py --help
```

## Usage

### Basic Usage

```bash
# Crawl a website with default settings (depth 2)
python web.py https://example.com

# Crawl with custom depth and output
python web.py https://example.com -d 3 -o sitemap.xml --format xml
```

### Advanced Usage

```bash
# Penetration testing mode - no SSL verification, custom user agent
python web.py https://target.com --no-ssl-verify --user-agent "Security-Scanner/1.0"

# Include only admin pages, exclude logout URLs
python web.py https://target.com --include-patterns ".*admin.*" --exclude-patterns ".*logout.*"

# Custom SSL certificates and headers
python web.py https://target.com --ssl-cert client.crt --ssl-key client.key --headers "X-Custom: test" "Authorization: Bearer token"

# High-performance crawling with rate limiting
python web.py https://target.com --max-concurrent 20 --workers 10 --delay 0.5

# Vulnerability scanning - SQL injection and XSS detection
python web.py https://target.com --enable-vuln-scan --vuln-types sqli xss --max-scan-urls 20

# Full vulnerability scan with HTML report
python web.py https://target.com --enable-vuln-scan --vuln-types all --vuln-report-format html
```

## Command Line Options

### Core Options
- `start_url`: The URL to begin crawling
- `-d, --max-depth`: Maximum crawling depth (default: 2)
- `-o, --output`: Output filename
- `-f, --format`: Output format - `json` or `xml` (default: json)

### Performance & Rate Limiting
- `--delay`: Delay between requests in seconds (default: 0.1)
- `--timeout`: Request timeout in seconds (default: 30)
- `--max-concurrent`: Maximum concurrent requests (default: 10)
- `--workers`: Number of worker threads (default: 5)

### SSL/TLS Options
- `--no-ssl-verify`: Disable SSL certificate verification
- `--ssl-cert`: Client certificate file
- `--ssl-key`: Client private key file
- `--ssl-ca`: CA certificates file

### HTTP Configuration
- `--user-agent`: Custom User-Agent string
- `--no-follow-redirects`: Do not follow HTTP redirects
- `--max-redirects`: Maximum redirects to follow (default: 10)
- `--headers`: Additional HTTP headers (format: "Key: Value")

### Scope Control
- `--no-robots-txt`: Ignore robots.txt restrictions
- `--same-domain-only`: Only crawl same domain (default: True)
- `--same-protocol-only`: Only crawl same protocol (HTTP/HTTPS)
- `--include-patterns`: Regex patterns for URLs to include
- `--exclude-patterns`: Regex patterns for URLs to exclude

### Logging & Debugging
- `--log-level`: Logging level - DEBUG, INFO, WARNING, ERROR (default: INFO)
- `--log-file`: Log file path (default: crawler.log)

### Vulnerability Scanning Options
- `--enable-vuln-scan`: Enable vulnerability scanning after crawling
- `--vuln-types`: Types of vulnerabilities to scan for (sqli, xss, command_injection, directory_traversal, open_redirect, all)
- `--max-scan-urls`: Maximum URLs to scan for vulnerabilities (default: 50)
- `--scan-delay`: Delay between vulnerability scan requests in seconds (default: 1.0)
- `--vuln-report-format`: Vulnerability report format (json, html, txt)

## Output Formats

### JSON Output
Comprehensive output including:
- Crawler configuration
- Statistics (URLs crawled, found, errors)
- Complete site map with metadata
- Error details with timestamps

### XML Sitemap
Standard sitemaps.org compliant XML format with:
- URL locations
- Last modification timestamps
- Change frequencies
- Priority scores based on depth

## Security Features

- **SSL Certificate Handling**: Full support for custom certificates, client authentication, and SSL verification control
- **Header Customization**: Add custom headers for authentication, security testing
- **User Agent Rotation**: Multiple user agents to avoid detection
- **Rate Limiting**: Configurable delays to avoid triggering rate limits or IDS
- **Scope Control**: Domain restrictions and URL pattern filtering
- **robots.txt Compliance**: Optional respect for robots.txt directives

## Examples for Penetration Testing

### Reconnaissance
```bash
# Basic reconnaissance with SSL bypass
python web.py https://target.com --no-ssl-verify --same-domain-only -d 1

# Find admin interfaces
python web.py https://target.com --include-patterns ".*admin.*" ".*login.*" ".*dashboard.*"
```

### Content Discovery
```bash
# Discover all endpoints with custom headers
python web.py https://target.com --headers "Cookie: session=abc123" "X-Forwarded-For: 127.0.0.1" -d 4
```

### Vulnerability Assessment
```bash
# Comprehensive vulnerability scan
python web.py https://target.com --enable-vuln-scan --vuln-types all --max-scan-urls 100

# Target specific vulnerability types
python web.py https://target.com --enable-vuln-scan --vuln-types sqli xss command_injection

# Scan with authentication and custom headers
python web.py https://target.com --enable-vuln-scan --headers "Cookie: session=abc123" "Authorization: Bearer token"
```

### SSL Testing
```bash
# Test SSL configurations
python web.py https://target.com --ssl-cert test.crt --ssl-key test.key --no-ssl-verify
```

## Error Handling

The crawler includes comprehensive error handling:
- Network timeouts and connection errors
- SSL certificate validation errors
- HTTP error status codes
- Malformed HTML/content
- robots.txt parsing errors

All errors are logged and included in the output for analysis.

## Performance Considerations

- **Asynchronous I/O**: Uses aiohttp for high-performance concurrent requests
- **Memory Efficient**: Processes URLs in batches with configurable limits
- **Configurable Concurrency**: Adjust workers and concurrent requests based on target
- **Rate Limiting**: Built-in delays to respect server resources

## Legal & Ethical Use

This tool is designed for authorized penetration testing and security assessments only. Always ensure you have explicit permission to crawl target websites. Respect robots.txt directives and implement appropriate rate limiting to avoid disrupting services.

## Contributing

Feel free to submit issues, feature requests, or pull requests to improve the crawler.

## License

This project is provided for educational and authorized security testing purposes.
