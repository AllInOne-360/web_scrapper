#!/usr/bin/env python3
"""
Advanced Web Crawler for Penetration Testing
Creates site maps with configurable depth, SSL options, and security testing features.
"""

import argparse
import asyncio
import json
import logging
import re
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag
from urllib.robotparser import RobotFileParser

import aiohttp
import requests
from bs4 import BeautifulSoup

from vuln_scanner import VulnerabilityScanner


class WebCrawler:
    """Advanced web crawler with penetration testing features."""

    def __init__(self, config: Dict):
        self.config = config
        self.session = None
        self.visited_urls: Set[str] = set()
        self.url_queue: deque = deque()
        self.site_map: Dict = {}
        self.errors: List[Dict] = []
        self.stats = {
            'urls_crawled': 0,
            'urls_found': 0,
            'errors': 0,
            'vulnerabilities_found': 0,
            'start_time': None,
            'end_time': None
        }
        self.vulnerabilities: List[Dict] = []

        # Setup logging
        self.setup_logging()

        # Setup SSL context
        self.ssl_context = self.setup_ssl_context()

        # Setup user agents
        self.user_agents = self.config.get('user_agents', [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ])

    def setup_logging(self):
        """Setup logging configuration."""
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.get('log_file', 'crawler.log')),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_ssl_context(self) -> ssl.SSLContext:
        """Setup SSL context based on configuration."""
        context = ssl.create_default_context()

        if not self.config.get('ssl_verify', True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

        # Custom certificate handling
        if self.config.get('ssl_cert_file'):
            context.load_cert_chain(
                self.config['ssl_cert_file'],
                self.config.get('ssl_key_file')
            )

        if self.config.get('ssl_ca_certs'):
            context.load_verify_locations(self.config['ssl_ca_certs'])

        return context

    def is_url_in_scope(self, url: str) -> bool:
        """Check if URL is within the crawling scope."""
        parsed = urlparse(url)
        base_parsed = urlparse(self.config['start_url'])

        # Check domain scope
        if self.config.get('same_domain_only', True):
            if parsed.netloc != base_parsed.netloc:
                return False

        # Check protocol scope
        if self.config.get('same_protocol_only', False):
            if parsed.scheme != base_parsed.scheme:
                return False

        # Check URL patterns
        include_patterns = self.config.get('include_patterns', [])
        exclude_patterns = self.config.get('exclude_patterns', [])

        for pattern in exclude_patterns:
            if re.search(pattern, url):
                return False

        if include_patterns:
            for pattern in include_patterns:
                if re.search(pattern, url):
                    return True
            return False

        return True

    def normalize_url(self, url: str, base_url: str) -> str:
        """Normalize URL by resolving relative URLs and removing fragments."""
        url = urljoin(base_url, url)
        url, _ = urldefrag(url)  # Remove fragment
        return url.rstrip('/')

    def extract_links_from_html(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML content."""
        soup = BeautifulSoup(html, 'html.parser')
        links = []

        # Extract various link types
        selectors = [
            ('a', 'href'),
            ('link', 'href'),
            ('area', 'href'),
            ('form', 'action'),
            ('iframe', 'src'),
            ('script', 'src'),
            ('img', 'src'),
            ('source', 'src'),
        ]

        for tag_name, attr in selectors:
            elements = soup.find_all(tag_name, {attr: True})
            for element in elements:
                href = element.get(attr)
                if href:
                    normalized = self.normalize_url(href, base_url)
                    if self.is_url_in_scope(normalized):
                        links.append(normalized)

        return list(set(links))  # Remove duplicates

    async def fetch_url(self, url: str, session: aiohttp.ClientSession) -> Tuple[Optional[str], Optional[Dict]]:
        """Fetch URL content asynchronously."""
        try:
            # Set up headers safely
            headers = {}
            user_agent = self.config.get('user_agent')
            if user_agent:
                headers['User-Agent'] = user_agent
            else:
                headers['User-Agent'] = 'WebCrawler/1.0'

            # Make the request
            timeout = aiohttp.ClientTimeout(total=self.config.get('timeout', 30))
            async with session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=True
            ) as response:

                # Only process HTML content
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type.lower() and 'application/xhtml' not in content_type.lower():
                    return None, None

                html = await response.text()

                # Create safe metadata
                metadata = {
                    'status_code': response.status,
                    'url': str(response.url),
                    'content_type': content_type
                }

                return html, metadata

        except Exception as e:
            error_msg = str(e)
            self.errors.append({
                'url': url,
                'error': error_msg,
                'timestamp': datetime.now().isoformat()
            })
            print(f"Error fetching {url}: {error_msg}")
            return None, None

    def check_robots_txt(self, base_url: str) -> bool:
        """Check robots.txt for crawling permissions."""
        if not self.config.get('respect_robots_txt', True):
            return True

        try:
            parsed = urlparse(base_url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()

            user_agent = self.config.get('user_agent', '*')
            return rp.can_fetch(user_agent, base_url)

        except Exception as e:
            self.logger.warning(f"Could not read robots.txt for {base_url}: {str(e)}")
            return True  # Allow crawling if robots.txt can't be read

    async def crawl_worker(self, session: aiohttp.ClientSession):
        """Worker function for crawling URLs."""
        while True:
            try:
                url, depth = self.url_queue.popleft()
            except IndexError:
                break

            if url in self.visited_urls or depth > self.config['max_depth']:
                continue

            self.visited_urls.add(url)
            self.logger.info(f"Crawling: {url} (depth: {depth})")

            # Rate limiting
            if self.config.get('delay', 0) > 0:
                await asyncio.sleep(self.config['delay'])

            html, metadata = await self.fetch_url(url, session)

            if html:
                self.stats['urls_crawled'] += 1
                self.site_map[url] = {
                    'depth': depth,
                    'metadata': metadata,
                    'links_found': [],
                    'timestamp': datetime.now().isoformat()
                }

                # Extract links
                links = self.extract_links_from_html(html, url)
                self.site_map[url]['links_found'] = links
                self.stats['urls_found'] += len(links)

                # Add new URLs to queue
                for link in links:
                    if link not in self.visited_urls and (link, depth + 1) not in [(u, d) for u, d in self.url_queue]:
                        self.url_queue.append((link, depth + 1))

    async def crawl(self) -> Dict:
        """Main crawling function."""
        self.stats['start_time'] = datetime.now().isoformat()

        # Initialize starting URL
        start_url = self.normalize_url(self.config['start_url'], self.config['start_url'])

        if not self.check_robots_txt(start_url):
            self.logger.error(f"Robots.txt disallows crawling: {start_url}")
            return self.site_map

        self.url_queue.append((start_url, 0))

        # Setup aiohttp session (simplified to avoid potential issues)
        async with aiohttp.ClientSession() as session:
            # Create worker tasks
            workers = []
            for _ in range(self.config.get('num_workers', 5)):
                task = asyncio.create_task(self.crawl_worker(session))
                workers.append(task)

            # Wait for all workers to complete
            await asyncio.gather(*workers, return_exceptions=True)

        self.stats['end_time'] = datetime.now().isoformat()
        self.stats['errors'] = len(self.errors)

        # Perform vulnerability scanning if enabled
        if self.config.get('enable_vuln_scan', False):
            await self._perform_vulnerability_scan()

        return self.site_map

    async def _perform_vulnerability_scan(self):
        """Perform vulnerability scanning on crawled URLs."""
        self.logger.info("Starting vulnerability scan...")

        # Prepare scanner configuration
        scanner_config = {
            'user_agent': self.config.get('user_agent', 'WebCrawler/1.0'),
            'headers': self.config.get('headers', {}),
            'scan_delay': self.config.get('scan_delay', 1.0),
            'vuln_types': self.config.get('vuln_types', ['sqli', 'xss', 'command_injection', 'directory_traversal', 'open_redirect'])
        }

        # Initialize vulnerability scanner
        scanner = VulnerabilityScanner(scanner_config)

        # Get URLs to scan (limit for performance)
        urls_to_scan = list(self.site_map.keys())[:self.config.get('max_scan_urls', 50)]

        self.logger.info(f"Scanning {len(urls_to_scan)} URLs for vulnerabilities...")

        # Perform comprehensive scan
        scan_results = await scanner.comprehensive_scan(urls_to_scan)

        # Update stats and store vulnerabilities
        self.vulnerabilities = scan_results['vulnerabilities']
        self.stats['vulnerabilities_found'] = len(self.vulnerabilities)

        self.logger.info(f"Vulnerability scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")

    def generate_xml_sitemap(self) -> str:
        """Generate XML sitemap following sitemaps.org protocol."""
        urlset = ET.Element("urlset", xmlns="http://www.sitemaps.org/schemas/sitemap/0.9")

        for url, data in self.site_map.items():
            url_element = ET.SubElement(urlset, "url")
            loc = ET.SubElement(url_element, "loc")
            loc.text = url

            lastmod = ET.SubElement(url_element, "lastmod")
            lastmod.text = data.get('timestamp', datetime.now().isoformat())

            changefreq = ET.SubElement(url_element, "changefreq")
            changefreq.text = "monthly"  # Default value

            priority = ET.SubElement(url_element, "priority")
            # Higher priority for shallower pages
            priority_val = max(0.1, 1.0 - (data.get('depth', 0) * 0.1))
            priority.text = f"{priority_val:.1f}"

        # Convert to string with proper encoding
        tree = ET.ElementTree(urlset)
        ET.indent(tree, space="  ", level=0)

        return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(urlset, encoding='unicode')

    def generate_json_output(self) -> Dict:
        """Generate comprehensive JSON output."""
        return {
            'config': self.config,
            'stats': self.stats,
            'site_map': self.site_map,
            'errors': self.errors,
            'vulnerabilities': self.vulnerabilities
        }

    def save_results(self, output_format: str = 'json', filename: Optional[str] = None):
        """Save crawling results in specified format."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crawler_results_{timestamp}.{output_format}"

        if output_format == 'xml':
            content = self.generate_xml_sitemap()
        elif output_format == 'json':
            content = json.dumps(self.generate_json_output(), indent=2, ensure_ascii=False, default=str)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)

        self.logger.info(f"Results saved to {filename}")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Advanced Web Crawler for Penetration Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com -d 3 -o sitemap.xml --format xml
  %(prog)s https://example.com --no-ssl-verify --user-agent "Custom Agent"
  %(prog)s https://example.com --include-patterns ".*admin.*" --exclude-patterns ".*logout.*"
  %(prog)s https://example.com --enable-vuln-scan --vuln-types sqli xss --max-scan-urls 20
  %(prog)s https://target.com --enable-vuln-scan --vuln-report-format html
        """
    )

    parser.add_argument('start_url', help='Starting URL to crawl')
    parser.add_argument('-d', '--max-depth', type=int, default=2,
                       help='Maximum crawling depth (default: 2)')
    parser.add_argument('-o', '--output', help='Output filename')
    parser.add_argument('-f', '--format', choices=['json', 'xml'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--max-concurrent', type=int, default=10,
                       help='Maximum concurrent requests (default: 10)')
    parser.add_argument('--workers', type=int, default=5,
                       help='Number of worker threads (default: 5)')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--no-ssl-verify', action='store_true',
                       help='Disable SSL certificate verification')
    parser.add_argument('--ssl-cert', help='Client certificate file')
    parser.add_argument('--ssl-key', help='Client private key file')
    parser.add_argument('--ssl-ca', help='CA certificates file')
    parser.add_argument('--no-follow-redirects', action='store_true',
                       help='Do not follow HTTP redirects')
    parser.add_argument('--max-redirects', type=int, default=10,
                       help='Maximum number of redirects to follow (default: 10)')
    parser.add_argument('--no-robots-txt', action='store_true',
                       help='Ignore robots.txt restrictions')
    parser.add_argument('--same-domain-only', action='store_true', default=True,
                       help='Only crawl same domain (default: True)')
    parser.add_argument('--same-protocol-only', action='store_true',
                       help='Only crawl same protocol (HTTP/HTTPS)')
    parser.add_argument('--include-patterns', nargs='+',
                       help='Regex patterns for URLs to include')
    parser.add_argument('--exclude-patterns', nargs='+',
                       help='Regex patterns for URLs to exclude')
    parser.add_argument('--headers', nargs='+',
                       help='Additional HTTP headers (format: "Key: Value")')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level (default: INFO)')
    parser.add_argument('--log-file', default='crawler.log',
                       help='Log file path (default: crawler.log)')

    # Vulnerability scanning options
    vuln_group = parser.add_argument_group('Vulnerability Scanning')
    vuln_group.add_argument('--enable-vuln-scan', action='store_true',
                           help='Enable vulnerability scanning after crawling')
    vuln_group.add_argument('--vuln-types', nargs='+',
                           choices=['sqli', 'xss', 'command_injection', 'directory_traversal', 'open_redirect', 'all'],
                           default=['sqli', 'xss', 'command_injection', 'directory_traversal', 'open_redirect'],
                           help='Types of vulnerabilities to scan for (default: all)')
    vuln_group.add_argument('--max-scan-urls', type=int, default=50,
                           help='Maximum URLs to scan for vulnerabilities (default: 50)')
    vuln_group.add_argument('--scan-delay', type=float, default=1.0,
                           help='Delay between vulnerability scan requests in seconds (default: 1.0)')
    vuln_group.add_argument('--vuln-report-format', choices=['json', 'html', 'txt'],
                           default='json', help='Vulnerability report format (default: json)')

    return parser.parse_args()


def main():
    """Main function."""
    args = parse_arguments()

    # Build configuration from arguments
    vuln_types = args.vuln_types
    if 'all' in vuln_types:
        vuln_types = ['sqli', 'xss', 'command_injection', 'directory_traversal', 'open_redirect']

    config = {
        'start_url': args.start_url,
        'max_depth': args.max_depth,
        'delay': args.delay,
        'timeout': args.timeout,
        'max_concurrent_requests': args.max_concurrent,
        'num_workers': args.workers,
        'user_agent': args.user_agent,
        'ssl_verify': not args.no_ssl_verify,
        'ssl_cert_file': args.ssl_cert,
        'ssl_key_file': args.ssl_key,
        'ssl_ca_certs': args.ssl_ca,
        'follow_redirects': not args.no_follow_redirects,
        'max_redirects': args.max_redirects,
        'respect_robots_txt': not args.no_robots_txt,
        'same_domain_only': args.same_domain_only,
        'same_protocol_only': args.same_protocol_only,
        'include_patterns': args.include_patterns or [],
        'exclude_patterns': args.exclude_patterns or [],
        'log_level': args.log_level,
        'log_file': args.log_file,
        # Vulnerability scanning config
        'enable_vuln_scan': args.enable_vuln_scan,
        'vuln_types': vuln_types,
        'max_scan_urls': args.max_scan_urls,
        'scan_delay': args.scan_delay
    }

    # Parse additional headers
    if args.headers:
        config['headers'] = {}
        for header in args.headers:
            if ':' in header:
                key, value = header.split(':', 1)
                config['headers'][key.strip()] = value.strip()

    # Create and run crawler
    crawler = WebCrawler(config)

    try:
        print(f"Starting crawl of {args.start_url} with depth {args.max_depth}")
        print("Press Ctrl+C to stop...")

        # Run the crawler
        site_map = asyncio.run(crawler.crawl())

        print("\nCrawl completed!")
        print(f"URLs crawled: {crawler.stats['urls_crawled']}")
        print(f"URLs found: {crawler.stats['urls_found']}")
        print(f"Errors: {crawler.stats['errors']}")

        if args.enable_vuln_scan:
            print(f"Vulnerabilities found: {crawler.stats['vulnerabilities_found']}")

        # Save results
        if site_map:
            crawler.save_results(args.format, args.output)
            output_name = args.output or f"crawler_results_*.{args.format}"
            print(f"Crawler results saved to {output_name}")

            # Save vulnerability report if scanning was enabled
            if args.enable_vuln_scan and crawler.vulnerabilities:
                vuln_filename = args.output.replace('.json', '_vulns.' + args.vuln_report_format) if args.output else f"vulnerabilities_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.vuln_report_format}"

                # Create scanner instance to generate report
                from vuln_scanner import VulnerabilityScanner
                scanner = VulnerabilityScanner({})
                scanner.vulnerabilities = crawler.vulnerabilities
                scanner.stats = {'vulnerabilities_found': len(crawler.vulnerabilities)}

                vuln_report = scanner.generate_report(args.vuln_report_format)
                with open(vuln_filename, 'w', encoding='utf-8') as f:
                    f.write(vuln_report)

                print(f"Vulnerability report saved to {vuln_filename}")
        else:
            print("No URLs were crawled. Check logs for errors.")

    except KeyboardInterrupt:
        print("\nCrawl interrupted by user")
        if crawler.site_map:
            crawler.save_results(args.format, args.output or 'interrupted_results.json')
            print("Partial results saved")
    except Exception as e:
        print(f"Error during crawling: {e}")
        logging.error(f"Crawler error: {e}", exc_info=True)


if __name__ == '__main__':
    main()
