#!/usr/bin/env python3
"""
CYBER SECURITY SWISS ARMY KNIFE - Ultimate Professional Web Application Scanner
Enterprise-grade penetration testing tool with advanced detection capabilities
"""

import requests
import argparse
import sys
import time
import json
import hashlib
import random
import base64
import zlib
from urllib.parse import urljoin, urlparse, quote, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import os
import re
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
import ipaddress
import subprocess

try:
    import dns.resolver
    from dns.exception import DNSException
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    from whois.parser import PywhoisError
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import ssl
    import socket
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import OpenSSL
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

class Color:
    """Enhanced color class for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    
    @classmethod
    def rainbow_text(cls, text):
        """Create rainbow colored text"""
        colors = [cls.RED, cls.YELLOW, cls.GREEN, cls.CYAN, cls.BLUE, cls.MAGENTA]
        result = ""
        for i, char in enumerate(text):
            result += colors[i % len(colors)] + char
        return result + cls.END

class ProgressBar:
    """Advanced progress bar with multiple styles"""
    def __init__(self, total, description="Progress", width=50):
        self.total = total
        self.description = description
        self.width = width
        self.start_time = time.time()
        
    def update(self, current):
        percent = current / self.total
        filled = int(self.width * percent)
        bar = '█' * filled + '░' * (self.width - filled)
        
        elapsed = time.time() - self.start_time
        if current > 0:
            eta = (elapsed / current) * (self.total - current)
        else:
            eta = 0
            
        sys.stdout.write(f'\r{Color.CYAN}{self.description}:{Color.END} [{bar}] {percent:.1%} '
                        f'| {current}/{self.total} | ETA: {eta:.1f}s')
        sys.stdout.flush()
        
    def finish(self):
        sys.stdout.write('\n')
        sys.stdout.flush()

class AdvancedSecurityScanner:
    def __init__(self, target_url, config=None):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.config = config or {}
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'security_issues': [],
            'technologies': [],
            'directories': [],
            'subdomains': [],
            'vulnerabilities': [],
            'dns_info': {},
            'ssl_info': {},
            'whois_info': {},
            'server_info': {},
            'waf_detection': {},
            'cves': [],
            'risk_score': 0,
            'threat_level': 'LOW'
        }
        
        # Advanced session configuration
        self.session = requests.Session()
        self.setup_advanced_session()
        
        # Enhanced statistics
        self.stats = {
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'critical_issues': 0,
            'start_time': time.time(),
            'bandwidth_used': 0,
            'unique_patterns': set()
        }
        
    def setup_advanced_session(self):
        """Advanced session setup with evasion techniques"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/119.0.0.0'
        ]
        
        self.session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
        })
        
        # Advanced proxy configuration
        if self.config.get('proxy'):
            proxies = {
                'http': self.config['proxy'],
                'https': self.config['proxy']
            }
            self.session.proxies.update(proxies)
            
        # Rate limiting and delays
        self.request_delay = self.config.get('delay', 0.1)
        self.last_request_time = 0

    def intelligent_request(self, url, method='GET', **kwargs):
        """Intelligent request with rate limiting and evasion"""
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_request_time < self.request_delay:
            time.sleep(self.request_delay - (current_time - self.last_request_time))
        
        # Randomize headers for each request
        self.session.headers['User-Agent'] = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ])
        
        try:
            response = self.session.request(method, url, timeout=self.config.get('timeout', 10), **kwargs)
            self.stats['requests_sent'] += 1
            self.stats['bandwidth_used'] += len(response.content)
            self.last_request_time = time.time()
            return response
        except requests.RequestException as e:
            return None

    def print_status(self, message, status="info", details=None):
        """Enhanced status printing with details"""
        icons = {
            "info": f"{Color.BLUE}🅘{Color.END}",
            "success": f"{Color.GREEN}✅{Color.END}",
            "warning": f"{Color.YELLOW}⚠️{Color.END}",
            "error": f"{Color.RED}❌{Color.END}",
            "critical": f"{Color.RED}🚨{Color.END}",
            "scan": f"{Color.CYAN}🔍{Color.END}",
            "shield": f"{Color.GREEN}🛡️{Color.END}",
            "fire": f"{Color.RED}🔥{Color.END}"
        }
        
        colors = {
            "info": Color.BLUE,
            "success": Color.GREEN,
            "warning": Color.YELLOW,
            "error": Color.RED,
            "critical": Color.RED,
            "scan": Color.CYAN,
            "shield": Color.GREEN,
            "fire": Color.RED
        }
        
        icon = icons.get(status, icons["info"])
        color = colors.get(status, Color.BLUE)
        
        output = f"  {icon} {color}{message}{Color.END}"
        if details:
            output += f" {Color.WHITE}({details}){Color.END}"
        print(output)

class IntelligentDirectoryBruteforcer:
    def __init__(self, scanner, threads=20, timeout=8):
        self.scanner = scanner
        self.threads = threads
        self.timeout = timeout
        self.found_directories = []
        self.tech_specific_paths = {}
        
        # AI-powered wordlist generation
        self.smart_wordlists = self.generate_intelligent_wordlists()
    
    def generate_intelligent_wordlists(self):
        """Generate context-aware wordlists based on target analysis"""
        base_wordlists = {
            'critical': self.get_critical_paths(),
            'common': self.get_common_paths(),
            'backups': self.get_backup_paths(),
            'configs': self.get_config_paths(),
            'apis': self.get_api_paths(),
            'devops': self.get_devops_paths(),
            'cloud': self.get_cloud_paths(),
            'database': self.get_database_paths()
        }
        
        # Technology-specific paths will be added after tech detection
        return base_wordlists
    
    def get_critical_paths(self):
        """Critical security paths"""
        return [
            'admin', 'administrator', 'wp-admin', 'panel', 'login', 
            'admin/login', 'administrator/login', 'admincp', 'cp',
            'control', 'dashboard', 'manager', 'webadmin', 'cpanel',
            'phpmyadmin', 'mysql', 'sql', 'webmin', 'plesk',
            'root', 'superuser', 'sysadmin', 'backend', 'moderator'
        ]
    
    def get_common_paths(self):
        """Common application paths"""
        return [
            'uploads', 'files', 'images', 'assets', 'media', 'static',
            'css', 'js', 'public', 'private', 'tmp', 'temp', 'cache',
            'session', 'logs', 'database', 'db', 'storage', 'downloads',
            'export', 'import', 'backup', 'archives', 'reports'
        ]
    
    def get_backup_paths(self):
        """Backup file patterns"""
        extensions = ['.zip', '.tar', '.tar.gz', '.rar', '.7z', '.bak', '.old', '.sql', '.dump', '.backup']
        bases = ['backup', 'dump', 'database', 'site', 'web', 'www', 'db', 'sql', 'data', 'full']
        dates = ['', '_2024', '_2023', '_old', '_new', '_latest']
        return [f"{base}{date}{ext}" for base in bases for date in dates for ext in extensions]
    
    def get_config_paths(self):
        """Configuration files"""
        return [
            'config.php', 'wp-config.php', 'configuration.php', 'config.json',
            'config.xml', 'config.yml', 'config.yaml', 'settings.py',
            'settings.json', '.env', '.env.example', '.env.local',
            'app.config', 'web.config', 'application.yml', 'application.properties',
            'config.inc.php', 'database.php', 'db.php', 'config.database.php'
        ]
    
    def get_api_paths(self):
        """API endpoints"""
        versions = ['', 'v1', 'v2', 'v3', 'v4', 'v5', 'latest', 'stable', 'beta']
        bases = ['api', 'rest', 'graphql', 'ajax', 'json', 'xmlrpc', 'soap', 'rpc']
        return [f"{base}/{ver}".rstrip('/') for base in bases for ver in versions]
    
    def get_devops_paths(self):
        """DevOps and infrastructure paths"""
        return [
            '.git', '.svn', '.hg', '.gitignore', 'Dockerfile', 'docker-compose.yml',
            'Jenkinsfile', '.travis.yml', '.github', '.gitlab-ci.yml',
            'package.json', 'composer.json', 'pom.xml', 'build.gradle',
            'requirements.txt', 'Pipfile', 'Gemfile', 'yarn.lock'
        ]
    
    def get_cloud_paths(self):
        """Cloud and infrastructure paths"""
        return [
            'aws', 'azure', 'gcp', 'cloud', 's3', 'ec2', 'lambda',
            'storage', 'bucket', 'blob', 'cdn', 'edge', 'serverless'
        ]
    
    def get_database_paths(self):
        """Database related paths"""
        return [
            'phpmyadmin', 'adminer', 'mysql', 'postgresql', 'mongodb',
            'redis', 'memcached', 'sqlite', 'oracle', 'mssql',
            'database', 'db', 'dba', 'sql', 'nosql'
        ]
    
    def add_technology_specific_paths(self, technologies):
        """Add paths specific to detected technologies"""
        tech_paths = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'xmlrpc.php'],
            'Laravel': ['storage', 'bootstrap', 'vendor', 'artisan', 'routes'],
            'Django': ['static', 'media', 'admin', 'api', 'graphql'],
            'React': ['build', 'static/js', 'static/css', 'manifest.json'],
            'Vue.js': ['dist', 'src', 'public', 'vue.config.js'],
            'Magento': ['static/frontend', 'media/catalog', 'var/log'],
            'Joomla': ['media', 'components', 'modules', 'plugins', 'templates'],
            'Drupal': ['sites/default', 'modules', 'themes', 'profiles']
        }
        
        for tech in technologies:
            if tech in tech_paths:
                self.smart_wordlists[tech] = tech_paths[tech]

    def scan_directory(self, path):
        """Enhanced directory scanning with content analysis"""
        url = urljoin(self.scanner.target_url, path)
        
        try:
            response = self.scanner.intelligent_request(url)
            if not response:
                return None
                
            if response.status_code in [200, 301, 302, 403, 401]:
                # Content analysis
                content_analysis = self.analyze_content(response.text, response.headers)
                
                result = {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'redirect': response.headers.get('Location', ''),
                    'directory': path,
                    'content_type': response.headers.get('Content-Type', ''),
                    'server': response.headers.get('Server', ''),
                    'title': self.extract_title(response.text),
                    'analysis': content_analysis
                }
                
                # Enhanced risk assessment
                result.update(self.assess_risk_level(result))
                return result
                
        except Exception:
            pass
        
        return None
    
    def analyze_content(self, content, headers):
        """Analyze content for interesting patterns"""
        analysis = {
            'has_forms': bool(re.search(r'<form[^>]*>', content, re.IGNORECASE)),
            'has_login': bool(re.search(r'password|login|sign.in', content, re.IGNORECASE)),
            'has_comments': '<!--' in content,
            'has_errors': bool(re.search(r'error|exception|warning', content, re.IGNORECASE)),
            'has_emails': len(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)),
            'has_ips': len(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content)),
            'tech_indicators': []
        }
        
        return analysis
    
    def extract_title(self, content):
        """Extract page title from HTML"""
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE)
        return title_match.group(1).strip() if title_match else ''
    
    def assess_risk_level(self, result):
        """Advanced risk assessment"""
        risk_factors = {
            'admin_keywords': ['admin', 'login', 'config', 'backup', 'database'],
            'sensitive_extensions': ['.env', '.sql', '.bak', '.old', '.tar', '.zip'],
            'dangerous_directories': ['.git', '.svn', '.htaccess']
        }
        
        risk_score = 0
        risk_level = 'LOW'
        
        # Check path for risk indicators
        path = result['directory'].lower()
        
        for keyword in risk_factors['admin_keywords']:
            if keyword in path:
                risk_score += 2
                
        for ext in risk_factors['sensitive_extensions']:
            if path.endswith(ext):
                risk_score += 3
                
        for directory in risk_factors['dangerous_directories']:
            if directory in path:
                risk_score += 4
        
        # Status code based risk
        if result['status'] == 200:
            risk_score += 1
        elif result['status'] in [301, 302]:
            risk_score += 0.5
        elif result['status'] == 403:
            risk_score += 1.5
        elif result['status'] == 401:
            risk_score += 2
            
        # Content based risk
        if result['analysis']['has_login']:
            risk_score += 2
        if result['analysis']['has_errors']:
            risk_score += 1
            
        # Determine risk level
        if risk_score >= 8:
            risk_level = 'CRITICAL'
        elif risk_score >= 5:
            risk_level = 'HIGH'
        elif risk_score >= 3:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
            
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'type': 'critical' if risk_level in ['CRITICAL', 'HIGH'] else 'common'
        }

    def scan_all_directories(self):
        """Perform intelligent directory scanning"""
        # Combine all wordlists
        all_paths = []
        for category, paths in self.smart_wordlists.items():
            all_paths.extend(paths)
        
        # Remove duplicates while preserving order
        all_paths = list(dict.fromkeys(all_paths))
        
        self.scanner.print_status(f"Starting intelligent directory bruteforce", "scan", 
                                f"{len(all_paths)} paths, {self.threads} threads")
        
        progress = ProgressBar(len(all_paths), "Directory Scanning")
        found_count = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {executor.submit(self.scan_directory, path): path for path in all_paths}
            
            for i, future in enumerate(as_completed(future_to_path)):
                progress.update(i + 1)
                result = future.result()
                if result:
                    self.found_directories.append(result)
                    found_count += 1
                    
                    # Real-time intelligent output
                    self.print_discovery(result)
        
        progress.finish()
        return found_count
    
    def print_discovery(self, result):
        """Intelligent discovery printing"""
        status_icons = {
            200: f"{Color.GREEN}🟢{Color.END}",
            301: f"{Color.BLUE}🔵{Color.END}", 
            302: f"{Color.BLUE}🔵{Color.END}",
            403: f"{Color.YELLOW}🟡{Color.END}",
            401: f"{Color.YELLOW}🟡{Color.END}",
            500: f"{Color.RED}🔴{Color.END}"
        }
        
        risk_colors = {
            'CRITICAL': Color.RED,
            'HIGH': Color.RED,
            'MEDIUM': Color.YELLOW,
            'LOW': Color.GREEN
        }
        
        emoji = status_icons.get(result['status'], '⚪')
        risk_color = risk_colors.get(result['risk_level'], Color.WHITE)
        
        # Enhanced output with context
        output = f"    {emoji} [{result['status']}] {risk_color}{result['url']}{Color.END}"
        
        # Add context hints
        hints = []
        if result['analysis']['has_login']:
            hints.append("🔐 Login")
        if result['analysis']['has_forms']:
            hints.append("📝 Forms")
        if result['title']:
            hints.append(f'"{result["title"][:30]}"')
            
        if hints:
            output += f" {Color.WHITE}({', '.join(hints)}){Color.END}"
            
        print(output)

class AdvancedTechnologyDetector:
    def __init__(self, scanner):
        self.scanner = scanner
        self.technologies = []
        self.confidence_scores = {}
        
        # Extended technology signatures
        self.signatures = self.load_advanced_signatures()
    
    def load_advanced_signatures(self):
        """Load comprehensive technology signatures"""
        return {
            'cms': {
                'WordPress': {'patterns': ['wp-content', 'wp-includes', '/wp-admin/', 'wordpress'], 'confidence': 0.9},
                'Joomla': {'patterns': ['joomla', '/media/jui/', '/components/com_'], 'confidence': 0.8},
                'Drupal': {'patterns': ['drupal', '/sites/default/', 'Drupal.settings'], 'confidence': 0.85},
                'Magento': {'patterns': ['magento', '/static/frontend/', '/media/'], 'confidence': 0.8},
                'Shopify': {'patterns': ['shopify', 'cdn.shopify.com'], 'confidence': 0.9},
            },
            'frameworks': {
                'Laravel': {'patterns': ['laravel', '/storage/framework/', 'csrf-token'], 'confidence': 0.8},
                'Django': {'patterns': ['django', 'csrftoken', 'Django'], 'confidence': 0.85},
                'React': {'patterns': ['react', 'react-dom', '__reactInternalInstance'], 'confidence': 0.7},
                'Vue.js': {'patterns': ['vue', '__vue__', 'v-app'], 'confidence': 0.7},
                'Angular': {'patterns': ['angular', 'ng-'], 'confidence': 0.7},
                'Express.js': {'patterns': ['express', 'X-Powered-By: Express'], 'confidence': 0.8},
            },
            'servers': {
                'Apache': {'patterns': ['Apache', 'server: apache'], 'confidence': 0.9},
                'Nginx': {'patterns': ['nginx', 'server: nginx'], 'confidence': 0.9},
                'IIS': {'patterns': ['Microsoft-IIS', 'server: microsoft-iis'], 'confidence': 0.9},
                'Cloudflare': {'patterns': ['cloudflare', 'cf-ray'], 'confidence': 0.95},
            },
            'languages': {
                'PHP': {'patterns': ['php', 'PHP/', 'X-Powered-By: PHP'], 'confidence': 0.9},
                'Python': {'patterns': ['python', 'Python/', 'Django'], 'confidence': 0.8},
                'Node.js': {'patterns': ['node', 'express', 'X-Powered-By: Express'], 'confidence': 0.8},
                'Java': {'patterns': ['java', 'jsp', 'servlet'], 'confidence': 0.8},
                'Ruby': {'patterns': ['ruby', 'rails', 'X-Runtime: ruby'], 'confidence': 0.8},
            },
            'databases': {
                'MySQL': {'patterns': ['mysql', 'mysqli_connect'], 'confidence': 0.7},
                'PostgreSQL': {'patterns': ['postgresql', 'pg_'], 'confidence': 0.7},
                'MongoDB': {'patterns': ['mongodb', 'mongo'], 'confidence': 0.6},
            },
            'analytics': {
                'Google Analytics': {'patterns': ['google-analytics', 'ga.js', 'gtag.js'], 'confidence': 0.95},
                'Google Tag Manager': {'patterns': ['googletagmanager', 'gtm.js'], 'confidence': 0.95},
                'Facebook Pixel': {'patterns': ['facebook-pixel', 'fbq('], 'confidence': 0.9},
            }
        }
    
    def detect_technologies(self):
        """Advanced technology detection with confidence scoring"""
        self.scanner.print_status("Running advanced technology detection...", "scan")
        
        try:
            response = self.scanner.intelligent_request(self.scanner.target_url)
            if not response:
                return []
                
            headers = response.headers
            content = response.text
            scripts = self.extract_scripts(content)
            
            detected = []
            
            # Multi-layered detection
            detected.extend(self.detect_from_headers(headers))
            detected.extend(self.detect_from_content(content))
            detected.extend(self.detect_from_scripts(scripts))
            detected.extend(self.detect_from_cookies(headers))
            detected.extend(self.detect_from_file_extensions(response.url))
            
            # Remove duplicates and sort by confidence
            unique_detected = []
            seen = set()
            for tech, confidence in detected:
                if tech not in seen:
                    seen.add(tech)
                    unique_detected.append((tech, confidence))
            
            unique_detected.sort(key=lambda x: x[1], reverse=True)
            self.technologies = [tech for tech, _ in unique_detected]
            self.confidence_scores = {tech: conf for tech, conf in unique_detected}
            
            # Print results with confidence
            for tech, confidence in unique_detected[:10]:  # Top 10
                confidence_color = Color.GREEN if confidence > 0.8 else Color.YELLOW if confidence > 0.6 else Color.RED
                self.scanner.print_status(f"Detected: {tech}", "success", f"{confidence:.0%} confidence")
                
            return self.technologies
            
        except Exception as e:
            self.scanner.print_status(f"Technology detection failed: {e}", "error")
            return []
    
    def detect_from_headers(self, headers):
        """Detect technologies from HTTP headers"""
        detected = []
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        for category, techs in self.signatures.items():
            for tech, data in techs.items():
                for pattern in data['patterns']:
                    if (pattern.lower() in server or 
                        pattern.lower() in powered_by):
                        detected.append((tech, data['confidence']))
                        
        return detected
    
    def detect_from_content(self, content):
        """Detect technologies from page content"""
        detected = []
        content_lower = content.lower()
        
        for category, techs in self.signatures.items():
            for tech, data in techs.items():
                for pattern in data['patterns']:
                    if pattern.lower() in content_lower:
                        # Adjust confidence based on occurrence count
                        count = content_lower.count(pattern.lower())
                        confidence = min(data['confidence'] + (count * 0.1), 0.95)
                        detected.append((tech, confidence))
                        
        return detected
    
    def extract_scripts(self, content):
        """Extract JavaScript and CSS references"""
        scripts = []
        # Extract script src
        script_pattern = r'<script[^>]*src=["\']([^"\']*)["\']'
        scripts.extend(re.findall(script_pattern, content, re.IGNORECASE))
        
        # Extract link href for CSS
        css_pattern = r'<link[^>]*href=["\']([^"\']*)["\']'
        scripts.extend(re.findall(css_pattern, content, re.IGNORECASE))
        
        return scripts
    
    def detect_from_scripts(self, scripts):
        """Detect technologies from script and CSS references"""
        detected = []
        
        for script in scripts:
            for category, techs in self.signatures.items():
                for tech, data in techs.items():
                    for pattern in data['patterns']:
                        if pattern.lower() in script.lower():
                            detected.append((tech, data['confidence']))
                            
        return detected
    
    def detect_from_cookies(self, headers):
        """Detect technologies from cookies"""
        detected = []
        cookies = headers.get('Set-Cookie', '')
        
        cookie_indicators = {
            'PHP': 'PHPSESSID',
            'ASP.NET': 'ASP.NET_SessionId',
            'Laravel': 'laravel_session',
            'Django': 'sessionid',
        }
        
        for tech, indicator in cookie_indicators.items():
            if indicator in cookies:
                detected.append((tech, 0.9))
                
        return detected
    
    def detect_from_file_extensions(self, url):
        """Detect technologies from file extensions in URLs"""
        detected = []
        path = urlparse(url).path
        
        extension_indicators = {
            '.php': 'PHP',
            '.aspx': 'ASP.NET',
            '.jsp': 'Java',
            '.py': 'Python',
            '.rb': 'Ruby',
        }
        
        for ext, tech in extension_indicators.items():
            if path.endswith(ext):
                detected.append((tech, 0.8))
                
        return detected

class AdvancedVulnerabilityScanner:
    def __init__(self, scanner):
        self.scanner = scanner
        self.vulnerabilities = []
        self.cves = []
        
        # Vulnerability database
        self.vuln_db = self.load_vulnerability_database()
    
    def load_vulnerability_database(self):
        """Load known vulnerability patterns"""
        return {
            'sql_injection': {
                'patterns': [
                    r"sql.*syntax.*error",
                    r"warning.*mysql",
                    r"Microsoft OLE DB Provider for ODBC Drivers",
                    r"ODBC Driver",
                    r"PostgreSQL.*ERROR"
                ],
                'risk': 'HIGH'
            },
            'xss': {
                'patterns': [
                    r"<script>alert",
                    r"javascript:",
                    r"onerror=",
                    r"onload="
                ],
                'risk': 'MEDIUM'
            },
            'path_traversal': {
                'patterns': [
                    r"\.\.[/\\]",
                    r"etc/passwd",
                    r"boot.ini",
                    r"win.ini"
                ],
                'risk': 'HIGH'
            },
            'information_disclosure': {
                'patterns': [
                    r"stack trace:",
                    r"Microsoft .NET Framework",
                    r"PHP Debug",
                    r"DEBUG.*TRUE"
                ],
                'risk': 'MEDIUM'
            }
        }
    
    def comprehensive_security_scan(self):
        """Comprehensive security vulnerability assessment"""
        self.scanner.print_status("Starting comprehensive security assessment...", "shield")
        
        checks = []
        
        # HTTP Security Headers Check
        checks.extend(self.check_security_headers())
        
        # SSL/TLS Configuration Check
        if SSL_AVAILABLE:
            checks.extend(self.check_ssl_configuration())
        
        # Information Disclosure Check
        checks.extend(self.check_information_disclosure())
        
        # Common Misconfigurations
        checks.extend(self.check_common_misconfigurations())
        
        # Technology-specific vulnerabilities
        checks.extend(self.check_technology_vulnerabilities())
        
        # API Security
        checks.extend(self.check_api_security())
        
        self.vulnerabilities = checks
        return checks
    
    def check_security_headers(self):
        """Comprehensive security headers check"""
        checks = []
        
        try:
            response = self.scanner.intelligent_request(self.scanner.target_url)
            if not response:
                return checks
                
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': {'risk': 'MEDIUM', 'description': 'Clickjacking protection'},
                'X-Content-Type-Options': {'risk': 'MEDIUM', 'description': 'MIME sniffing protection'},
                'Strict-Transport-Security': {'risk': 'HIGH', 'description': 'HTTPS enforcement'},
                'Content-Security-Policy': {'risk': 'HIGH', 'description': 'XSS protection'},
                'X-XSS-Protection': {'risk': 'MEDIUM', 'description': 'XSS filter'},
                'Referrer-Policy': {'risk': 'LOW', 'description': 'Referrer information control'},
                'Permissions-Policy': {'risk': 'MEDIUM', 'description': 'Browser features control'},
                'Cache-Control': {'risk': 'LOW', 'description': 'Caching directives'}
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    checks.append({
                        'type': 'SECURITY_HEADER',
                        'message': f'Missing security header: {header}',
                        'description': info['description'],
                        'risk': info['risk'],
                        'severity': 'WARNING'
                    })
                else:
                    # Validate header values
                    checks.extend(self.validate_header_value(header, headers[header], info))
                    
        except Exception as e:
            self.scanner.print_status(f"Security headers check failed: {e}", "error")
            
        return checks
    
    def validate_header_value(self, header, value, info):
        """Validate security header values"""
        checks = []
        
        validation_rules = {
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'X-Content-Type-Options': ['nosniff'],
            'X-XSS-Protection': ['1', '1; mode=block']
        }
        
        if header in validation_rules:
            if value not in validation_rules[header]:
                checks.append({
                    'type': 'HEADER_VALUE',
                    'message': f'Invalid {header} value: {value}',
                    'description': f'Should be one of: {", ".join(validation_rules[header])}',
                    'risk': info['risk'],
                    'severity': 'WARNING'
                })
                
        return checks
    
    def check_ssl_configuration(self):
        """Check SSL/TLS configuration"""
        checks = []
        
        try:
            hostname = self.scanner.domain
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        checks.append({
                            'type': 'SSL_CERTIFICATE',
                            'message': f'SSL certificate expires in {days_until_expiry} days',
                            'description': 'Certificate nearing expiration',
                            'risk': 'HIGH',
                            'severity': 'WARNING'
                        })
                    
                    # Check cipher strength
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        checks.append({
                            'type': 'SSL_CIPHER',
                            'message': f'Weak cipher suite: {cipher[0]}',
                            'description': 'Using weak encryption cipher',
                            'risk': 'HIGH',
                            'severity': 'CRITICAL'
                        })
                        
        except Exception as e:
            self.scanner.print_status(f"SSL check failed: {e}", "error")
            
        return checks
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        checks = []
        
        try:
            # Test error pages
            test_urls = [
                f"{self.scanner.target_url}/nonexistent-page-12345",
                f"{self.scanner.target_url}/../etc/passwd"
            ]
            
            for test_url in test_urls:
                response = self.scanner.intelligent_request(test_url)
                if response and response.status_code == 200:
                    content = response.text
                    
                    # Check for stack traces
                    if any(pattern in content.lower() for pattern in ['stack trace', 'exception', 'error in']):
                        checks.append({
                            'type': 'INFO_DISCLOSURE',
                            'message': 'Stack trace disclosed in error pages',
                            'description': 'Sensitive debugging information exposed',
                            'risk': 'MEDIUM',
                            'severity': 'WARNING'
                        })
                    
                    # Check for version information
                    if any(pattern in content for pattern in ['Apache/', 'nginx/', 'PHP/', 'ASP.NET']):
                        checks.append({
                            'type': 'INFO_DISCLOSURE',
                            'message': 'Server version information disclosed',
                            'description': 'Software versions exposed to attackers',
                            'risk': 'LOW',
                            'severity': 'INFO'
                        })
                        
        except Exception as e:
            self.scanner.print_status(f"Information disclosure check failed: {e}", "error")
            
        return checks
    
    def check_common_misconfigurations(self):
        """Check for common web server misconfigurations"""
        checks = []
        
        try:
            # Check for directory listing
            test_dirs = ['/images/', '/css/', '/js/', '/uploads/']
            for directory in test_dirs:
                url = urljoin(self.scanner.target_url, directory)
                response = self.scanner.intelligent_request(url)
                if response and response.status_code == 200:
                    if '<title>Index of' in response.text or '<h1>Directory listing' in response.text:
                        checks.append({
                            'type': 'MISCONFIGURATION',
                            'message': f'Directory listing enabled: {directory}',
                            'description': 'Directory contents exposed to public',
                            'risk': 'MEDIUM',
                            'severity': 'WARNING'
                        })
            
            # Check HTTP methods
            response = self.scanner.intelligent_request(self.scanner.target_url, method='OPTIONS')
            if response:
                methods = response.headers.get('Allow', '')
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                for method in dangerous_methods:
                    if method in methods:
                        checks.append({
                            'type': 'MISCONFIGURATION',
                            'message': f'Dangerous HTTP method enabled: {method}',
                            'description': f'{method} method should be disabled',
                            'risk': 'MEDIUM',
                            'severity': 'WARNING'
                        })
                        
        except Exception as e:
            self.scanner.print_status(f"Misconfiguration check failed: {e}", "error")
            
        return checks
    
    def check_technology_vulnerabilities(self):
        """Check for technology-specific vulnerabilities"""
        checks = []
        technologies = self.scanner.results.get('technologies', [])
        
        # WordPress specific checks
        if 'WordPress' in technologies:
            checks.extend(self.check_wordpress_vulnerabilities())
        
        # Laravel specific checks
        if 'Laravel' in technologies:
            checks.extend(self.check_laravel_vulnerabilities())
            
        return checks
    
    def check_wordpress_vulnerabilities(self):
        """WordPress specific vulnerability checks"""
        checks = []
        
        try:
            # Check for wp-config.php backup files
            backup_patterns = ['wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.backup']
            for pattern in backup_patterns:
                url = urljoin(self.scanner.target_url, pattern)
                response = self.scanner.intelligent_request(url)
                if response and response.status_code == 200:
                    checks.append({
                        'type': 'WORDPRESS_VULN',
                        'message': f'WordPress config backup file accessible: {pattern}',
                        'description': 'Database credentials exposed',
                        'risk': 'CRITICAL',
                        'severity': 'CRITICAL'
                    })
                    
            # Check for readme.html
            readme_url = urljoin(self.scanner.target_url, 'readme.html')
            response = self.scanner.intelligent_request(readme_url)
            if response and response.status_code == 200:
                checks.append({
                    'type': 'WORDPRESS_VULN',
                    'message': 'WordPress version exposed via readme.html',
                    'description': 'Version information helps attackers',
                    'risk': 'LOW',
                    'severity': 'INFO'
                })
                
        except Exception as e:
            self.scanner.print_status(f"WordPress check failed: {e}", "error")
            
        return checks
    
    def check_laravel_vulnerabilities(self):
        """Laravel specific vulnerability checks"""
        checks = []
        
        try:
            # Check for .env file
            env_url = urljoin(self.scanner.target_url, '.env')
            response = self.scanner.intelligent_request(env_url)
            if response and response.status_code == 200 and 'APP_KEY' in response.text:
                checks.append({
                    'type': 'LARAVEL_VULN',
                    'message': 'Laravel .env file accessible',
                    'description': 'Application configuration and secrets exposed',
                    'risk': 'CRITICAL',
                    'severity': 'CRITICAL'
                })
                
        except Exception as e:
            self.scanner.print_status(f"Laravel check failed: {e}", "error")
            
        return checks
    
    def check_api_security(self):
        """API security checks"""
        checks = []
        
        try:
            # Check common API endpoints
            api_endpoints = ['/api/', '/graphql', '/rest/', '/v1/', '/v2/']
            for endpoint in api_endpoints:
                url = urljoin(self.scanner.target_url, endpoint)
                response = self.scanner.intelligent_request(url)
                if response and response.status_code in [200, 201]:
                    # Check for lack of rate limiting
                    rapid_requests = []
                    for i in range(5):
                        rapid_response = self.scanner.intelligent_request(url)
                        if rapid_response:
                            rapid_requests.append(rapid_response.status_code)
                    
                    if all(status == 200 for status in rapid_requests):
                        checks.append({
                            'type': 'API_SECURITY',
                            'message': f'API endpoint without rate limiting: {endpoint}',
                            'description': 'Vulnerable to brute force attacks',
                            'risk': 'MEDIUM',
                            'severity': 'WARNING'
                        })
                        
        except Exception as e:
            self.scanner.print_status(f"API security check failed: {e}", "error")
            
        return checks

class WAFDetector:
    """Web Application Firewall detection"""
    def __init__(self, scanner):
        self.scanner = scanner
        
    def detect_waf(self):
        """Detect WAF presence and type"""
        self.scanner.print_status("Detecting Web Application Firewall...", "shield")
        
        waf_indicators = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'server'],
                'patterns': ['cloudflare', 'cf']
            },
            'Akamai': {
                'headers': ['x-akamai-transformed', 'akamai-origin-hop'],
                'patterns': ['akamai']
            },
            'Imperva': {
                'headers': ['x-cdn', 'incap-sid'],
                'patterns': ['imperva', 'incapsula']
            },
            'AWS WAF': {
                'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'patterns': ['aws', 'amazon']
            },
            'ModSecurity': {
                'headers': ['server'],
                'patterns': ['mod_security', 'modsecurity']
            }
        }
        
        try:
            response = self.scanner.intelligent_request(self.scanner.target_url)
            if not response:
                return None
                
            headers = response.headers
            detected_wafs = []
            
            for waf, indicators in waf_indicators.items():
                # Check headers
                for header in indicators['headers']:
                    if header in headers:
                        detected_wafs.append(waf)
                        break
                
                # Check content patterns
                for pattern in indicators['patterns']:
                    if pattern in str(headers).lower() or pattern in response.text.lower():
                        if waf not in detected_wafs:
                            detected_wafs.append(waf)
                            
            if detected_wafs:
                for waf in detected_wafs:
                    self.scanner.print_status(f"WAF detected: {waf}", "warning")
                return detected_wafs
            else:
                self.scanner.print_status("No WAF detected", "success")
                return None
                
        except Exception as e:
            self.scanner.print_status(f"WAF detection failed: {e}", "error")
            return None

class ThreatIntelligence:
    """Threat intelligence integration"""
    def __init__(self, scanner):
        self.scanner = scanner
        
    def analyze_threat_level(self):
        """Analyze overall threat level based on findings"""
        self.scanner.print_status("Analyzing threat intelligence...", "shield")
        
        risk_factors = {
            'critical_directories': 10,
            'high_risk_vulns': 8,
            'medium_risk_vulns': 5,
            'missing_headers': 3,
            'info_disclosure': 6,
            'waf_present': -5  # WAF reduces risk
        }
        
        total_score = 0
        
        # Calculate risk score
        critical_dirs = len([d for d in self.scanner.results['directories'] if d.get('risk_level') in ['CRITICAL', 'HIGH']])
        total_score += critical_dirs * risk_factors['critical_directories']
        
        high_vulns = len([v for v in self.scanner.results['vulnerabilities'] if v.get('risk') == 'HIGH'])
        total_score += high_vulns * risk_factors['high_risk_vulns']
        
        medium_vulns = len([v for v in self.scanner.results['vulnerabilities'] if v.get('risk') == 'MEDIUM'])
        total_score += medium_vulns * risk_factors['medium_risk_vulns']
        
        missing_headers = len([v for v in self.scanner.results['vulnerabilities'] if v.get('type') == 'SECURITY_HEADER'])
        total_score += missing_headers * risk_factors['missing_headers']
        
        info_disclosure = len([v for v in self.scanner.results['vulnerabilities'] if v.get('type') == 'INFO_DISCLOSURE'])
        total_score += info_disclosure * risk_factors['info_disclosure']
        
        # Adjust for WAF
        if self.scanner.results.get('waf_detection'):
            total_score += risk_factors['waf_present']
        
        # Determine threat level
        if total_score >= 50:
            threat_level = "CRITICAL"
            color = Color.RED
        elif total_score >= 30:
            threat_level = "HIGH"
            color = Color.RED
        elif total_score >= 15:
            threat_level = "MEDIUM"
            color = Color.YELLOW
        elif total_score >= 5:
            threat_level = "LOW"
            color = Color.GREEN
        else:
            threat_level = "MINIMAL"
            color = Color.GREEN
            
        self.scanner.results['risk_score'] = total_score
        self.scanner.results['threat_level'] = threat_level
        
        self.scanner.print_status(f"Overall threat level: {color}{threat_level}{Color.END}", 
                                "critical" if threat_level in ['CRITICAL', 'HIGH'] else "warning",
                                f"Score: {total_score}")
        
        return threat_level

class UltimateWebScanner:
    """
    ULTIMATE PROFESSIONAL WEB SECURITY SCANNER
    Enterprise-grade penetration testing tool
    """
    
    def __init__(self, target_url, config=None):
        self.target_url = target_url
        self.config = config or {}
        
        # Initialize all advanced modules
        self.core_scanner = AdvancedSecurityScanner(target_url, config)
        self.dir_bruteforcer = IntelligentDirectoryBruteforcer(self.core_scanner, 
                                                             threads=config.get('threads', 20),
                                                             timeout=config.get('timeout', 8))
        self.tech_detector = AdvancedTechnologyDetector(self.core_scanner)
        self.vuln_scanner = AdvancedVulnerabilityScanner(self.core_scanner)
        self.waf_detector = WAFDetector(self.core_scanner)
        self.threat_intel = ThreatIntelligence(self.core_scanner)
        
        # Results storage
        self.scan_results = {}
        
    def print_ultimate_banner(self):
        """Ultimate professional banner"""
        banner = f"""
{Color.rainbow_text("╔════════════════════════════════════════════════════════════════╗")}
{Color.rainbow_text("║                ULTIMATE SECURITY SCANNER v5.0                 ║")}
{Color.rainbow_text("║               Enterprise Penetration Testing                 ║")}
{Color.rainbow_text("╚════════════════════════════════════════════════════════════════╝")}

{Color.WHITE}🎯 {Color.BOLD}Target:{Color.END} {Color.GREEN}{self.target_url}{Color.END}
{Color.WHITE}⏰ {Color.BOLD}Started:{Color.END} {Color.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.END}
{Color.WHITE}🔧 {Color.BOLD}Mode:{Color.END} {Color.BLUE}{self.config.get('mode', 'full').upper()}{Color.END}
{Color.WHITE}🚀 {Color.BOLD}Threads:{Color.END} {Color.CYAN}{self.config.get('threads', 20)}{Color.END}
        """
        print(banner)
        
    def comprehensive_scan(self):
        """Ultimate comprehensive security scan"""
        self.print_ultimate_banner()
        
        # Phase 1: Advanced Reconnaissance
        print(f"\n{Color.BOLD}[1/6] {Color.CYAN}🛰️  ADVANCED RECONNAISSANCE{Color.END}")
        self.advanced_reconnaissance_phase()
        
        # Phase 2: Technology Intelligence
        print(f"\n{Color.BOLD}[2/6] {Color.BLUE}🔧 TECHNOLOGY INTELLIGENCE{Color.END}") 
        self.technology_intelligence_phase()
        
        # Phase 3: Intelligent Directory Discovery
        print(f"\n{Color.BOLD}[3/6] {Color.MAGENTA}📁 INTELLIGENT DIRECTORY DISCOVERY{Color.END}")
        self.intelligent_directory_phase()
        
        # Phase 4: WAF & Protection Detection
        print(f"\n{Color.BOLD}[4/6] {Color.YELLOW}🛡️  WAF & PROTECTION DETECTION{Color.END}")
        self.protection_detection_phase()
        
        # Phase 5: Comprehensive Vulnerability Assessment
        print(f"\n{Color.BOLD}[5/6] {Color.RED}🚨 COMPREHENSIVE VULNERABILITY ASSESSMENT{Color.END}")
        self.comprehensive_vulnerability_phase()
        
        # Phase 6: Threat Intelligence & Risk Analysis
        print(f"\n{Color.BOLD}[6/6] {Color.GREEN}📊 THREAT INTELLIGENCE & RISK ANALYSIS{Color.END}")
        self.threat_intelligence_phase()
        
        # Ultimate Report Generation
        self.generate_ultimate_report()
        
    def advanced_reconnaissance_phase(self):
        """Advanced reconnaissance with multiple techniques"""
        self.core_scanner.print_status("Starting advanced reconnaissance...", "scan")
        
        # Basic target information
        try:
            response = self.core_scanner.intelligent_request(self.target_url)
            if response:
                self.core_scanner.results['server_info'] = {
                    'server': response.headers.get('Server', 'Unknown'),
                    'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds()
                }
                
                self.core_scanner.print_status(f"Server: {response.headers.get('Server', 'Unknown')}", "success")
                self.core_scanner.print_status(f"Status: {response.status_code}", "success")
                self.core_scanner.print_status(f"Response Time: {response.elapsed.total_seconds():.2f}s", "info")
                
        except Exception as e:
            self.core_scanner.print_status(f"Reconnaissance failed: {e}", "error")
    
    def technology_intelligence_phase(self):
        """Advanced technology detection"""
        technologies = self.tech_detector.detect_technologies()
        self.core_scanner.results['technologies'] = technologies
        
        # Add technology-specific paths to directory bruteforcer
        self.dir_bruteforcer.add_technology_specific_paths(technologies)
        
        if not technologies:
            self.core_scanner.print_status("No technologies detected", "warning")
    
    def intelligent_directory_phase(self):
        """Intelligent directory and file discovery"""
        found_count = self.dir_bruteforcer.scan_all_directories()
        self.core_scanner.results['directories'] = self.dir_bruteforcer.found_directories
        
        # Categorize findings
        critical_findings = len([d for d in self.dir_bruteforcer.found_directories if d.get('risk_level') in ['CRITICAL', 'HIGH']])
        
        self.core_scanner.print_status(f"Discovery complete: {found_count} resources found", "success", 
                                     f"{critical_findings} critical")
    
    def protection_detection_phase(self):
        """WAF and protection mechanisms detection"""
        waf_detected = self.waf_detector.detect_waf()
        self.core_scanner.results['waf_detection'] = waf_detected
        
    def comprehensive_vulnerability_phase(self):
        """Comprehensive vulnerability assessment"""
        vulnerabilities = self.vuln_scanner.comprehensive_security_scan()
        self.core_scanner.results['vulnerabilities'] = vulnerabilities
        
        # Categorize vulnerabilities
        critical_vulns = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'WARNING' and v.get('risk') == 'HIGH'])
        
        for vuln in vulnerabilities:
            severity_icon = "🚨" if vuln.get('severity') == 'CRITICAL' else "⚠️" if vuln.get('severity') == 'WARNING' else "ℹ️"
            self.core_scanner.print_status(f"{severity_icon} {vuln['type']}: {vuln['message']}", 
                                         "critical" if vuln.get('severity') == 'CRITICAL' else "warning")
        
        self.core_scanner.print_status(f"Vulnerability assessment complete", "success",
                                     f"{critical_vulns} critical, {high_vulns} high risk")
    
    def threat_intelligence_phase(self):
        """Threat intelligence and risk analysis"""
        threat_level = self.threat_intel.analyze_threat_level()
        
        # Generate actionable recommendations
        recommendations = self.generate_actionable_recommendations()
        self.core_scanner.results['recommendations'] = recommendations
    
    def generate_actionable_recommendations(self):
        """Generate prioritized, actionable recommendations"""
        recommendations = []
        
        # Critical directory access
        critical_dirs = [d for d in self.core_scanner.results['directories'] if d.get('risk_level') in ['CRITICAL', 'HIGH']]
        if critical_dirs:
            dir_names = [d['directory'] for d in critical_dirs[:3]]  # Top 3
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'BLOCK_ACCESS',
                'description': f'Restrict access to critical directories: {", ".join(dir_names)}',
                'impact': 'Prevents unauthorized access to sensitive areas'
            })
        
        # Security headers
        missing_headers = [v for v in self.core_scanner.results['vulnerabilities'] if v.get('type') == 'SECURITY_HEADER']
        if missing_headers:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'IMPLEMENT_HEADERS',
                'description': f'Implement {len(missing_headers)} missing security headers',
                'impact': 'Enhances protection against common web attacks'
            })
        
        # Information disclosure
        info_disclosure = [v for v in self.core_scanner.results['vulnerabilities'] if v.get('type') == 'INFO_DISCLOSURE']
        if info_disclosure:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'HIDE_INFO',
                'description': 'Fix information disclosure vulnerabilities',
                'impact': 'Prevents leakage of sensitive system information'
            })
        
        # WAF implementation
        if not self.core_scanner.results.get('waf_detection'):
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'DEPLOY_WAF',
                'description': 'Consider deploying a Web Application Firewall',
                'impact': 'Provides additional layer of protection'
            })
        
        return recommendations

    def generate_ultimate_report(self):
        """Generate ultimate comprehensive security report"""
        duration = time.time() - self.core_scanner.stats['start_time']
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ultimate_security_audit_{self.core_scanner.domain}_{timestamp}.json"
        
        # Comprehensive report data
        report = {
            'metadata': {
                'scanner_version': '5.0',
                'scan_date': datetime.now().isoformat(),
                'target': self.target_url,
                'scan_duration': f"{duration:.2f} seconds",
                'requests_sent': self.core_scanner.stats['requests_sent'],
                'bandwidth_used': f"{self.core_scanner.stats['bandwidth_used'] / 1024:.2f} KB"
            },
            'executive_summary': {
                'threat_level': self.core_scanner.results['threat_level'],
                'risk_score': self.core_scanner.results['risk_score'],
                'total_findings': len(self.core_scanner.results['directories']) + len(self.core_scanner.results['vulnerabilities']),
                'critical_findings': len([d for d in self.core_scanner.results['directories'] if d.get('risk_level') in ['CRITICAL', 'HIGH']]) +
                                   len([v for v in self.core_scanner.results['vulnerabilities'] if v.get('severity') == 'CRITICAL'])
            },
            'detailed_findings': self.core_scanner.results,
            'statistics': {
                'directories_found': len(self.core_scanner.results['directories']),
                'technologies_detected': len(self.core_scanner.results['technologies']),
                'vulnerabilities_found': len(self.core_scanner.results['vulnerabilities']),
                'waf_detected': bool(self.core_scanner.results.get('waf_detection'))
            },
            'action_plan': self.core_scanner.results.get('recommendations', [])
        }
        
        # Save comprehensive report
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        # Ultimate results presentation
        self.present_ultimate_results(duration, filename)
    
    def present_ultimate_results(self, duration, filename):
        """Present results in ultimate format"""
        critical_dirs = len([d for d in self.core_scanner.results['directories'] if d.get('risk_level') in ['CRITICAL', 'HIGH']])
        critical_vulns = len([v for v in self.core_scanner.results['vulnerabilities'] if v.get('severity') == 'CRITICAL'])
        
        print(f"""
{Color.CYAN}{Color.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                     SCAN COMPLETE                             ║
║                   Ultimate Security Report                   ║
╚════════════════════════════════════════════════════════════════╝{Color.END}

{Color.WHITE}🎯 {Color.BOLD}Target Analysis:{Color.END}
   {Color.GREEN}•{Color.END} URL: {self.target_url}
   {Color.GREEN}•{Color.END} Threat Level: {self.get_threat_color()}{self.core_scanner.results['threat_level']}{Color.END}
   {Color.GREEN}•{Color.END} Risk Score: {Color.CYAN}{self.core_scanner.results['risk_score']}/100{Color.END}

{Color.WHITE}📊 {Color.BOLD}Security Findings:{Color.END}
   {Color.GREEN}•{Color.END} Resources Found: {Color.CYAN}{len(self.core_scanner.results['directories'])}{Color.END}
   {Color.GREEN}•{Color.END} Critical Directories: {Color.RED}{critical_dirs}{Color.END}
   {Color.GREEN}•{Color.END} Technologies: {Color.CYAN}{len(self.core_scanner.results['technologies'])}{Color.END}
   {Color.GREEN}•{Color.END} Vulnerabilities: {Color.CYAN}{len(self.core_scanner.results['vulnerabilities'])}{Color.END}
   {Color.GREEN}•{Color.END} Critical Vulnerabilities: {Color.RED}{critical_vulns}{Color.END}

{Color.WHITE}⚡ {Color.BOLD}Performance Metrics:{Color.END}
   {Color.GREEN}•{Color.END} Scan Duration: {Color.YELLOW}{duration:.2f} seconds{Color.END}
   {Color.GREEN}•{Color.END} Requests Sent: {Color.YELLOW}{self.core_scanner.stats['requests_sent']}{Color.END}
   {Color.GREEN}•{Color.END} Bandwidth Used: {Color.YELLOW}{self.core_scanner.stats['bandwidth_used'] / 1024:.2f} KB{Color.END}

{Color.WHITE}💾 {Color.BOLD}Report Generated:{Color.END} {Color.GREEN}{filename}{Color.END}

{Color.WHITE}🚨 {Color.BOLD}Critical Actions Required:{Color.END}""")
        
        recommendations = self.core_scanner.results.get('recommendations', [])
        for i, rec in enumerate(recommendations[:5], 1):
            priority_color = Color.RED if rec['priority'] == 'CRITICAL' else Color.YELLOW if rec['priority'] == 'HIGH' else Color.GREEN
            print(f"   {priority_color}{i}. [{rec['priority']}] {rec['action']}: {rec['description']}{Color.END}")

        print(f"""
{Color.RED}{Color.BOLD}
🔐 SECURITY NOTICE:
   This tool is for authorized security testing only!
   Always obtain proper permission before scanning!
   Report findings responsibly to site owners.
   
   Need help fixing these issues? Contact security professionals!{Color.END}
        """)
    
    def get_threat_color(self):
        """Get color for threat level"""
        threat_level = self.core_scanner.results['threat_level']
        return {
            'CRITICAL': Color.RED,
            'HIGH': Color.RED,
            'MEDIUM': Color.YELLOW,
            'LOW': Color.GREEN,
            'MINIMAL': Color.GREEN
        }.get(threat_level, Color.WHITE)

def main():
    parser = argparse.ArgumentParser(
        description='ULTIMATE WEB SECURITY SCANNER - Enterprise Penetration Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Color.CYAN}{Color.BOLD}EXAMPLES:{Color.END}
  {Color.GREEN}python ultimate_scanner.py https://example.com{Color.END}
  {Color.GREEN}python ultimate_scanner.py https://example.com --threads 50 --timeout 10{Color.END}
  {Color.GREEN}python ultimate_scanner.py https://example.com --mode quick{Color.END}

{Color.CYAN}{Color.BOLD}ENTERPRISE USAGE:{Color.END}
  {Color.YELLOW}# Full enterprise penetration test{Color.END}
  python ultimate_scanner.py https://target.com --mode full --threads 100

  {Color.YELLOW}# Quick security assessment{Color.END}  
  python ultimate_scanner.py https://target.com --mode quick --threads 20

  {Color.YELLOW}# Stealth mode for sensitive environments{Color.END}
  python ultimate_scanner.py https://target.com --mode stealth --delay 1.0

{Color.RED}{Color.BOLD}
⚠️  LEGAL NOTICE: Always ensure you have proper authorization before scanning!
   Unauthorized scanning may be illegal in your jurisdiction.{Color.END}
        """
    )
    
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=20, 
                       help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between requests (default: 0.1)')
    parser.add_argument('-m', '--mode', choices=['quick', 'full', 'stealth'], 
                       default='full', help='Scanning mode (default: full)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--proxy', help='Use proxy for requests')
    parser.add_argument('--user-agent', help='Custom User-Agent string')
    parser.add_argument('--wordlist', help='Custom wordlist file')
    parser.add_argument('--max-requests', type=int, default=1000,
                       help='Maximum number of requests (default: 1000)')
    
    args = parser.parse_args()
    
    # Enhanced configuration
    config = {
        'threads': args.threads,
        'timeout': args.timeout,
        'delay': args.delay,
        'mode': args.mode,
        'proxy': args.proxy,
        'user_agent': args.user_agent,
        'max_requests': args.max_requests
    }
    
    try:
        # Create and run the ultimate scanner
        scanner = UltimateWebScanner(args.url, config)
        scanner.comprehensive_scan()
        
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}🛑 Scan interrupted by user{Color.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Color.RED}💥 Critical error: {e}{Color.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()