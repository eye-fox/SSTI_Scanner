#!/usr/bin/env python3
import requests
import re
from urllib.parse import urlparse, parse_qs, urljoin, urlencode
from bs4 import BeautifulSoup
import sys
import time
import random
import hashlib
import json
import statistics
import argparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import RequestException, Timeout
from data_ssti import *
import asyncio
import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from datetime import datetime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
class colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'
LOGOUT_PATTERNS = ['login','logout', 'signout', 'endsession', 'keluar', 'logoff', 'signoff', 'exit', 'destroy_session', 'logout.php', 'signout.aspx', 'logout.action', 'signout.do', 'logout.jsp', 'signout.php', 'logout.aspx', 'signout.jsp', 'logout.do', 'signout.action', 'member/logout', 'user/logout', 'account/logout', 'admin/logout', 'session/logout', 'auth/logout', 'login/logout', 'keluar.php', 'keluar.aspx', 'keluar.jsp', 'keluar.do', 'keluar.action', 'log-me-out', 'sign-me-out', 'endsession.php', 'endsession.aspx', 'endsession.jsp', 'endsession.do', 'endsession.action']
def random_headers(cookie=None, referer=None):
    headers = {
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'id-ID,id;q=0.9', 'en;q=0.8']),
        'Referer': referer or random.choice(['https://www.google.com/', 'https://www.bing.com/', 'https://www.facebook.com/', 'https://www.twitter.com/']),
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Ch-Ua': random.choice(SEC_CH_UA),
        'Sec-Ch-Ua-Mobile': random.choice(['?0', '?1']),
        'Sec-Ch-Ua-Platform': random.choice(SEC_CH_UA_PLATFORM),
        'Sec-Fetch-Site': random.choice(['none', 'cross-site', 'same-site', 'same-origin']),
        'Sec-Fetch-Mode': random.choice(['navigate', 'cors', 'no-cors']),
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': random.choice(['document', 'empty']),
        'Accept-Encoding': random.choice(['gzip, deflate, br', 'gzip, deflate', 'br']),
        'Cache-Control': random.choice(['max-age=0', 'no-cache']),
    }
    if cookie:
        headers['Cookie'] = cookie
    return headers
def generate_probe_string(index):
    return f"SSTI_PROBE_{index}_{random.randint(10000, 99999)}_{hashlib.md5(str(random.random()).encode()).hexdigest()[:8]}"
def truncate(text, length=50):
    return text[:length] + '...' if len(text) > length else text
def is_logout_url(url):
    if not url:
        return False
    url_lower = url.lower()
    for pattern in LOGOUT_PATTERNS:
        if pattern in url_lower:
            return True
    return False
class SSTIScanner:
    def __init__(self, url, cookie=None):
        self.url = url
        self.base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        self.cookie = cookie
        self.session = self.create_session_with_retries()
        self.params_get = {}
        self.params_post = {}
        self.params_button = {}
        self.post_url = None
        self.get_url = None
        self.reflection_point = None
        self.probe_strings = [generate_probe_string(i) for i in range(3)]
        self.csrf_params = []
        self.baseline_status = None
        self.baseline_length = None
        self.probe_data = {}
        self.payload_results = []
        self.vulnerable_payloads = []
        self.suspicious_payloads = []
        self.mapping_errors = []
        self.parser_mode = 'unknown'
        self.non_suspicious_keywords = non_suspicious_keywords
        self.engine_signatures = engine_signatures
        self.finding_text = None
        self.original_cookies = self.parse_cookie(cookie) if cookie else {}
        self.session_cookies = {}
    def parse_cookie(self, cookie_str):
        cookies = {}
        for item in cookie_str.split(';'):
            item = item.strip()
            if '=' in item:
                name, value = item.split('=', 1)
                cookies[name.strip()] = value.strip()
        return cookies
    def create_session_with_retries(self):
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429], allowed_methods=["GET", "POST"])
        adapter = HTTPAdapter(max_retries=retries)
        session.mount('http://', adapter)
        cipher_suite = random.choice(CIPHER_SUITES)
        session.mount('https://', adapter)
        if self.cookie:
            session.headers.update({'Cookie': self.cookie})
        session.verify = False
        return session
    def make_request_with_retry(self, method, url, max_retries=3, **kwargs):
        headers = kwargs.pop('headers', random_headers(self.cookie))
        timeout = kwargs.pop('timeout', 10)
        data = kwargs.get('data', {})
        preserve_session = kwargs.pop('preserve_session', True)
        for attempt in range(max_retries):
            try:
                if method.upper() == 'GET':
                    resp = self.session.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
                else:
                    resp = self.session.post(url, headers=headers, data=data, timeout=timeout, allow_redirects=True, verify=False)
                if preserve_session and resp.cookies:
                    self.session.cookies.update(resp.cookies)
                if resp.status_code in [301, 302, 303, 307, 308] and resp.headers.get('Location'):
                    redirect = resp.headers['Location']
                    if not redirect.startswith('http'):
                        redirect = urljoin(url, redirect)
                    if method.upper() == 'GET':
                        resp = self.session.get(redirect, headers=random_headers(self.cookie), timeout=timeout, allow_redirects=True, verify=False)
                    else:
                        resp = self.session.get(redirect, headers=random_headers(self.cookie), timeout=timeout, allow_redirects=True, verify=False)
                return {
                    'success': True,
                    'status_code': resp.status_code,
                    'text': resp.text,
                    'length': len(resp.text),
                    'error': None
                }
            except requests.exceptions.Timeout:
                if attempt == max_retries - 1:
                    return {'success': False, 'error': 'timeout', 'status_code': None, 'text': '', 'length': None}
                time.sleep(random.uniform(1, 2))
            except requests.exceptions.ConnectionError:
                if attempt == max_retries - 1:
                    return {'success': False, 'error': 'connection_error', 'status_code': None, 'text': '', 'length': None}
                time.sleep(random.uniform(1, 2))
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    return {'success': False, 'error': str(e), 'status_code': None, 'text': '', 'length': None}
                time.sleep(random.uniform(1, 2))
        return {'success': False, 'error': 'unknown_error', 'status_code': None, 'text': '', 'length': None}
    def extract_csrf_token(self, url, form_data):
        try:
            resp = self.session.get(url, headers=random_headers(self.cookie), timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                full_action = urljoin(url, action) if action else url
                if full_action == self.post_url:
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for inp in inputs:
                        name = inp.get('name')
                        if name and name in self.csrf_params:
                            value = inp.get('value', '')
                            if value:
                                form_data[name] = value
                            break
        except:
            pass
        return form_data
    def extract_params(self):
        parsed = urlparse(self.url)
        if parsed.query:
            self.params_get = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            resp = self.session.get(self.url, headers=random_headers(self.cookie), timeout=10, allow_redirects=True, verify=False)
            if resp.status_code != 200:
                return
            content_type = resp.headers.get('Content-Type', '').lower()
            if 'text/html' in content_type:
                self.parser_mode = 'html'
                soup = BeautifulSoup(resp.text, 'html.parser')
                forms = soup.find_all('form')
                if forms:
                    for i, form in enumerate(forms, 1):
                        action = form.get('action', '')
                        full_action = urljoin(self.url, action) if action else self.url
                        if is_logout_url(full_action):
                            continue
                        method = form.get('method', 'get').lower()
                        inputs = form.find_all(['input', 'textarea', 'select'])
                        form_params = {}
                        for inp in inputs:
                            name = inp.get('name')
                            if name:
                                value = inp.get('value', '')
                                if inp.name == 'textarea':
                                    value = inp.get_text() or value
                                elif inp.name == 'select' and inp.find('option', selected=True):
                                    value = inp.find('option', selected=True).get('value', '')
                                form_params[name] = value
                                if self.is_csrf_param(name):
                                    self.csrf_params.append(name)
                        buttons = form.find_all(['button', 'input'], type='submit')
                        for btn in buttons:
                            name = btn.get('name')
                            if name:
                                self.params_button[name] = btn.get('value', '')
                        if form_params:
                            if method == 'get':
                                self.params_get.update(form_params)
                                self.get_url = full_action
                            else:
                                self.params_post.update(form_params)
                                self.post_url = full_action
            elif 'application/xml' in content_type or 'text/xml' in content_type:
                self.parser_mode = 'xml'
                soup = BeautifulSoup(resp.text, 'xml')
            else:
                self.parser_mode = 'unknown'
        except Exception as e:
            pass
    def is_csrf_param(self, param_name):
        patterns = ['csrf', 'token', 'authenticity_token', '_token', 'csrf_token', 'csrfmiddlewaretoken', '__RequestVerificationToken', 'xsrf', '_csrf']
        return any(p in param_name.lower() for p in patterns)
    def find_position(self, html, string):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for text in soup.find_all(string=True):
                if string in text:
                    element = text.parent
                    tags = []
                    while element and element.name:
                        attrs = []
                        if element.get('id'):
                            attrs.append(f"id='{element.get('id')}'")
                        if element.get('class'):
                            attrs.append(f"class='{' '.join(element.get('class'))}'")
                        tag_str = element.name + (f"[{', '.join(attrs)}]" if attrs else '')
                        tags.append(tag_str)
                        element = element.parent
                    return ' > '.join(reversed(tags))
        except:
            pass
        return 'unknown'
    def detect_context(self, html, probe):
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for text in soup.find_all(string=True):
                if probe in text:
                    parent = text.parent
                    if parent.name == 'script':
                        return 'javascript'
                    elif parent.name == 'style':
                        return 'css'
                    elif parent.name in ['a', 'link', 'img', 'script', 'iframe'] and parent.get('href') or parent.get('src'):
                        return 'url'
                    else:
                        for ancestor in parent.parents:
                            if ancestor.name == 'script':
                                return 'javascript'
                            if ancestor.name == 'style':
                                return 'css'
                        return 'html'
            for tag in soup.find_all(True):
                for attr, value in tag.attrs.items():
                    if isinstance(value, str) and probe in value:
                        if attr in ['href', 'src', 'action']:
                            return 'url'
                        elif attr.startswith('on'):
                            return 'javascript'
                        else:
                            return 'attribute'
            return 'unknown'
        except:
            return 'unknown'
    def get_element_context(self, soup, text_fragment):
        try:
            for element in soup.find_all(string=True):
                if text_fragment in element:
                    parent = element.parent
                    return {
                        'tag': parent.name,
                        'classes': parent.get('class', []),
                        'is_pre_code': parent.name in ['pre', 'code'],
                        'is_content_tag': parent.name in ['p', 'div', 'span', 'li', 'td', 'th', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
                    }
        except:
            pass
        return None
    def in_content_tag(self, soup, text):
        context = self.get_element_context(soup, text)
        return context and context['is_content_tag'] and not context['is_pre_code']
    def detect_stack_trace(self, html):
        html_str = str(html)
        stack_patterns = [
            r'Traceback \(most recent call last\):',
            r'File "[^"]+", line \d+, in \w+',
            r'at [a-zA-Z0-9_.]+\.[a-zA-Z0-9_]+\([^)]+:\d+\)',
            r'Stack trace:',
            r'Stacktrace:',
            r'^\s+at\s+[\w\.]+\([\w\.]+:\d+\)',
            r'--->',
            r'in \w+ \(.*\):'
        ]
        found = []
        for pattern in stack_patterns:
            if re.search(pattern, html_str, re.MULTILINE):
                found.append(pattern)
        return found
    def detect_error_patterns_contextual(self, html, status_code, soup):
        html_lower = html.lower()
        engine_names = ['handlebars', 'jinja2', 'twig', 'smarty', 'blade', 'freemarker', 'velocity', 'thymeleaf', 'django', 'flask', 'tornado', 'mako', 'cheetah', 'chameleon', 'genshi']
        for engine in engine_names:
            if engine in html_lower and status_code == 500:
                in_pre_code = bool(soup.find_all(['pre', 'code'])) if soup else False
                if in_pre_code or 'error' in html_lower or 'exception' in html_lower:
                    return [f"{engine}_detected"]
        in_pre_code = bool(soup.find_all(['pre', 'code'])) if soup else False
        found = []
        for pattern in error_patterns_contextual:
            if pattern in html_lower:
                if status_code == 500 or in_pre_code:
                    found.append(pattern)
        common_words = ['error', 'exception', 'line', 'at']
        for word in common_words:
            if word in html_lower:
                if status_code == 500 and in_pre_code:
                    found.append(f"{word}_in_pre_500")
                elif status_code == 500:
                    context = self.get_element_context(soup, word)
                    if context and not context['is_content_tag']:
                        found.append(f"{word}_in_500")
        return found
    def detect_engine_signatures(self, html):
        html_lower = html.lower()
        detected = {}
        for engine, signatures in self.engine_signatures.items():
            matches = 0
            for sig in signatures:
                if len(sig) < 4:
                    continue
                pattern = r'\b' + re.escape(sig.lower()) + r'\b'
                if re.search(pattern, html_lower):
                    matches += 1
                    if len(sig) > 15:
                        matches += 2
            if matches > 0:
                confidence = (matches * 100) // len(signatures)
                if confidence >= 30:
                    detected[engine] = confidence
        if detected:
            best_engine = max(detected, key=detected.get)
            return [best_engine] if detected[best_engine] >= 40 else []
        return []
    def detect_template_engine(self, html):
        html_lower = html.lower()
        detected = {}
        for engine, patterns in high_priority_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_lower):
                    detected[engine] = detected.get(engine, 0) + 10
                    break
        for engine, signatures in self.engine_signatures.items():
            if engine in detected:
                continue
            for sig in signatures:
                if len(sig) < 4:
                    continue
                pattern = r'\b' + re.escape(sig.lower()) + r'\b'
                if re.search(pattern, html_lower):
                    score = len(sig) // 5
                    if len(sig) > 15:
                        score += 3
                    detected[engine] = detected.get(engine, 0) + score
                    break
        sorted_engines = sorted(detected.items(), key=lambda x: x[1], reverse=True)
        result = []
        for engine, score in sorted_engines:
            if score >= 8:
                result.append(engine)
            if len(result) >= 2:
                break
        return result
    def is_suspicious_error(self, html):
        html_lower = html.lower()
        for pattern in all_error_patterns:
            if pattern.lower() in html_lower:
                return True
        return False
    def analyze_response(self, html, status_code):
        html_lower = html.lower() if html else ""
        soup = BeautifulSoup(html, 'html.parser') if html else None
        detected_engines = self.detect_template_engine(html)
        if detected_engines:
            return {
                'verdict': 'CRITICAL',
                'reason': f"Engine detected: {', '.join(detected_engines)}",
                'engines': detected_engines,
                'has_engine': True,
                'has_error': True,
                'has_non_suspicious': any(k in html_lower for k in self.non_suspicious_keywords)
            }
        engine_signatures = self.detect_engine_signatures(html)
        if engine_signatures:
            return {
                'verdict': 'CRITICAL',
                'reason': f"Engine detected: {', '.join(engine_signatures)}",
                'engines': engine_signatures,
                'has_engine': True,
                'has_error': True,
                'has_non_suspicious': any(k in html_lower for k in self.non_suspicious_keywords)
            }
        stack_trace = self.detect_stack_trace(html)
        if stack_trace and len(stack_trace) >= 2 and (status_code == 500 or (soup and soup.find_all(['pre', 'code']))):
            return {
                'verdict': 'HIGH',
                'reason': f"Stack trace detected: {len(stack_trace)} patterns",
                'traces': stack_trace,
                'has_engine': False,
                'has_error': True,
                'has_non_suspicious': any(k in html_lower for k in self.non_suspicious_keywords)
            }
        error_patterns = self.detect_error_patterns_contextual(html, status_code, soup)
        if error_patterns:
            if status_code == 500 and soup and soup.find_all(['pre', 'code']):
                return {
                    'verdict': 'MEDIUM',
                    'reason': f"Error patterns in 500/pre: {', '.join(error_patterns[:2])}",
                    'errors': error_patterns,
                    'has_engine': False,
                    'has_error': True,
                    'has_non_suspicious': any(k in html_lower for k in self.non_suspicious_keywords)
                }
            else:
                self.suspicious_payloads.append({'type': 'error_hint', 'patterns': error_patterns})
        errors = self.detect_error_messages(html)
        if errors:
            return {
                'verdict': 'LOW',
                'reason': f"Error messages: {', '.join(errors[:2])}",
                'errors': errors,
                'has_engine': False,
                'has_error': True,
                'has_non_suspicious': any(k in html_lower for k in self.non_suspicious_keywords)
            }
        has_non_suspicious = any(k in html_lower for k in self.non_suspicious_keywords)
        if has_non_suspicious and status_code >= 400:
            return {
                'verdict': 'SAFE',
                'reason': 'Non-suspicious error message',
                'has_engine': False,
                'has_error': False,
                'has_non_suspicious': True
            }
        return {
            'verdict': 'UNKNOWN',
            'reason': 'No clear indicators',
            'has_engine': False,
            'has_error': False,
            'has_non_suspicious': False
        }
    def detect_error_messages(self, html):
        html_lower = html.lower()
        found = []
        all_patterns = (python_error_patterns + php_error_patterns + java_error_patterns + 
                        js_error_patterns + ruby_error_patterns + go_error_patterns + 
                        dotnet_error_patterns + cpp_error_patterns + perl_error_patterns + 
                        common_error_patterns)
        for pattern in all_patterns:
            if pattern.lower() in html_lower:
                found.append(pattern)
                if len(found) >= 10:
                    break
        return found
    def check_baseline(self):
        if self.params_get:
            test_params = self.params_get.copy()
            if self.get_url:
                full_url = f"{self.get_url}?{urlencode(test_params)}"
            else:
                full_url = f"{self.url.split('?')[0]}?{urlencode(test_params)}"
            result = self.make_request_with_retry('GET', full_url)
            if result['success']:
                self.baseline_status = result['status_code']
                self.baseline_length = result['length']
                return True
            else:
                return False
        elif self.params_post and self.post_url:
            data = self.params_post.copy()
            if self.params_button:
                btn = list(self.params_button.keys())[0]
                data[btn] = self.params_button[btn]
            result = self.make_request_with_retry('POST', self.post_url, data=data)
            if result['success']:
                self.baseline_status = result['status_code']
                self.baseline_length = result['length']
                return True
            else:
                return False
        return False
    def track_reflection(self):
        positions = []
        self.mapping_errors = []
        mapping_success = False
        all_errors_no_200 = True
        if self.params_get:
            for probe in self.probe_strings:
                for param in self.params_get:
                    test_params = self.params_get.copy()
                    test_params[param] = probe
                    if self.get_url:
                        full_url = f"{self.get_url}?{urlencode(test_params)}"
                    else:
                        full_url = f"{self.url.split('?')[0]}?{urlencode(test_params)}"
                    result = self.make_request_with_retry('GET', full_url)
                    if result['success']:
                        if result['status_code'] == 200:
                            all_errors_no_200 = False
                            param_key = f"GET_{param}"
                            if param_key not in self.probe_data:
                                self.probe_data[param_key] = {
                                    'lengths': [self.baseline_length],
                                    'positions': [],
                                    'contexts': [],
                                    'probe_count': 0,
                                    'probe_success_count': 0
                                }
                            self.probe_data[param_key]['lengths'].append(result['length'])
                            self.probe_data[param_key]['probe_count'] += 1
                            if probe in result['text']:
                                self.probe_data[param_key]['probe_success_count'] += 1
                                pos = self.find_position(result['text'], probe)
                                context = self.detect_context(result['text'], probe)
                                self.probe_data[param_key]['positions'].append(pos)
                                self.probe_data[param_key]['contexts'].append(context)
                                positions.append({'method': 'GET', 'param': param, 'string': probe, 'position': pos, 'context': context})
                                mapping_success = True
                        else:
                            analysis = self.analyze_response(result['text'], result['status_code'])
                            if analysis['verdict'] == 'CRITICAL':
                                self.mapping_errors.append({
                                    'method': 'GET', 
                                    'param': param, 
                                    'status': result['status_code'], 
                                    'text': result['text'],
                                    'engines': analysis['engines'],
                                    'severity': 'CRITICAL'
                                })
                            elif analysis['verdict'] == 'HIGH':
                                self.mapping_errors.append({
                                    'method': 'GET', 
                                    'param': param, 
                                    'status': result['status_code'], 
                                    'text': result['text'],
                                    'traces': analysis['traces'],
                                    'severity': 'HIGH'
                                })
                            elif analysis['verdict'] == 'MEDIUM':
                                self.mapping_errors.append({
                                    'method': 'GET', 
                                    'param': param, 
                                    'status': result['status_code'], 
                                    'text': result['text'],
                                    'errors': analysis['errors'],
                                    'severity': 'MEDIUM'
                                })
        if self.params_post and self.post_url:
            injectable = [p for p in self.params_post if p not in self.csrf_params]
            btn = list(self.params_button.keys())[0] if self.params_button else None
            for probe in self.probe_strings:
                for param in injectable:
                    data = self.params_post.copy()
                    data[param] = probe
                    if btn:
                        data[btn] = self.params_button[btn]
                    result = self.make_request_with_retry('POST', self.post_url, data=data)
                    if result['success']:
                        if result['status_code'] == 200:
                            all_errors_no_200 = False
                            param_key = f"POST_{param}"
                            if param_key not in self.probe_data:
                                self.probe_data[param_key] = {
                                    'lengths': [self.baseline_length],
                                    'positions': [],
                                    'contexts': [],
                                    'probe_count': 0,
                                    'probe_success_count': 0
                                }
                            self.probe_data[param_key]['lengths'].append(result['length'])
                            self.probe_data[param_key]['probe_count'] += 1
                            if probe in result['text']:
                                self.probe_data[param_key]['probe_success_count'] += 1
                                pos = self.find_position(result['text'], probe)
                                context = self.detect_context(result['text'], probe)
                                self.probe_data[param_key]['positions'].append(pos)
                                self.probe_data[param_key]['contexts'].append(context)
                                positions.append({'method': 'POST', 'param': param, 'string': probe, 'position': pos, 'context': context})
                                mapping_success = True
                        else:
                            analysis = self.analyze_response(result['text'], result['status_code'])
                            if analysis['verdict'] == 'CRITICAL':
                                self.mapping_errors.append({
                                    'method': 'POST', 
                                    'param': param, 
                                    'status': result['status_code'], 
                                    'text': result['text'],
                                    'engines': analysis['engines'],
                                    'severity': 'CRITICAL'
                                })
                            elif analysis['verdict'] == 'HIGH':
                                self.mapping_errors.append({
                                    'method': 'POST', 
                                    'param': param, 
                                    'status': result['status_code'], 
                                    'text': result['text'],
                                    'traces': analysis['traces'],
                                    'severity': 'HIGH'
                                })
                            elif analysis['verdict'] == 'MEDIUM':
                                self.mapping_errors.append({
                                    'method': 'POST', 
                                    'param': param, 
                                    'status': result['status_code'], 
                                    'text': result['text'],
                                    'errors': analysis['errors'],
                                    'severity': 'MEDIUM'
                                })
        if all_errors_no_200 and self.mapping_errors:
            self.final_error_payload_scan()
            return False
        reflections = [p for p in positions if 'position' in p]
        if reflections:
            best = max(set((r['method'], r['param']) for r in reflections), key=lambda x: sum(1 for r in reflections if r['method']==x[0] and r['param']==x[1]))
            self.reflection_point = next(r for r in reflections if r['method']==best[0] and r['param']==best[1])
            param_key = f"{best[0]}_{best[1]}"
            if param_key in self.probe_data:
                probe_info = self.probe_data[param_key]
                if probe_info['positions']:
                    probe_info['common_position'] = max(set(probe_info['positions']), key=probe_info['positions'].count)
                else:
                    probe_info['common_position'] = None
                probe_info['median_length'] = statistics.median(probe_info['lengths'])
                probe_info['all_probes_successful'] = (probe_info['probe_success_count'] == len(self.probe_strings))
            return True
        elif self.mapping_errors:
            return True
        return False
    def inject_payload(self, method, param, payload, expected):
        btn = list(self.params_button.keys())[0] if self.params_button else None
        if method == 'GET':
            test_params = self.params_get.copy()
            test_params[param] = payload
            if self.get_url:
                url = f"{self.get_url}?{urlencode(test_params)}"
            else:
                url = f"{self.url.split('?')[0]}?{urlencode(test_params)}"
            result = self.make_request_with_retry('GET', url)
        else:
            data = self.params_post.copy()
            if self.csrf_params and self.post_url:
                data = self.extract_csrf_token(self.post_url, data)
            data[param] = payload
            if btn:
                data[btn] = self.params_button[btn]
            result = self.make_request_with_retry('POST', self.post_url, data=data)
        if not result['success']:
            return {
                'payload': payload,
                'expected': expected,
                'status': f"ERROR: {result['error']}",
                'length': None,
                'errors': [],
                'detected_engines': [],
                'analysis': {'verdict': 'ERROR', 'reason': result['error']},
                'success': False,
                'reflected': False,
                'position': None,
                'text': ''
            }
        analysis = self.analyze_response(result['text'], result['status_code'])
        errors_found = analysis['errors'] if 'errors' in analysis else []
        detected_engines = analysis['engines'] if 'engines' in analysis else []
        res = {
            'payload': payload,
            'expected': expected,
            'status': result['status_code'],
            'length': result['length'],
            'errors': errors_found,
            'detected_engines': detected_engines,
            'analysis': analysis,
            'success': True,
            'reflected': False,
            'position': None,
            'text': result['text']
        }
        if expected and expected in result['text']:
            res['reflected'] = True
            res['position'] = self.find_position(result['text'], expected)
        return res
    def scan_ssti(self):
        if not self.reflection_point and not self.mapping_errors:
            return
        payloads = [("{{7*7}}", "49"), ("${7*7}", "49"), ("<%=7*7%>", "49"), ("#{7*7}", "49"), ("@(7*7)", "49"), ("[[7*7]]", "49"), ("{7*7}", "49"), ("${{7*7}}", "49")]
        verified = []
        potential = []
        param_key = f"{self.reflection_point['method']}_{self.reflection_point['param']}"
        probe_info = self.probe_data.get(param_key, {})
        common_position = probe_info.get('common_position', self.reflection_point['position'])
        median_length = probe_info.get('median_length', self.baseline_length)
        all_probes_successful = probe_info.get('all_probes_successful', False)
        self.payload_results = []
        for payload, expected in payloads:
            time.sleep(random.uniform(1, 2))
            result = self.inject_payload(self.reflection_point['method'], self.reflection_point['param'], payload, expected)
            self.payload_results.append(result)
            if not result['success']:
                continue
            if result['status'] != 200:
                continue
            if result['reflected']:
                if result['position'] == common_position:
                    potential.append(payload)
                    verify_payload = payload.replace("7*7", "5*5") if "7*7" in payload else None
                    if verify_payload:
                        time.sleep(random.uniform(1, 2))
                        verify_result = self.inject_payload(self.reflection_point['method'], self.reflection_point['param'], verify_payload, "25")
                        if verify_result['success'] and verify_result['status'] == 200 and verify_result['reflected'] and verify_result['position'] == result['position']:
                            verified.append(payload)
                            result['verified'] = True
        if verified:
            url = self.get_url if self.reflection_point['method'] == 'GET' else self.post_url
            if not url:
                url = self.url.split('?')[0]
            result_text = f"{colors.RED}[!!!] CRITICAL: SSTI DETECTED{colors.END}\n"
            result_text += f"{colors.RED}    → URL: {url}{colors.END}\n"
            result_text += f"{colors.RED}    → Method: {self.reflection_point['method']}{colors.END}\n"
            result_text += f"{colors.RED}    → Parameter: {self.reflection_point['param']}{colors.END}\n"
            result_text += f"{colors.RED}    → Verified payloads: {len(verified)}{colors.END}\n"
            for v in verified:
                result_text += f"{colors.RED}    → {v}{colors.END}\n"
            print(result_text)
            self.finding_text = result_text
            return
        if potential:
            url = self.get_url if self.reflection_point['method'] == 'GET' else self.post_url
            if not url:
                url = self.url.split('?')[0]
            result_text = f"{colors.YELLOW}[!] POTENTIAL SSTI{colors.END}\n"
            result_text += f"{colors.YELLOW}    → URL: {url}{colors.END}\n"
            result_text += f"{colors.YELLOW}    → Method: {self.reflection_point['method']}{colors.END}\n"
            result_text += f"{colors.YELLOW}    → Parameter: {self.reflection_point['param']}{colors.END}\n"
            result_text += f"{colors.YELLOW}    → Unverified payloads: {len(potential)}{colors.END}\n"
            for p in potential:
                result_text += f"{colors.YELLOW}    → {p}{colors.END}\n"
            print(result_text)
            self.finding_text = result_text
            return
        suspicious = []
        waf_keywords = ['waf', 'blocked', 'forbidden', 'access denied', 'not found', 'invalid request', 'malformed', 'rejected']
        all_engines = set()
        critical_payloads = []
        for result in self.payload_results:
            if not result['success']:
                continue
            analysis = result.get('analysis', {})
            if analysis.get('verdict') == 'CRITICAL':
                engines = analysis.get('engines', [])
                if engines:
                    critical_payloads.append(result['payload'])
                    all_engines.update(engines)
            elif analysis.get('verdict') == 'HIGH':
                suspicious.append({
                    'payload': result['payload'], 
                    'reason': 'stack_trace_detected', 
                    'severity': 'high', 
                    'traces': analysis.get('traces', []),
                    'method': self.reflection_point['method'],
                    'param': self.reflection_point['param'],
                    'url': self.get_url if self.reflection_point['method'] == 'GET' else self.post_url
                })
            elif analysis.get('verdict') == 'MEDIUM':
                suspicious.append({
                    'payload': result['payload'], 
                    'reason': 'error_patterns_detected', 
                    'severity': 'medium', 
                    'errors': analysis.get('errors', []),
                    'method': self.reflection_point['method'],
                    'param': self.reflection_point['param'],
                    'url': self.get_url if self.reflection_point['method'] == 'GET' else self.post_url
                })
            elif isinstance(result['status'], int):
                if result['status'] >= 500:
                    if not analysis.get('has_non_suspicious'):
                        suspicious.append({
                            'payload': result['payload'], 
                            'reason': f"status_{result['status']}_no_details", 
                            'severity': 'medium',
                            'method': self.reflection_point['method'],
                            'param': self.reflection_point['param'],
                            'url': self.get_url if self.reflection_point['method'] == 'GET' else self.post_url
                        })
        if critical_payloads:
            url = self.get_url if self.reflection_point['method'] == 'GET' else self.post_url
            if not url:
                url = self.url.split('?')[0]
            result_text = f"{colors.RED}[!!!] CRITICAL: SSTI DETECTED{colors.END}\n"
            result_text += f"{colors.RED}    → URL: {url}{colors.END}\n"
            result_text += f"{colors.RED}    → Method: {self.reflection_point['method']}{colors.END}\n"
            result_text += f"{colors.RED}    → Parameter: {self.reflection_point['param']}{colors.END}\n"
            result_text += f"{colors.RED}    → Engine(s): {colors.BOLD}{', '.join(all_engines)}{colors.RED}{colors.END}\n"
            result_text += f"{colors.RED}    → Affected payloads: {len(critical_payloads)} payloads{colors.END}\n"
            result_text += f"{colors.RED}    → Examples: {', '.join(critical_payloads[:3])}{colors.END}\n"
            print(result_text)
            self.finding_text = result_text
            return
        high_severity = [s for s in suspicious if s['severity'] == 'high']
        medium_severity = [s for s in suspicious if s['severity'] == 'medium']
        if high_severity or medium_severity:
            url = self.get_url if self.reflection_point['method'] == 'GET' else self.post_url
            if not url:
                url = self.url.split('?')[0]
            result_text = ""
            if high_severity:
                result_text += f"{colors.MAGENTA}[!] HIGH SEVERITY ANOMALIES{colors.END}\n"
                result_text += f"{colors.MAGENTA}    → URL: {url}{colors.END}\n"
                result_text += f"{colors.MAGENTA}    → Method: {self.reflection_point['method']}{colors.END}\n"
                result_text += f"{colors.MAGENTA}    → Parameter: {self.reflection_point['param']}{colors.END}\n"
                for s in high_severity[:3]:
                    result_text += f"{colors.MAGENTA}    → {s['payload']}: {s['reason']}{colors.END}\n"
            if medium_severity:
                result_text += f"{colors.YELLOW}[!] MEDIUM SEVERITY ANOMALIES{colors.END}\n"
                result_text += f"{colors.YELLOW}    → URL: {url}{colors.END}\n"
                result_text += f"{colors.YELLOW}    → Method: {self.reflection_point['method']}{colors.END}\n"
                result_text += f"{colors.YELLOW}    → Parameter: {self.reflection_point['param']}{colors.END}\n"
                for s in medium_severity[:3]:
                    result_text += f"{colors.YELLOW}    → {s['payload']}: {s['reason']}{colors.END}\n"
            if len(high_severity) + len(medium_severity) > 3:
                result_text += f"{colors.MAGENTA}    ... and {len(high_severity) + len(medium_severity) - 3} more{colors.END}\n"
            print(result_text)
            self.finding_text = result_text
        else:
            self.final_error_payload_scan()
    def final_error_payload_scan(self):
        error_payload = "${{<%[%'\"}}%\\"
        all_params = []
        for param in self.params_get:
            all_params.append(('GET', param, self.get_url if self.get_url else self.url.split('?')[0]))
        if self.post_url:
            injectable = [p for p in self.params_post if p not in self.csrf_params]
            for param in injectable:
                all_params.append(('POST', param, self.post_url))
        if not all_params:
            return
        error_results = []
        all_engines = set()
        critical_params = []
        high_results = []
        medium_results = []
        for method, param, target_url in all_params:
            time.sleep(random.uniform(1, 2))
            result = self.inject_payload(method, param, error_payload, "")
            error_results.append(result)
            if not result['success']:
                continue
            analysis = result.get('analysis', {})
            if analysis.get('verdict') == 'CRITICAL':
                engines = analysis.get('engines', [])
                if engines:
                    critical_params.append({
                        'method': method,
                        'param': param,
                        'url': target_url,
                        'engines': engines
                    })
                    all_engines.update(engines)
            elif analysis.get('verdict') == 'HIGH':
                high_results.append({
                    'method': method,
                    'param': param,
                    'url': target_url,
                    'traces': analysis.get('traces', [])
                })
            elif analysis.get('verdict') == 'MEDIUM':
                medium_results.append({
                    'method': method,
                    'param': param,
                    'url': target_url,
                    'errors': analysis.get('errors', [])
                })
            elif result['status'] == 500 and not analysis.get('has_non_suspicious'):
                medium_results.append({
                    'method': method,
                    'param': param,
                    'url': target_url,
                    'reason': 'status_500_no_details'
                })
        if critical_params or high_results or medium_results:
            result_text = ""
            if critical_params:
                result_text += f"{colors.RED}[!!!] CRITICAL: {len(critical_params)} parameter(s) triggered engine errors{colors.END}\n"
                if all_engines:
                    result_text += f"{colors.RED}    → Engine(s): {colors.BOLD}{', '.join(all_engines)}{colors.RED}{colors.END}\n"
                for cp in critical_params[:3]:
                    result_text += f"{colors.RED}    → URL: {cp['url']}{colors.END}\n"
                    result_text += f"{colors.RED}      Method: {cp['method']}, Parameter: {cp['param']}{colors.END}\n"
            if high_results:
                result_text += f"{colors.MAGENTA}[!] HIGH: {len(high_results)} parameter(s) triggered stack traces{colors.END}\n"
                for hr in high_results[:3]:
                    result_text += f"{colors.MAGENTA}    → URL: {hr['url']}{colors.END}\n"
                    result_text += f"{colors.MAGENTA}      Method: {hr['method']}, Parameter: {hr['param']}{colors.END}\n"
            if medium_results:
                result_text += f"{colors.YELLOW}[!] MEDIUM: {len(medium_results)} parameter(s) triggered anomalies{colors.END}\n"
                for mr in medium_results[:3]:
                    result_text += f"{colors.YELLOW}    → URL: {mr['url']}{colors.END}\n"
                    result_text += f"{colors.YELLOW}      Method: {mr['method']}, Parameter: {mr['param']}{colors.END}\n"
            print(result_text)
            self.finding_text = result_text
    def run(self):
        print(f"{colors.BOLD}{colors.CYAN}[SSTI Scanner] Target: {self.url}{colors.END}")
        if self.cookie:
            print(f"{colors.BOLD}[Cookie] Present - Session will be preserved{colors.END}")
        self.extract_params()
        if not self.params_get and not self.params_post:
            return
        if not self.check_baseline():
            pass
        if self.track_reflection():
            self.scan_ssti()
        return self.finding_text
def read_urls_from_file(filename):
    urls = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    urls.append(url)
    except Exception as e:
        print(f"{colors.RED}[ERROR] Failed to read URL list: {e}{colors.END}")
        sys.exit(1)
    return urls
def init_output_file(output_file, total_urls):
    try:
        with open(output_file, 'w') as f:
            f.write("="*50 + "\n")
            f.write("SSTI SCAN RESULTS\n")
            f.write("="*50 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total URLs to Scan: {total_urls}\n")
            f.write("="*50 + "\n\n")
    except Exception as e:
        print(f"{colors.RED}[ERROR] Failed to create output file: {e}{colors.END}")
def append_finding_to_file(output_file, finding_text):
    try:
        finding_clean = finding_text.replace(colors.RED, '').replace(colors.GREEN, '').replace(colors.YELLOW, '')
        finding_clean = finding_clean.replace(colors.BLUE, '').replace(colors.CYAN, '').replace(colors.MAGENTA, '')
        finding_clean = finding_clean.replace(colors.BOLD, '').replace(colors.END, '')
        with open(output_file, 'a') as f:
            f.write(finding_clean + "\n")
            f.write("-"*50 + "\n")
            f.flush()
    except Exception as e:
        print(f"{colors.RED}[ERROR] Failed to write to output file: {e}{colors.END}")
def finalize_output_file(output_file, scanned, findings_count):
    try:
        with open(output_file, 'a') as f:
            f.write("\n" + "="*50 + "\n")
            f.write(f"Scan Complete: {findings_count} findings out of {scanned} URLs\n")
            f.write("="*50 + "\n")
    except Exception as e:
        print(f"{colors.RED}[ERROR] Failed to finalize output file: {e}{colors.END}")
async def scan_url_async(semaphore, url, cookie, output_file, findings_counter, total_urls):
    async with semaphore:
        print(f"\n{colors.BOLD}[{findings_counter['scanned']+1}/{total_urls}] Scanning: {url}{colors.END}")
        loop = asyncio.get_event_loop()
        scanner = SSTIScanner(url, cookie)
        finding = await loop.run_in_executor(None, scanner.run)
        findings_counter['scanned'] += 1
        if finding:
            findings_counter['findings'] += 1
            print(f"{colors.GREEN}[FINDING] Found on: {url}{colors.END}")
            if output_file:
                append_finding_to_file(output_file, finding)
        return finding
async def scan_multiple_urls(urls, cookie, output_file, max_concurrent):
    print(f"{colors.BOLD}{colors.CYAN}[SSTI Scanner] Scanning {len(urls)} URLs (concurrent: {max_concurrent}){colors.END}")
    if output_file:
        init_output_file(output_file, len(urls))
    semaphore = asyncio.Semaphore(max_concurrent)
    findings_counter = {'scanned': 0, 'findings': 0}
    tasks = []
    for url in urls:
        task = asyncio.create_task(scan_url_async(semaphore, url, cookie, output_file, findings_counter, len(urls)))
        tasks.append(task)
    await asyncio.gather(*tasks)
    print(f"\n{colors.BOLD}{colors.CYAN}[SCAN COMPLETE]{colors.END}")
    print(f"{colors.GREEN}URLs scanned: {findings_counter['scanned']}{colors.END}")
    print(f"{colors.YELLOW}Findings: {findings_counter['findings']}{colors.END}")
    if output_file:
        finalize_output_file(output_file, findings_counter['scanned'], findings_counter['findings'])
        print(f"{colors.GREEN}Results saved to: {output_file}{colors.END}")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SSTI Scanner Tool')
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-l', '--list', help='File containing list of URLs to scan')
    parser.add_argument('-c', '--cookie', help='Cookie to use for authenticated requests')
    parser.add_argument('-o', '--output', help='Output file to save findings (plaintext)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Number of concurrent URLs (default: 5)')
    args = parser.parse_args()
    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)
    if args.list:
        urls = read_urls_from_file(args.list)
        asyncio.run(scan_multiple_urls(urls, args.cookie, args.output, args.threads))
    else:
        scanner = SSTIScanner(args.url, args.cookie)
        finding = scanner.run()
        if finding and args.output:
            init_output_file(args.output, 1)
            append_finding_to_file(args.output, finding)
            finalize_output_file(args.output, 1, 1)
            print(f"{colors.GREEN}Results saved to: {args.output}{colors.END}")
