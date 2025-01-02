import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import ssl
import socket
import jwt
from itertools import product

# XSS Detection (Reflected and Stored)
def test_xss(url):
    payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    for payload in payloads:
        response = requests.get(url, params={ 'input': payload })
        if payload in response.text:
            print(f"Potential XSS vulnerability found on: {url}")

def test_stored_xss(url):
    payloads = ["<script>alert('Stored XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    response = requests.post(url, data={ 'input': payload })
    if payload in response.text:
        print(f"Potential Stored XSS vulnerability found on: {url}")

# SQL Injection (Error-Based and Blind)
def test_sql_injection(url):
    sql_payloads = ["' OR 1=1 --", "' OR 'a'='a"]
    for payload in sql_payloads:
        response = requests.get(url, params={ 'input': payload })
        if "error" in response.text:
            print(f"Potential SQL Injection vulnerability found on: {url}")

def test_blind_sql_injection(url):
    blind_payloads = ["' AND 1=1", "' AND 1=2", "' OR 1=1 --"]
    for payload in blind_payloads:
        response = requests.get(url, params={ 'input': payload })
        if "error" in response.text or "unexpected" in response.text:
            print(f"Potential Blind SQL Injection vulnerability found on: {url}")

# CSRF Detection
def test_csrf(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        if not form.find('input', {'name': '_csrf_token'}):
            print(f"Potential CSRF vulnerability found on: {url}")

# Open Redirect Detection
def test_open_redirect(url):
    redirect_payloads = ["http://malicious-website.com", "https://malicious-website.com"]
    for payload in redirect_payloads:
        response = requests.get(url, params={ 'redirect': payload })
        if response.url != url:
            print(f"Potential Open Redirect vulnerability found on: {url}")

# Subdomain Enumeration
def enumerate_subdomains(domain):
    api_url = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key=YOUR_API_KEY"
    response = requests.get(api_url)
    if response.status_code == 200:
        subdomains = response.json()
        print(f"Subdomains of {domain}: {', '.join(subdomains)}")
    else:
        print(f"Could not enumerate subdomains for {domain}")

# Brute Force Testing for Login Pages
def brute_force_login(url):
    usernames = ['admin', 'user', 'guest']
    passwords = ['password', '123456', 'admin']
    for username, password in product(usernames, passwords):
        response = requests.post(url, data={'username': username, 'password': password})
        if "login successful" in response.text:
            print(f"Login successful with {username}:{password}")
            break
        else:
            print(f"Failed attempt: {username}:{password}")

# SSL/TLS Vulnerability Check
def check_ssl_vulnerabilities(domain):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    try:
        conn.connect((domain, 443))
        ssl_info = conn.getpeercert()
        print(f"SSL Certificate Info for {domain}: {ssl_info}")
    except ssl.SSLError as e:
        print(f"SSL error on {domain}: {e}")

# Content Security Policy Header Check
def check_csp_header(url):
    response = requests.get(url)
    csp_header = response.headers.get('Content-Security-Policy')
    if csp_header:
        print(f"CSP header found: {csp_header}")
    else:
        print(f"No CSP header found on: {url}")

# JWT Validation
def check_jwt_token(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        print(f"Decoded JWT: {decoded}")
    except jwt.DecodeError:
        print("Invalid JWT token.")
    except Exception as e:
        print(f"Error in JWT validation: {e}")

# CORS Misconfiguration Check
def check_cors(url):
    response = requests.options(url)
    cors_header = response.headers.get('Access-Control-Allow-Origin')
    if cors_header == '*':
        print(f"Potential CORS misconfiguration detected on: {url}")
    else:
        print(f"CORS configuration looks safe for: {url}")

# Run the scan on the target URL
def scan(url):
    print(f"Scanning {url}...")
    test_xss(url)
    test_stored_xss(url)
    test_sql_injection(url)
    test_blind_sql_injection(url)
    test_csrf(url)
    test_open_redirect(url)
    check_cors(url)
    check_csp_header(url)
    check_ssl_vulnerabilities(urlparse(url).hostname)

if __name__ == "__main__":
    url = input("Enter the URL to scan: ")
    scan(url)
