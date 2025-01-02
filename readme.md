# Comprehensive Web Application Vulnerability Scanner

This is a Python-based scanner to detect common web application vulnerabilities. It covers several security checks like XSS, SQL Injection, CSRF, Open Redirects, and more. The tool also tests for SSL/TLS vulnerabilities, checks for proper HTTP security headers, and validates JWT tokens.

## Features:
- XSS Detection (Reflected and Stored)
- SQL Injection (Error-Based and Blind)
- CSRF Detection
- Open Redirect Detection
- Subdomain Enumeration
- Brute Force Testing for Login Pages
- SSL/TLS Vulnerability Check
- Automated HTTP Security Headers Test
- JWT Validation
- Content Security Policy (CSP) Header Check
- CORS Misconfiguration Check

## Setup Instructions:

### 1. Clone the repository:
    Open Git Bash or Command Prompt and execute:
    ```bash
    git clone https://github.com/yourusername/vuln-scanner.git
    cd vuln-scanner
    ```

### 2. Set up a virtual environment (optional but recommended):
    ```bash
    python -m venv venv
    source venv/Scripts/activate  # For Git Bash or Command Prompt
    ```

### 3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### 4. Run the scanner:
    ```bash
    python scanner.py
    ```

    Enter the URL you want to scan when prompted.

## Contributing:
Feel free to fork this repository, submit issues, or open pull requests with improvements, bug fixes, or new features.

