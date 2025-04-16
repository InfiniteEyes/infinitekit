import logging
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import time

def scan_website(target_url, scan_depth='basic'):
    """
    Scan a website for common vulnerabilities
    
    Args:
        target_url (str): The URL to scan
        scan_depth (str): Scan depth - 'basic', 'medium', or 'deep'
    
    Returns:
        list: List of vulnerability results
    """
    logging.info(f"Starting website scan for {target_url} with depth {scan_depth}")
    results = []
    
    try:
        # Standardize URL format
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # Perform initial request
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        }
        response = session.get(target_url, headers=headers, timeout=10, allow_redirects=True)
        
        # Check for server information disclosure
        server_info = check_server_info(response)
        if server_info:
            results.append(server_info)
        
        # Check for insecure headers
        header_vulns = check_security_headers(response)
        results.extend(header_vulns)
        
        # Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check for potential XSS vulnerabilities
        xss_vulns = check_xss_vulnerabilities(soup, target_url)
        results.extend(xss_vulns)
        
        # Check for potential SQL injection points
        sqli_vulns = check_sql_injection(soup, target_url, session)
        results.extend(sqli_vulns)
        
        # Check for CSRF vulnerabilities
        csrf_vulns = check_csrf_vulnerabilities(soup, target_url)
        results.extend(csrf_vulns)
        
        # If medium or deep scan, do more intensive checks
        if scan_depth in ['medium', 'deep']:
            # Get all links on the page
            links = get_page_links(soup, target_url)
            
            # Check for sensitive files
            sensitive_files = check_sensitive_files(target_url, session)
            results.extend(sensitive_files)
            
            # Check for directory listing
            dir_listing = check_directory_listing(target_url, session)
            if dir_listing:
                results.append(dir_listing)
                
            # If deep scan, crawl site links and check them
            if scan_depth == 'deep' and links:
                # Limit to avoid excessive scanning
                for link in links[:10]:
                    try:
                        link_response = session.get(link, headers=headers, timeout=5)
                        link_soup = BeautifulSoup(link_response.text, 'html.parser')
                        
                        # Check for XSS in sub-pages
                        link_xss = check_xss_vulnerabilities(link_soup, link)
                        results.extend(link_xss)
                        
                        # Brief pause to avoid overwhelming the server
                        time.sleep(0.5)
                    except Exception as e:
                        logging.warning(f"Error scanning sub-link {link}: {e}")
        
        logging.info(f"Completed website scan for {target_url}. Found {len(results)} potential vulnerabilities.")
        return results
    
    except Exception as e:
        logging.error(f"Error scanning website {target_url}: {e}")
        results.append({
            'vulnerability_type': 'scan_error',
            'severity': 'low',
            'description': 'An error occurred during the scan',
            'details': str(e)
        })
        return results


def check_server_info(response):
    """Check for server information disclosure in headers"""
    server_header = response.headers.get('Server')
    if server_header:
        return {
            'vulnerability_type': 'server_info_disclosure',
            'severity': 'low',
            'description': 'Server information disclosure',
            'details': f"The server header reveals information about the underlying technology: {server_header}"
        }
    return None


def check_security_headers(response):
    """Check for missing security headers"""
    results = []
    
    # Important security headers
    security_headers = {
        'Strict-Transport-Security': 'Missing HSTS header which helps protect against protocol downgrade attacks',
        'Content-Security-Policy': 'Missing CSP header which helps mitigate XSS attacks',
        'X-Content-Type-Options': 'Missing X-Content-Type-Options header which prevents MIME type sniffing',
        'X-Frame-Options': 'Missing X-Frame-Options header which protects against clickjacking',
        'X-XSS-Protection': 'Missing X-XSS-Protection header which enables browser XSS filters'
    }
    
    for header, description in security_headers.items():
        if header not in response.headers:
            results.append({
                'vulnerability_type': f'missing_{header.lower().replace("-", "_")}',
                'severity': 'medium',
                'description': f'Missing security header: {header}',
                'details': description
            })
    
    # Check if HTTPS is used
    if response.url.startswith('http://'):
        results.append({
            'vulnerability_type': 'insecure_http',
            'severity': 'high',
            'description': 'Insecure HTTP connection',
            'details': 'The website is using insecure HTTP protocol instead of HTTPS, which puts user data at risk.'
        })
    
    return results


def check_xss_vulnerabilities(soup, base_url):
    """Check for potential XSS vulnerabilities"""
    results = []
    
    # Find input fields that might be vulnerable
    input_fields = soup.find_all(['input', 'textarea'])
    forms = soup.find_all('form')
    
    # Check input fields
    for input_field in input_fields:
        input_type = input_field.get('type', '').lower()
        
        # Text inputs are more likely to be vulnerable
        if input_type in ['text', 'search', 'url', 'email', 'hidden'] or input_field.name == 'textarea':
            field_name = input_field.get('name', 'unnamed')
            field_id = input_field.get('id', 'no-id')
            
            # Look for lack of validation attributes
            if not input_field.get('pattern') and not input_field.get('maxlength'):
                results.append({
                    'vulnerability_type': 'potential_xss',
                    'severity': 'high',
                    'description': f'Potential XSS vulnerability in {input_field.name} field',
                    'details': f"Field name: {field_name}, ID: {field_id}. No input validation patterns detected, which may allow injection of malicious scripts."
                })
    
    # Check for unsafe innerHTML usage in scripts
    scripts = soup.find_all('script')
    for script in scripts:
        script_content = script.string
        if script_content:
            # Look for dangerous patterns like direct DOM manipulation without sanitization
            if re.search(r'\.innerHTML\s*=|document\.write\(', script_content):
                results.append({
                    'vulnerability_type': 'unsafe_javascript',
                    'severity': 'high',
                    'description': 'Unsafe JavaScript DOM manipulation',
                    'details': "The application may have unsafe DOM manipulation (innerHTML or document.write) which could lead to XSS vulnerabilities."
                })
    
    return results


def check_sql_injection(soup, base_url, session):
    """Check for potential SQL injection vulnerabilities"""
    results = []
    
    # Find forms that could be used for SQL injection testing
    forms = soup.find_all('form')
    
    for form in forms:
        form_method = form.get('method', 'get').lower()
        form_action = form.get('action', '')
        form_url = urljoin(base_url, form_action) if form_action else base_url
        
        # If it's a login or search form, it's worth checking
        if any(keyword in str(form).lower() for keyword in ['login', 'search', 'user', 'pass']):
            results.append({
                'vulnerability_type': 'potential_sqli',
                'severity': 'high',
                'description': 'Potential SQL injection point',
                'details': f"A {form_method.upper()} form at {form_url} contains input fields that might be vulnerable to SQL injection."
            })
    
    return results


def check_csrf_vulnerabilities(soup, base_url):
    """Check for CSRF vulnerabilities"""
    results = []
    
    # Find forms without CSRF tokens
    forms = soup.find_all('form')
    
    for form in forms:
        # Check for form method - POST forms without CSRF protection are vulnerable
        form_method = form.get('method', 'get').lower()
        if form_method == 'post':
            # Check for CSRF tokens
            has_csrf_token = False
            
            # Look for common CSRF token implementations
            csrf_inputs = form.find_all('input', attrs={
                'name': re.compile(r'csrf|token|nonce', re.I)
            })
            
            if not csrf_inputs:
                # Look for hidden inputs that might contain CSRF tokens
                hidden_inputs = form.find_all('input', attrs={'type': 'hidden'})
                if not any(re.search(r'csrf|token|nonce', str(input_), re.I) for input_ in hidden_inputs):
                    has_csrf_token = False
                else:
                    has_csrf_token = True
            else:
                has_csrf_token = True
            
            if not has_csrf_token:
                form_action = form.get('action', 'unknown')
                results.append({
                    'vulnerability_type': 'csrf_vulnerability',
                    'severity': 'high',
                    'description': 'Potential CSRF vulnerability',
                    'details': f"POST form with action '{form_action}' doesn't appear to implement CSRF protection, making it vulnerable to cross-site request forgery attacks."
                })
    
    return results


def get_page_links(soup, base_url):
    """Get all links on a page that belong to the same domain"""
    links = []
    base_domain = urlparse(base_url).netloc
    
    for a_tag in soup.find_all('a', href=True):
        href = a_tag['href']
        full_url = urljoin(base_url, href)
        
        # Only include links to the same domain
        parsed_url = urlparse(full_url)
        if parsed_url.netloc == base_domain:
            links.append(full_url)
    
    return list(set(links))  # Remove duplicates


def check_sensitive_files(base_url, session):
    """Check for common sensitive files"""
    results = []
    sensitive_paths = [
        '/robots.txt',
        '/.git/HEAD',
        '/.env',
        '/wp-config.php',
        '/config.php',
        '/admin/',
        '/phpinfo.php',
        '/.htaccess',
        '/.svn/entries',
        '/backup/',
        '/backup.zip',
        '/wp-login.php'
    ]
    
    for path in sensitive_paths:
        try:
            url = urljoin(base_url, path)
            response = session.get(url, timeout=5)
            
            if response.status_code == 200:
                results.append({
                    'vulnerability_type': 'sensitive_file_exposure',
                    'severity': 'high',
                    'description': f'Sensitive file or directory found: {path}',
                    'details': f"The server exposes a potentially sensitive file or directory at {url}, which may reveal configurations or allow unauthorized access."
                })
        except:
            pass
    
    return results


def check_directory_listing(base_url, session):
    """Check for directory listing vulnerabilities"""
    common_dirs = ['/images/', '/js/', '/css/', '/uploads/', '/includes/', '/temp/']
    
    for directory in common_dirs:
        try:
            url = urljoin(base_url, directory)
            response = session.get(url, timeout=5)
            
            # Look for signs of directory listing
            if response.status_code == 200 and any(marker in response.text for marker in [
                'Index of', 'Directory Listing', 'Parent Directory'
            ]):
                return {
                    'vulnerability_type': 'directory_listing',
                    'severity': 'medium',
                    'description': 'Directory listing enabled',
                    'details': f"Directory listing is enabled at {url}, which may expose sensitive files and information."
                }
        except:
            pass
    
    return None
