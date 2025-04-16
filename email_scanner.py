import logging
import re
import dns.resolver
import socket
import email
from email.parser import HeaderParser
import base64

def scan_email(target_email, scan_headers=True, check_spf_dkim=True, check_phishing=True):
    """
    Analyze an email address or raw email content for security issues
    
    Args:
        target_email (str): Email address or raw email content
        scan_headers (bool): Whether to analyze email headers
        check_spf_dkim (bool): Whether to check SPF/DKIM/DMARC records
        check_phishing (bool): Whether to check for phishing indicators
    
    Returns:
        list: List of vulnerability results
    """
    logging.info(f"Starting email analysis for {target_email}")
    results = []
    
    try:
        # Check if this is a raw email or just an email address
        is_raw_email = '\n' in target_email
        
        if is_raw_email:
            # Analyze raw email content
            if scan_headers:
                header_results = analyze_email_headers(target_email)
                results.extend(header_results)
            
            if check_phishing:
                phishing_results = check_phishing_indicators(target_email)
                results.extend(phishing_results)
        else:
            # Just an email address - check domain
            domain = target_email.split('@')[-1]
            
            # Basic email format validation
            email_format_results = validate_email_format(target_email)
            results.extend(email_format_results)
            
            if check_spf_dkim:
                dns_results = check_email_dns_records(domain)
                results.extend(dns_results)
        
        logging.info(f"Completed email analysis. Found {len(results)} issues/vulnerabilities.")
        return results
    
    except Exception as e:
        logging.error(f"Error scanning email {target_email}: {e}")
        results.append({
            'vulnerability_type': 'scan_error',
            'severity': 'low',
            'description': 'An error occurred during the email analysis',
            'details': str(e)
        })
        return results


def validate_email_format(email_address):
    """Validate basic email format and check for common issues"""
    results = []
    
    # Basic email format regex
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_regex, email_address):
        results.append({
            'vulnerability_type': 'invalid_email_format',
            'severity': 'low',
            'description': 'Invalid email format',
            'details': f"The email address '{email_address}' does not follow standard email format."
        })
        return results
    
    # Check for disposable email services
    domain = email_address.split('@')[-1]
    disposable_domains = [
        'mailinator.com', 'yopmail.com', 'guerrillamail.com', 
        'tempmail.com', '10minutemail.com', 'temp-mail.org'
    ]
    
    if domain in disposable_domains:
        results.append({
            'vulnerability_type': 'disposable_email',
            'severity': 'medium',
            'description': 'Disposable email address detected',
            'details': f"The domain '{domain}' is a known disposable email service, which may indicate temporary or anonymous usage."
        })
    
    return results


def check_email_dns_records(domain):
    """Check SPF, DKIM, and DMARC DNS records for a domain"""
    results = []
    
    # Check for MX records
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if not mx_records:
            results.append({
                'vulnerability_type': 'missing_mx_records',
                'severity': 'high',
                'description': 'Missing MX records',
                'details': f"The domain '{domain}' does not have MX records, which are required for email delivery."
            })
    except Exception as e:
        results.append({
            'vulnerability_type': 'mx_resolution_error',
            'severity': 'medium',
            'description': 'Unable to resolve MX records',
            'details': f"Error resolving MX records for '{domain}': {str(e)}"
        })
    
    # Check for SPF record
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        has_spf = False
        
        for record in spf_records:
            txt_record = record.to_text()
            if 'v=spf1' in txt_record:
                has_spf = True
                # Check for weak SPF configuration
                if '+all' in txt_record:
                    results.append({
                        'vulnerability_type': 'weak_spf_record',
                        'severity': 'high',
                        'description': 'Weak SPF configuration',
                        'details': f"The domain has a SPF record with '+all' which is dangerous as it allows any server to send emails from this domain: {txt_record}"
                    })
                elif '~all' in txt_record:
                    results.append({
                        'vulnerability_type': 'soft_fail_spf',
                        'severity': 'medium',
                        'description': 'SPF soft fail configuration',
                        'details': f"The domain has a SPF record with '~all' (soft fail), which is less secure than a hard fail: {txt_record}"
                    })
        
        if not has_spf:
            results.append({
                'vulnerability_type': 'missing_spf',
                'severity': 'high',
                'description': 'Missing SPF record',
                'details': f"The domain '{domain}' does not have a Sender Policy Framework (SPF) record, making it vulnerable to email spoofing."
            })
    except Exception as e:
        results.append({
            'vulnerability_type': 'spf_resolution_error',
            'severity': 'medium',
            'description': 'Unable to resolve SPF record',
            'details': f"Error checking SPF record for '{domain}': {str(e)}"
        })
    
    # Check for DMARC record
    try:
        dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        has_dmarc = False
        
        for record in dmarc_records:
            txt_record = record.to_text()
            if 'v=DMARC1' in txt_record:
                has_dmarc = True
                
                # Check for weak DMARC policy
                if 'p=none' in txt_record:
                    results.append({
                        'vulnerability_type': 'weak_dmarc_policy',
                        'severity': 'medium',
                        'description': 'Weak DMARC policy',
                        'details': f"The domain has a DMARC record with 'p=none' which only monitors but does not enforce any policy: {txt_record}"
                    })
        
        if not has_dmarc:
            results.append({
                'vulnerability_type': 'missing_dmarc',
                'severity': 'high',
                'description': 'Missing DMARC record',
                'details': f"The domain '{domain}' does not have a DMARC record, reducing protection against email spoofing."
            })
    except Exception as e:
        results.append({
            'vulnerability_type': 'dmarc_resolution_error',
            'severity': 'medium',
            'description': 'Unable to resolve DMARC record',
            'details': f"Error checking DMARC record for '{domain}': {str(e)}"
        })
    
    return results


def analyze_email_headers(raw_email):
    """Analyze email headers for security issues and anomalies"""
    results = []
    
    try:
        # Parse the email headers
        parser = HeaderParser()
        headers = parser.parsestr(raw_email)
        
        # Check for header inconsistencies
        from_header = headers.get('From', '')
        return_path = headers.get('Return-Path', '')
        
        if from_header and return_path and '@' in from_header and '@' in return_path:
            from_domain = from_header.split('@')[-1].strip('>')
            return_domain = return_path.split('@')[-1].strip('>')
            
            if from_domain != return_domain:
                results.append({
                    'vulnerability_type': 'header_inconsistency',
                    'severity': 'high',
                    'description': 'Email header inconsistency',
                    'details': f"The 'From' header domain ({from_domain}) does not match the 'Return-Path' domain ({return_domain}), which is a strong indicator of email spoofing."
                })
        
        # Check for missing important headers
        important_headers = ['Message-ID', 'Date', 'From', 'To']
        for header in important_headers:
            if not headers.get(header):
                results.append({
                    'vulnerability_type': 'missing_header',
                    'severity': 'medium',
                    'description': f'Missing {header} header',
                    'details': f"The email is missing the '{header}' header, which is unusual for legitimate emails."
                })
        
        # Check for suspicious Received headers
        received_headers = headers.get_all('Received', [])
        if received_headers:
            # Analyze the path that the email took
            suspicious_ips = []
            for received in received_headers:
                # Look for IPs in the Received header
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                found_ips = re.findall(ip_pattern, received)
                
                for ip in found_ips:
                    # Check if it's a private IP (for demonstration)
                    if ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
                        suspicious_ips.append(ip)
            
            if suspicious_ips:
                results.append({
                    'vulnerability_type': 'suspicious_received_path',
                    'severity': 'medium',
                    'description': 'Suspicious email routing',
                    'details': f"The email passed through potentially suspicious IP addresses: {', '.join(suspicious_ips)}"
                })
        
        # Check Authentication-Results for SPF/DKIM failures
        auth_results = headers.get('Authentication-Results', '')
        if 'spf=fail' in auth_results or 'dkim=fail' in auth_results:
            results.append({
                'vulnerability_type': 'authentication_failure',
                'severity': 'high',
                'description': 'Email authentication failure',
                'details': f"The email failed authentication checks: {auth_results}"
            })
        
        return results
    
    except Exception as e:
        logging.error(f"Error analyzing email headers: {e}")
        results.append({
            'vulnerability_type': 'header_analysis_error',
            'severity': 'low',
            'description': 'Error analyzing email headers',
            'details': str(e)
        })
        return results


def check_phishing_indicators(raw_email):
    """Check for common phishing indicators in an email"""
    results = []
    
    try:
        # Parse the email
        msg = email.message_from_string(raw_email)
        
        # Check subject for common phishing keywords
        subject = msg.get('Subject', '')
        phishing_keywords = [
            'urgent', 'verify', 'account', 'suspend', 'update', 'security', 
            'confirm', 'immediately', 'unusual activity', 'password', 'login'
        ]
        
        subject_lower = subject.lower()
        found_keywords = [keyword for keyword in phishing_keywords if keyword in subject_lower]
        
        if found_keywords:
            results.append({
                'vulnerability_type': 'phishing_subject',
                'severity': 'medium',
                'description': 'Potential phishing subject',
                'details': f"The email subject contains common phishing keywords: {', '.join(found_keywords)}"
            })
        
        # Get email body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == 'text/plain' or content_type == 'text/html':
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        body += payload.decode(charset, errors='replace')
                    except:
                        pass
        else:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or 'utf-8'
                body += payload.decode(charset, errors='replace')
            except:
                pass
        
        # Check for suspicious links in the body
        url_pattern = r'https?://[^\s<>"\']*'
        urls = re.findall(url_pattern, body)
        
        mismatched_urls = []
        for url in urls:
            # Look for URLs that display one domain but link to another
            display_text_pattern = r'<a[^>]*href=["\'](' + re.escape(url) + r')["\'][^>]*>(.*?)</a>'
            display_matches = re.findall(display_text_pattern, body)
            
            for href, display_text in display_matches:
                # If the display text looks like a URL but doesn't match the href
                if re.match(url_pattern, display_text) and href != display_text:
                    mismatched_urls.append((display_text, href))
        
        if mismatched_urls:
            results.append({
                'vulnerability_type': 'misleading_links',
                'severity': 'high',
                'description': 'Misleading links detected',
                'details': f"The email contains links that display one URL but actually link to another: {mismatched_urls}"
            })
        
        # Check for suspicious attachments
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    # Check for dangerous extensions
                    dangerous_extensions = ['.exe', '.js', '.vbs', '.bat', '.cmd', '.scr', '.pif', '.reg', '.com', '.jar', '.jse', '.wsf', '.ps1', '.msi', '.hta']
                    
                    for ext in dangerous_extensions:
                        if filename.lower().endswith(ext):
                            results.append({
                                'vulnerability_type': 'dangerous_attachment',
                                'severity': 'critical',
                                'description': 'Potentially malicious attachment',
                                'details': f"The email contains an attachment with a potentially dangerous extension: {filename}"
                            })
                            break
        
        return results
    
    except Exception as e:
        logging.error(f"Error checking phishing indicators: {e}")
        results.append({
            'vulnerability_type': 'phishing_analysis_error',
            'severity': 'low',
            'description': 'Error analyzing email for phishing indicators',
            'details': str(e)
        })
        return results
