import logging
import socket
import re
import concurrent.futures
import time
import ssl
import subprocess
from urllib.parse import urlparse

def scan_infrastructure(target_host, port_scan=True, service_scan=True):
    """
    Scan infrastructure for vulnerabilities
    
    Args:
        target_host (str): The hostname or IP to scan
        port_scan (bool): Whether to perform a port scan
        service_scan (bool): Whether to perform service identification
    
    Returns:
        list: List of vulnerability results
    """
    logging.info(f"Starting infrastructure scan for {target_host}")
    results = []
    
    try:
        # Clean up the target host (remove protocol if present)
        if '://' in target_host:
            parsed = urlparse(target_host)
            target_host = parsed.netloc
        
        # Get IP address for hostname
        try:
            ip_address = socket.gethostbyname(target_host)
        except socket.gaierror:
            results.append({
                'vulnerability_type': 'dns_resolution_error',
                'severity': 'low',
                'description': 'Unable to resolve hostname',
                'details': f"Could not resolve the hostname {target_host} to an IP address. This could indicate a DNS issue or a non-existent domain."
            })
            return results
        
        # Basic information gathering
        results.append({
            'vulnerability_type': 'information',
            'severity': 'low',
            'description': 'Infrastructure information',
            'details': f"Target: {target_host}, IP Address: {ip_address}"
        })
        
        # Perform port scan if requested
        if port_scan:
            port_results = scan_common_ports(ip_address)
            results.extend(port_results)
        
        # Perform service identification if requested
        if service_scan and port_scan:
            # Extract open ports from the port scan results
            open_ports = []
            for result in port_results:
                if 'open port' in result['vulnerability_type']:
                    port_num = int(re.search(r'\d+', result['vulnerability_type']).group())
                    open_ports.append(port_num)
            
            if open_ports:
                service_results = identify_services(ip_address, open_ports)
                results.extend(service_results)
        
        # Check for SSL/TLS vulnerabilities if 443 is open
        if port_scan and any(result.get('vulnerability_type') == 'open_port_443' for result in port_results):
            ssl_results = check_ssl_vulnerabilities(target_host)
            results.extend(ssl_results)
        
        logging.info(f"Completed infrastructure scan. Found {len(results)} potential vulnerabilities.")
        return results
    
    except Exception as e:
        logging.error(f"Error scanning infrastructure {target_host}: {e}")
        results.append({
            'vulnerability_type': 'scan_error',
            'severity': 'low',
            'description': 'An error occurred during the infrastructure scan',
            'details': str(e)
        })
        return results


def scan_common_ports(ip_address):
    """Scan common ports to identify open services"""
    results = []
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    
    open_ports = []
    
    # Use ThreadPoolExecutor for parallel port scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # Create a dictionary mapping future objects to their corresponding ports
        future_to_port = {executor.submit(is_port_open, ip_address, port): port for port in common_ports}
        
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    service_name = common_ports[port]
                    
                    # Determine severity based on the service
                    severity = 'medium'  # Default severity
                    if port in [23, 135, 445]:  # Particularly risky services
                        severity = 'high'
                    elif port in [22, 443, 993, 995]:  # Usually secure services
                        severity = 'low'
                    
                    results.append({
                        'vulnerability_type': f'open_port_{port}',
                        'severity': severity,
                        'description': f'Open port: {port}/{service_name}',
                        'details': f"The port {port} ({service_name}) is open on {ip_address}. This service may provide an attack vector if not properly secured."
                    })
            except Exception as e:
                logging.error(f"Error scanning port {port}: {e}")
    
    # If no open ports were found, add a note
    if not open_ports:
        results.append({
            'vulnerability_type': 'no_open_ports',
            'severity': 'low',
            'description': 'No open ports found',
            'details': f"No open ports were found on the common port list. This could indicate strong security or a firewall blocking the scan."
        })
    
    return results


def is_port_open(ip_address, port):
    """Check if a specific port is open"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)  # Short timeout for efficiency
    
    try:
        result = sock.connect_ex((ip_address, port))
        return result == 0  # 0 means connection successful (port is open)
    except:
        return False
    finally:
        sock.close()


def identify_services(ip_address, open_ports):
    """Attempt to identify services running on open ports"""
    results = []
    
    for port in open_ports:
        # Attempt banner grabbing
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((ip_address, port))
                
                # Send a benign request
                if port == 80 or port == 8080:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 21:
                    pass  # FTP servers usually send a banner upon connection
                elif port == 22:
                    pass  # SSH servers usually send a banner upon connection
                elif port == 25 or port == 587:
                    pass  # SMTP servers usually send a banner upon connection
                else:
                    # For unknown services, try a generic request
                    s.send(b"\r\n")
                
                # Wait for response
                banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                
                if banner:
                    # Look for version information
                    version_match = re.search(r'[0-9]+\.[0-9]+\.[0-9]+', banner)
                    version = version_match.group(0) if version_match else "unknown"
                    
                    # Check for known vulnerable versions (example)
                    is_vulnerable = False
                    vulnerability_details = ""
                    
                    # Example checks - in a real-world scenario, this would be more comprehensive
                    if "Apache" in banner and version.startswith("2.4."):
                        if float(version.split('.')[1]) < 49:  # Apache < 2.4.49
                            is_vulnerable = True
                            vulnerability_details = f"Apache {version} may be vulnerable to path traversal (CVE-2021-41773)"
                    elif "OpenSSH" in banner and version.startswith("7."):
                        if float(version.split('.')[1]) < 6:  # OpenSSH < 7.6
                            is_vulnerable = True
                            vulnerability_details = f"OpenSSH {version} may be vulnerable to username enumeration"
                    
                    if is_vulnerable:
                        results.append({
                            'vulnerability_type': 'vulnerable_service',
                            'severity': 'high',
                            'description': f'Potentially vulnerable service on port {port}',
                            'details': f"Service banner: {banner}\n{vulnerability_details}"
                        })
                    else:
                        results.append({
                            'vulnerability_type': 'service_identification',
                            'severity': 'low',
                            'description': f'Service identified on port {port}',
                            'details': f"Service banner: {banner}"
                        })
        except Exception as e:
            logging.debug(f"Could not identify service on port {port}: {e}")
    
    return results


def check_ssl_vulnerabilities(hostname):
    """Check for SSL/TLS vulnerabilities"""
    results = []
    
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect to the server
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate info
                cert = ssock.getpeercert(binary_form=True)
                if not cert:
                    results.append({
                        'vulnerability_type': 'invalid_ssl_cert',
                        'severity': 'high',
                        'description': 'Invalid SSL certificate',
                        'details': "The server presented an invalid or unrecognized SSL certificate."
                    })
                    return results
                
                # Check SSL version
                version = ssock.version()
                
                if version == "TLSv1" or version == "TLSv1.1" or version == "SSLv3" or version == "SSLv2":
                    results.append({
                        'vulnerability_type': 'outdated_ssl_protocol',
                        'severity': 'high',
                        'description': 'Outdated SSL/TLS protocol in use',
                        'details': f"The server is using an outdated and insecure protocol: {version}"
                    })
                
                # Get certificate details
                try:
                    cert_info = ssl._ssl._test_decode_cert(cert)
                    
                    # Check certificate expiration
                    not_after = cert_info.get('notAfter', '')
                    if not_after:
                        import datetime
                        # Format is usually like: 'Sep 15 12:00:00 2023 GMT'
                        expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        now = datetime.datetime.utcnow()
                        
                        if expiry < now:
                            results.append({
                                'vulnerability_type': 'expired_ssl_cert',
                                'severity': 'high',
                                'description': 'Expired SSL certificate',
                                'details': f"The SSL certificate expired on {not_after}"
                            })
                        elif (expiry - now).days < 30:
                            results.append({
                                'vulnerability_type': 'expiring_ssl_cert',
                                'severity': 'medium',
                                'description': 'SSL certificate expiring soon',
                                'details': f"The SSL certificate will expire on {not_after}"
                            })
                    
                    # Check if certificate is self-signed
                    issuer = cert_info.get('issuer', {})
                    subject = cert_info.get('subject', {})
                    
                    if issuer == subject:
                        results.append({
                            'vulnerability_type': 'self_signed_cert',
                            'severity': 'high',
                            'description': 'Self-signed SSL certificate',
                            'details': "The server is using a self-signed certificate, which browsers will not trust."
                        })
                except Exception as e:
                    logging.error(f"Error decoding certificate: {e}")
        
        # Check for weak cipher suites (would normally use a tool like OpenSSL or sslyze)
        # For demonstration, we'll just add a placeholder
        results.append({
            'vulnerability_type': 'information',
            'severity': 'low',
            'description': 'SSL/TLS Information',
            'details': f"SSL/TLS protocol version: {version}. For a complete cipher suite analysis, we would need to use specialized tools like OpenSSL or sslyze."
        })
        
        return results
    
    except ssl.SSLError as e:
        results.append({
            'vulnerability_type': 'ssl_error',
            'severity': 'high',
            'description': 'SSL/TLS connection error',
            'details': f"Error establishing SSL connection: {str(e)}"
        })
        return results
    except socket.error as e:
        results.append({
            'vulnerability_type': 'connection_error',
            'severity': 'medium',
            'description': 'Connection error on port 443',
            'details': f"Error connecting to port 443: {str(e)}"
        })
        return results
    except Exception as e:
        logging.error(f"Error checking SSL: {e}")
        results.append({
            'vulnerability_type': 'ssl_check_error',
            'severity': 'low',
            'description': 'Error checking SSL/TLS configuration',
            'details': str(e)
        })
        return results
