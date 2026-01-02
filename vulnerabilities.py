import re
import socket
from typing import List, Dict, Tuple
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')


class VulnScanner:
    """Checks for common vulnerabilities in network services."""
    
    # Vulnerable version patterns
    VULNERABLE_VERSIONS = {
        'ssh': [
            ('OpenSSH_7.2', 'CVE-2018-15473: Username enumeration'),
            ('OpenSSH_7.1', 'Multiple vulnerabilities'),
            ('SSH-2.0-Cisco-', 'Potential Cisco vulnerabilities'),
        ],
        'apache': [
            ('Apache/2.2', 'End of life, multiple CVEs'),
            ('Apache/2.4.0', 'Old version with vulnerabilities'),
        ],
        'nginx': [
            ('nginx/1.10', 'Old version with vulnerabilities'),
            ('nginx/1.12', 'Multiple security issues'),
        ],
        'iis': [
            ('Microsoft-IIS/6.0', 'Multiple critical vulnerabilities'),
            ('Microsoft-IIS/7.0', 'Security improvements needed'),
        ],
        'ftp': [
            ('vsFTPd 2.3.4', 'Backdoor command execution'),
            ('ProFTPD 1.3.0', 'Multiple vulnerabilities'),
        ],
        'tomcat': [
            ('Apache-Coyote/1.1', 'Potential Tomcat vulnerabilities'),
        ],
        'mysql': [
            ('5.5.0', 'Old MySQL version'),
            ('5.6.0', 'Security updates available'),
        ]
    }
    
    # Common weak credentials to check
    COMMON_CREDENTIALS = {
        'ssh': [
            ('root', 'root'),
            ('admin', 'admin'),
            ('root', 'password'),
            ('root', '123456'),
            ('ubuntu', 'ubuntu'),
        ],
        'ftp': [
            ('anonymous', ''),
            ('ftp', 'ftp'),
            ('admin', 'admin'),
            ('test', 'test'),
        ],
        'telnet': [
            ('root', 'root'),
            ('admin', 'admin'),
        ],
        'mysql': [
            ('root', ''),
            ('root', 'root'),
            ('admin', 'admin'),
        ],
        'postgresql': [
            ('postgres', 'postgres'),
            ('admin', 'admin'),
        ]
    }
    
    # Services that commonly have default credentials
    WEAK_CREDENTIAL_SERVICES = {
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        3306: 'mysql',
        5432: 'postgresql',
        3389: 'rdp',
        5900: 'vnc'
    }
    
    @staticmethod
    def check_version_vulns(banner: str) -> List[str]:
        """Check for vulnerable software versions in banner."""
        findings = []
        
        if not banner:
            return findings
        
        banner_lower = banner.lower()
        
        # Check each vulnerable pattern
        for service, patterns in VulnScanner.VULNERABLE_VERSIONS.items():
            for pattern, description in patterns:
                if pattern.lower() in banner_lower:
                    findings.append(f"{service.upper()}: {description}")
        
        # Additional pattern matching
        # Check for PHP versions
        php_match = re.search(r'PHP/(\d+\.\d+\.\d+)', banner)
        if php_match:
            version = php_match.group(1)
            if version.startswith('5.') or version.startswith('7.0'):
                findings.append(f"PHP: Outdated version {version} - Multiple CVEs")
        
        # Check for WordPress
        if 'wordpress' in banner_lower:
            wp_match = re.search(r'wordpress[ /](\d+\.\d+\.\d+)', banner_lower)
            if wp_match:
                version = wp_match.group(1)
                if version.startswith('4.'):
                    findings.append(f"WordPress: Old version {version} - Security updates needed")
        
        return findings
    
    @staticmethod
    def check_weak_credentials(ip: str, port: int, service: str) -> List[str]:
        """Check for common weak credentials on a service."""
        findings = []
        
        # Map port to service type if service is unknown
        service_type = service.lower() if service != "Unknown" else ""
        
        if not service_type and port in VulnScanner.WEAK_CREDENTIAL_SERVICES:
            service_type = VulnScanner.WEAK_CREDENTIAL_SERVICES[port]
        
        # Check if this service type has common credentials
        if service_type in VulnScanner.COMMON_CREDENTIALS:
            findings.append(f"Common weak credentials check recommended for {service_type.upper()}")
        
        # Specific checks based on port
        if port == 21:  # FTP
            findings.append("FTP: Anonymous login often enabled")
            findings.append("FTP: Data transmitted in clear text")
        
        elif port == 22:  # SSH
            findings.append("SSH: Check for password authentication only")
            findings.append("SSH: Root login may be enabled")
        
        elif port == 23:  # Telnet
            findings.append("TELNET: All traffic unencrypted")
            findings.append("TELNET: Extremely insecure protocol")
        
        elif port == 80 or port == 443:  # HTTP/HTTPS
            if service == "HTTP" and port == 80:
                findings.append("HTTP: Traffic not encrypted")
            
            # Common web vulnerabilities
            findings.append("WEB: Check for default admin pages")
            findings.append("WEB: Directory listing may be enabled")
        
        elif port == 445:  # SMB
            findings.append("SMB: Check for SMBv1 (EternalBlue vulnerability)")
            findings.append("SMB: Null session may be enabled")
        
        elif port == 3389:  # RDP
            findings.append("RDP: Check for BlueKeep vulnerability (CVE-2019-0708)")
            findings.append("RDP: NLA may be disabled")
        
        elif port == 5900:  # VNC
            findings.append("VNC: Often has no password or weak password")
            findings.append("VNC: Traffic may be unencrypted")
        
        elif port == 27017:  # MongoDB
            findings.append("MongoDB: Often has no authentication by default")
        
        elif port == 6379:  # Redis
            findings.append("Redis: Often has no authentication by default")
        
        return findings
    
    @staticmethod
    def check_ssl_tls(ip: str, port: int) -> List[str]:
        """Check SSL/TLS configuration."""
        findings = []
        
        if port not in [443, 8443, 9443]:
            return findings
        
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((ip, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate
                    if not cert:
                        findings.append("SSL/TLS: No certificate presented")
                    
                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        if 'RC4' in cipher_name or 'DES' in cipher_name or '3DES' in cipher_name:
                            findings.append(f"SSL/TLS: Weak cipher {cipher_name}")
                        
                        if 'NULL' in cipher_name or 'ANON' in cipher_name:
                            findings.append(f"SSL/TLS: Insecure cipher {cipher_name}")
                    
                    # Check protocol version
                    version = ssock.version()
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append(f"SSL/TLS: Deprecated protocol {version}")
        
        except ssl.SSLError as e:
            findings.append(f"SSL/TLS Error: {str(e)}")
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def check_http_security_headers(ip: str, port: int) -> List[str]:
        """Check for missing security headers on HTTP services."""
        findings = []
        
        if port not in [80, 443, 8080, 8443]:
            return findings
        
        try:
            import requests
            from requests.exceptions import RequestException
            
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{ip}:{port}"
            
            try:
                response = requests.get(url, timeout=5, verify=False)
                
                # Check security headers
                security_headers = [
                    'Strict-Transport-Security',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Content-Security-Policy',
                    'X-XSS-Protection'
                ]
                
                for header in security_headers:
                    if header not in response.headers:
                        findings.append(f"HTTP: Missing security header {header}")
                
                # Check server header
                if 'Server' in response.headers:
                    server = response.headers['Server']
                    findings.append(f"HTTP: Server header exposes {server}")
                
                # Check for directory listing
                if "Index of /" in response.text:
                    findings.append("HTTP: Directory listing enabled")
                
            except RequestException:
                pass
        
        except ImportError:
            findings.append("Note: Install 'requests' library for HTTP security checks")
        except Exception:
            pass
        
        return findings
    
    @staticmethod
    def scan_service(ip: str, port: int, service: str, banner: str) -> Dict[str, List[str]]:
        """Perform comprehensive vulnerability scan on a service."""
        results = {
            'version_vulns': [],
            'weak_credentials': [],
            'ssl_tls': [],
            'http_security': [],
            'recommendations': []
        }
        
        # Check version vulnerabilities
        results['version_vulns'] = VulnScanner.check_version_vulns(banner)
        
        # Check for weak credentials
        results['weak_credentials'] = VulnScanner.check_weak_credentials(ip, port, service)
        
        # SSL/TLS checks for HTTPS services
        if port in [443, 8443, 9443]:
            results['ssl_tls'] = VulnScanner.check_ssl_tls(ip, port)
        
        # HTTP security headers check
        if port in [80, 443, 8080, 8443]:
            results['http_security'] = VulnScanner.check_http_security_headers(ip, port)
        
        # Generate recommendations
        recommendations = []
        
        if results['version_vulns']:
            recommendations.append("Update software to latest version")
        
        if results['weak_credentials']:
            recommendations.append("Implement strong password policy")
            recommendations.append("Disable unused authentication methods")
        
        if port == 21:  # FTP
            recommendations.append("Use SFTP or FTPS instead of FTP")
            recommendations.append("Disable anonymous login")
        
        if port == 22:  # SSH
            recommendations.append("Use key-based authentication")
            recommendations.append("Disable root login")
            recommendations.append("Change default SSH port")
        
        if port == 23:  # Telnet
            recommendations.append("Disable Telnet and use SSH")
        
        if port == 80:  # HTTP
            recommendations.append("Redirect HTTP to HTTPS")
        
        if port in [445, 139]:  # SMB
            recommendations.append("Disable SMBv1")
            recommendations.append("Require SMB signing")
        
        if port == 3389:  # RDP
            recommendations.append("Enable Network Level Authentication")
            recommendations.append("Restrict RDP access by IP")
        
        results['recommendations'] = recommendations
        
        return results
    
    @staticmethod
    def get_risk_level(findings: Dict[str, List[str]]) -> str:
        """Calculate risk level based on findings."""
        total_findings = sum(len(v) for v in findings.values())
        
        # Count critical findings
        critical_indicators = [
            'CVE-', 'EternalBlue', 'BlueKeep', 'vsFTPd 2.3.4',
            'anonymous login', 'unencrypted', 'no authentication',
            'SSLv2', 'SSLv3', 'NULL cipher', 'ANON cipher'
        ]
        
        critical_count = 0
        for category in findings.values():
            for finding in category:
                if any(indicator in finding.lower() for indicator in critical_indicators):
                    critical_count += 1
        
        if critical_count > 0:
            return "Critical"
        elif total_findings > 5:
            return "High"
        elif total_findings > 2:
            return "Medium"
        elif total_findings > 0:
            return "Low"
        else:
            return "None"


# Test the vulnerability scanner
if __name__ == "__main__":
    print("Testing Vulnerability Scanner...\n")
    
    # Test cases
    test_cases = [
        ("192.168.1.1", 22, "SSH", "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8"),
        ("192.168.1.1", 80, "HTTP", "Apache/2.2.22 (Ubuntu)"),
        ("192.168.1.1", 443, "HTTPS", ""),
        ("192.168.1.1", 21, "FTP", "220 vsFTPd 2.3.4"),
        ("192.168.1.1", 3389, "RDP", ""),
    ]
    
    for ip, port, service, banner in test_cases:
        print(f"\nScanning {ip}:{port} ({service})")
        print(f"Banner: {banner}")
        print("-" * 50)
        
        results = VulnScanner.scan_service(ip, port, service, banner)
        risk = VulnScanner.get_risk_level(results)
        
        print(f"Risk Level: {risk}")
        
        for category, findings in results.items():
            if findings:
                print(f"\n{category.replace('_', ' ').title()}:")
                for finding in findings:
                    print(f"  • {finding}")
        
        print()


# Create requirements.txt with actual dependencies
with open("requirements.txt", "w") as f:
    f.write("""# PySecure Scanner Dependencies
# Core dependencies
python>=3.8

# Optional dependencies for enhanced features
# requests>=2.31.0  # For HTTP security checks
# paramiko>=3.4.0   # For SSH testing
# cryptography>=41.0.0  # For SSL/TLS checks

# Install with: pip install -r requirements.txt
""")

print("Created requirements.txt")