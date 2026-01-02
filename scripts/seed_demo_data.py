import os
from report import Reporter

def seed():
    """Generates demo scan results for immediate testing."""
    demo_results = [
        {"ip": "192.168.1.1", "port": 80, "service": "http", "banner": "Apache/2.4.41 (Ubuntu)", "status": "Open"},
        {"ip": "192.168.1.10", "port": 22, "service": "ssh", "banner": "OpenSSH 7.2p2 Ubuntu", "status": "Open"},
        {"ip": "192.168.1.15", "port": 3306, "service": "mysql", "banner": "5.7.29-0ubuntu0.18.04.1", "status": "Open"},
    ]
    
    if not os.path.exists('demo'):
        os.makedirs('demo')
        
    Reporter.to_csv(demo_results, "demo/example_scan.csv")
    Reporter.to_html(demo_results, "demo/example_scan.html")
    print("[*] Demo data seeded in /demo directory.")

if __name__ == "__main__":
    seed()
