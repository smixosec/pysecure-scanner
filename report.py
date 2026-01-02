import csv
import json
import os
from datetime import datetime
from typing import List, Dict, Any


class Reporter:
    """Handles report generation in multiple formats."""
    
    @staticmethod
    def to_csv(results: List[Dict[str, Any]], filename: str = None) -> str:
        """Export results to CSV file."""
        if not filename:
            filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        if not results:
            print("[!] No results to export")
            return filename
        
        # Get all possible keys
        all_keys = set()
        for result in results:
            all_keys.update(result.keys())
        
        keys = sorted(all_keys)
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                
                for result in results:
                    # Ensure all keys are present
                    row = {key: result.get(key, '') for key in keys}
                    writer.writerow(row)
            
            print(f"[+] CSV report saved: {filename}")
            return filename
            
        except Exception as e:
            print(f"[!] Failed to save CSV: {e}")
            return ""
    
    @staticmethod
    def to_html(results: List[Dict[str, Any]], filename: str = None) -> str:
        """Export results to HTML file."""
        if not filename:
            filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        if not results:
            print("[!] No results to export")
            return filename
        
        # Count statistics
        total_hosts = len(set(r.get('ip', '') for r in results))
        open_ports = len(results)
        
        # Count by risk level if available
        high_risk = sum(1 for r in results if r.get('risk') in ['High', 'Critical'])
        medium_risk = sum(1 for r in results if r.get('risk') == 'Medium')
        low_risk = sum(1 for r in results if r.get('risk') == 'Low')
        
        # Prepare rows
        rows = ""
        for idx, result in enumerate(results, 1):
            ip = result.get('ip', 'N/A')
            port = result.get('port', 'N/A')
            service = result.get('service', 'Unknown')
            banner = result.get('banner', 'No banner')
            status = result.get('status', 'Open')
            risk = result.get('risk', 'Unknown')
            
            # Truncate long banners
            if len(banner) > 100:
                banner = banner[:100] + "..."
            
            # Risk color coding
            risk_class = "risk-low"
            if risk == "High" or risk == "Critical":
                risk_class = "risk-high"
            elif risk == "Medium":
                risk_class = "risk-medium"
            
            rows += f"""
            <tr>
                <td>{idx}</td>
                <td>{ip}</td>
                <td>{port}</td>
                <td>{service}</td>
                <td>{banner}</td>
                <td>{status}</td>
                <td class="{risk_class}">{risk}</td>
            </tr>
            """
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PySecure Scan Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.8;
            margin-bottom: 20px;
        }}
        
        .metadata {{
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        .meta-item {{
            text-align: center;
            margin: 10px;
            min-width: 150px;
        }}
        
        .meta-value {{
            font-size: 1.8rem;
            font-weight: bold;
            color: #2c3e50;
        }}
        
        .meta-label {{
            font-size: 0.9rem;
            color: #7f8c8d;
            margin-top: 5px;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: white;
        }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border-left: 4px solid #3498db;
        }}
        
        .stat-card.high-risk {{
            border-left-color: #e74c3c;
        }}
        
        .stat-card.medium-risk {{
            border-left-color: #f39c12;
        }}
        
        .stat-card.low-risk {{
            border-left-color: #27ae60;
        }}
        
        .stat-value {{
            font-size: 2.5rem;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        
        .stat-label {{
            font-size: 1rem;
            color: #7f8c8d;
        }}
        
        .results {{
            padding: 30px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        th {{
            background: #2c3e50;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        tr:hover {{
            background-color: #f5f7fa;
        }}
        
        .risk-high {{
            color: #e74c3c;
            font-weight: bold;
            background-color: #ffe6e6;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        
        .risk-medium {{
            color: #f39c12;
            font-weight: bold;
            background-color: #fff3cd;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        
        .risk-low {{
            color: #27ae60;
            background-color: #d4edda;
            padding: 4px 8px;
            border-radius: 4px;
        }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #7f8c8d;
            border-top: 1px solid #e0e0e0;
        }}
        
        @media (max-width: 768px) {{
            .metadata {{
                flex-direction: column;
                align-items: center;
            }}
            
            th, td {{
                padding: 8px;
                font-size: 0.9rem;
            }}
            
            .header h1 {{
                font-size: 1.8rem;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 PySecure Scan Report</h1>
            <div class="subtitle">Professional Network Security Assessment</div>
            <div class="scan-date">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
        
        <div class="metadata">
            <div class="meta-item">
                <div class="meta-value">{total_hosts}</div>
                <div class="meta-label">Hosts Scanned</div>
            </div>
            <div class="meta-item">
                <div class="meta-value">{open_ports}</div>
                <div class="meta-label">Open Ports</div>
            </div>
            <div class="meta-item">
                <div class="meta-value">{high_risk}</div>
                <div class="meta-label">High Risk</div>
            </div>
            <div class="meta-item">
                <div class="meta-value">{medium_risk}</div>
                <div class="meta-label">Medium Risk</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card high-risk">
                <div class="stat-value">{high_risk}</div>
                <div class="stat-label">High Risk Ports</div>
            </div>
            <div class="stat-card medium-risk">
                <div class="stat-value">{medium_risk}</div>
                <div class="stat-label">Medium Risk Ports</div>
            </div>
            <div class="stat-card low-risk">
                <div class="stat-value">{low_risk}</div>
                <div class="stat-label">Low Risk Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(results)}</div>
                <div class="stat-label">Total Findings</div>
            </div>
        </div>
        
        <div class="results">
            <h2>Scan Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>IP Address</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Banner</th>
                        <th>Status</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Report generated by PySecure Scanner v2.0</p>
            <p>For security testing and network auditing purposes only</p>
            <p>© {datetime.now().strftime('%Y')} PySecure Team</p>
        </div>
    </div>
    
    <script>
        // Add interactivity
        document.addEventListener('DOMContentLoaded', function() {{
            // Sort table on header click
            const headers = document.querySelectorAll('th');
            headers.forEach((header, index) => {{
                header.style.cursor = 'pointer';
                header.addEventListener('click', () => sortTable(index));
            }});
            
            // Add row highlighting
            const rows = document.querySelectorAll('tbody tr');
            rows.forEach(row => {{
                row.addEventListener('click', function() {{
                    rows.forEach(r => r.classList.remove('selected'));
                    this.classList.add('selected');
                }});
            }});
            
            function sortTable(column) {{
                const table = document.querySelector('table');
                const tbody = table.querySelector('tbody');
                const rows = Array.from(tbody.querySelectorAll('tr'));
                
                const isNumeric = column === 0 || column === 2; // # and Port columns
                
                rows.sort((a, b) => {{
                    const aText = a.children[column].textContent.trim();
                    const bText = b.children[column].textContent.trim();
                    
                    if (isNumeric) {{
                        return parseInt(aText) - parseInt(bText);
                    }} else {{
                        return aText.localeCompare(bText);
                    }}
                }});
                
                // Clear and re-add sorted rows
                rows.forEach(row => tbody.appendChild(row));
            }}
        }});
    </script>
</body>
</html>
        """
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_template)
            
            print(f"[+] HTML report saved: {filename}")
            return filename
            
        except Exception as e:
            print(f"[!] Failed to save HTML report: {e}")
            return ""
    
    @staticmethod
    def to_json(results: List[Dict[str, Any]], filename: str = None) -> str:
        """Export results to JSON file."""
        if not filename:
            filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        if not results:
            print("[!] No results to export")
            return filename
        
        # Add metadata
        report_data = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "tool": "PySecure Scanner v2.0",
                "total_results": len(results),
                "total_hosts": len(set(r.get('ip', '') for r in results))
            },
            "results": results
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            print(f"[+] JSON report saved: {filename}")
            return filename
            
        except Exception as e:
            print(f"[!] Failed to save JSON report: {e}")
            return ""
    
    @staticmethod
    def generate_summary(results: List[Dict[str, Any]]) -> str:
        """Generate a text summary of results."""
        if not results:
            return "No results to summarize."
        
        summary = []
        summary.append("=" * 60)
        summary.append("PYSECURE SCAN SUMMARY")
        summary.append("=" * 60)
        summary.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"Total Results: {len(results)}")
        summary.append(f"Unique Hosts: {len(set(r.get('ip', '') for r in results))}")
        summary.append("")
        
        # Group by IP
        hosts = {}
        for result in results:
            ip = result.get('ip', 'Unknown')
            if ip not in hosts:
                hosts[ip] = []
            hosts[ip].append(result)
        
        # Add host summaries
        for ip, host_results in hosts.items():
            summary.append(f"Host: {ip}")
            summary.append("-" * 40)
            
            for result in host_results:
                port = result.get('port', 'N/A')
                service = result.get('service', 'Unknown')
                banner = result.get('banner', '')
                
                if banner and banner != "No banner detected":
                    banner_preview = banner[:50] + "..." if len(banner) > 50 else banner
                    summary.append(f"  Port {port}: {service} - {banner_preview}")
                else:
                    summary.append(f"  Port {port}: {service}")
            
            summary.append("")
        
        summary.append("=" * 60)
        
        return "\n".join(summary)


# Test function
if __name__ == "__main__":
    # Sample data for testing
    test_results = [
        {
            "ip": "127.0.0.1",
            "port": 80,
            "service": "HTTP",
            "banner": "Apache/2.4.41 (Ubuntu)",
            "status": "Open",
            "risk": "Low"
        },
        {
            "ip": "127.0.0.1",
            "port": 22,
            "service": "SSH",
            "banner": "SSH-2.0-OpenSSH_7.6p1",
            "status": "Open",
            "risk": "High"
        },
        {
            "ip": "192.168.1.1",
            "port": 443,
            "service": "HTTPS",
            "banner": "nginx/1.18.0",
            "status": "Open",
            "risk": "Low"
        }
    ]
    
    print("Testing Reporter class...")
    print("\n1. Testing CSV export:")
    csv_file = Reporter.to_csv(test_results, "test_report.csv")
    
    print("\n2. Testing HTML export:")
    html_file = Reporter.to_html(test_results, "test_report.html")
    
    print("\n3. Testing JSON export:")
    json_file = Reporter.to_json(test_results, "test_report.json")
    
    print("\n4. Testing summary generation:")
    summary = Reporter.generate_summary(test_results)
    print(summary)