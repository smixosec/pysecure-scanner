#!/usr/bin/env python3
"""
PySecure Scanner - Main Entry Point
Fixed for PyInstaller compatibility
"""

import sys
import os

# Fix for PyInstaller stdin issue on Windows
if sys.platform == 'win32' and sys.stdin is None:
    sys.stdin = open(os.devnull, 'r')

def main():
    """Main entry point"""
    try:
        # Check for GUI mode
        if '--gui' in sys.argv or len(sys.argv) == 1:
            # Launch GUI
            import tkinter as tk
            from gui import PySecureGUI
            
            root = tk.Tk()
            app = PySecureGUI(root)
            root.mainloop()
            
        else:
            # CLI mode
            import argparse
            from scanner import ScannerEngine
            from report import Reporter
            from vulnerabilities import VulnScanner
            
            parser = argparse.ArgumentParser(
                description='PySecure Scanner - Professional Network Security Tool'
            )
            parser.add_argument('--target', '-t', required=True,
                              help='Target IP or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)')
            parser.add_argument('--ports', '-p', default='21,22,23,25,53,80,110,443,3306,5432,8080',
                              help='Ports to scan (comma-separated or range)')
            parser.add_argument('--report', '-r', choices=['csv', 'html', 'json'],
                              help='Generate report in specified format')
            parser.add_argument('--gui', '-g', action='store_true',
                              help='Launch Graphical User Interface')
            parser.add_argument('--vuln', '-v', action='store_true',
                              help='Enable vulnerability scanning')
            parser.add_argument('--threads', '-n', type=int, default=30,
                              help='Number of threads (default: 30)')
            parser.add_argument('--timeout', '-to', type=float, default=2.0,
                              help='Connection timeout in seconds')
            
            args = parser.parse_args()
            
            # Parse ports
            ports = []
            if '-' in args.ports:
                start, end = map(int, args.ports.split('-'))
                ports = list(range(start, end + 1))
            else:
                ports = [int(p.strip()) for p in args.ports.split(',')]
            
            # Run scan
            print(f"[*] Scanning {args.target}...")
            scanner = ScannerEngine(args.target, ports=ports, threads=args.threads)
            results = scanner.run()
            
            if args.vuln:
                print("[*] Checking vulnerabilities...")
                for res in results:
                    res['vulns'] = VulnScanner.check_weak_credentials(res['ip'], res['port'], res['service'])
                    res['vulns'].extend(VulnScanner.check_version_vulns(res['banner']))
            
            # Generate report or display results
            if args.report:
                if args.report == 'csv':
                    Reporter.to_csv(results)
                elif args.report == 'html':
                    Reporter.to_html(results)
                elif args.report == 'json':
                    import json
                    with open('scan_report.json', 'w') as f:
                        json.dump(results, f, indent=2)
                print(f"[+] Report generated: scan_report.{args.report}")
            else:
                # Print results to console
                print(f"\n[*] Found {len(results)} open port(s):")
                print("-" * 60)
                for r in results:
                    vuln_text = ""
                    if args.vuln and r.get('vulns'):
                        vuln_text = f" | VULNS: {', '.join(r['vulns'])}"
                    print(f"{r['ip']}:{r['port']} - {r['service']}{vuln_text}")
                print("-" * 60)
                
    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()  