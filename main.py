import argparse
import sys
import os
from datetime import datetime
from scanner import ScannerEngine
from report import Reporter
from vulnerabilities import VulnScanner
from gui import PySecureGUI
import tkinter as tk


def validate_target(target):
    """Validate target input"""
    try:
        if "/" in target:
            import ipaddress
            ipaddress.ip_network(target, strict=False)
            return True
        elif target.replace(".", "").isdigit():
            parts = target.split(".")
            if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                return True
        return target in ["localhost", "127.0.0.1"]
    except:
        return False


def parse_ports(port_str):
    """Parse port string into list"""
    ports = []
    parts = port_str.replace(" ", "").split(",")
    
    for part in parts:
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                ports.extend(range(start, end + 1))
            except:
                raise ValueError(f"Invalid range: {part}")
        else:
            try:
                ports.append(int(part))
            except:
                raise ValueError(f"Invalid port: {part}")
    
    # Remove duplicates, sort, and validate
    ports = sorted(set(p for p in ports if 1 <= p <= 65535))
    return ports


def run_cli_scan(args):
    """Run scan from command line"""
    print(f"\n{'='*60}")
    print("PySecure Scanner - Command Line Mode")
    print(f"{'='*60}\n")
    
    if not validate_target(args.target):
        print(f"[ERROR] Invalid target: {args.target}")
        return
    
    try:
        ports = parse_ports(args.ports) if args.ports else None
    except ValueError as e:
        print(f"[ERROR] {e}")
        return
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Ports: {len(ports) if ports else 'Default'}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Timeout: {args.timeout}s")
    print(f"[*] Banner grab: {'Yes' if args.banner else 'No'}")
    print(f"[*] Vuln scan: {'Yes' if args.vuln else 'No'}")
    print("-" * 60)
    
    try:
        scanner = ScannerEngine(
            targets=args.target,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
            banner_grab=args.banner
        )
        
        print("[*] Starting scan...")
        results = scanner.run()
        
        if not results:
            print("[*] No open ports found.")
            return
        
        # Vulnerability scanning if enabled
        if args.vuln:
            print("[*] Checking for vulnerabilities...")
            for result in results:
                result['vulns'] = VulnScanner.check_weak_credentials(
                    result['ip'], result['port'], result['service']
                )
                result['vulns'].extend(VulnScanner.check_version_vulns(result['banner']))
        
        print(f"\n[*] Found {len(results)} open port(s):")
        print("-" * 80)
        
        # Display results
        for idx, r in enumerate(results, 1):
            status = "OPEN"
            vuln_text = ""
            
            if args.vuln and r.get('vulns'):
                vuln_text = f" | VULNS: {', '.join(r['vulns'])}"
                status = "VULNERABLE"
            
            print(f"[{idx:3}] {r['ip']:15}:{r['port']:<5} {r['service']:12} {status:12}{vuln_text}")
            
            if r['banner'] and r['banner'] != "No banner detected":
                print(f"      Banner: {r['banner'][:80]}")
        
        print("-" * 80)
        
        # Generate report if requested
        if args.report:
            if args.report == 'csv':
                filename = Reporter.to_csv(results)
                print(f"[+] CSV report saved: {filename}")
            elif args.report == 'html':
                filename = Reporter.to_html(results)
                print(f"[+] HTML report saved: {filename}")
            elif args.report == 'json':
                filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                import json
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"[+] JSON report saved: {filename}")
            elif args.report == 'txt':
                filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(filename, 'w') as f:
                    f.write(f"PySecure Scan Report\n")
                    f.write(f"{'='*50}\n")
                    f.write(f"Target: {args.target}\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Open Ports: {len(results)}\n\n")
                    
                    for r in results:
                        f.write(f"IP: {r['ip']}:{r['port']}\n")
                        f.write(f"Service: {r['service']}\n")
                        f.write(f"Banner: {r.get('banner', 'N/A')}\n")
                        if args.vuln and r.get('vulns'):
                            f.write(f"Vulnerabilities: {', '.join(r['vulns'])}\n")
                        f.write(f"{'-'*40}\n")
                
                print(f"[+] Text report saved: {filename}")
        
        # Summary
        print(f"\n[*] Scan complete.")
        print(f"[*] Total hosts: {len(set(r['ip'] for r in results))}")
        print(f"[*] Open ports: {len(results)}")
        
        if args.vuln:
            vuln_count = sum(len(r.get('vulns', [])) for r in results)
            print(f"[*] Vulnerabilities found: {vuln_count}")
    
    except KeyboardInterrupt:
        print("\n\n[*] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="PySecure Scanner - Professional Network Security Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.1
  %(prog)s --target 192.168.1.0/24 --ports 1-1000
  %(prog)s --target example.com --ports 80,443 --report html
  %(prog)s --gui
        """
    )
    
    # Target arguments
    parser.add_argument("--target", "-t", 
                       help="Target IP, CIDR, or hostname (e.g., 192.168.1.1 or 192.168.1.0/24)")
    
    # Scan options
    parser.add_argument("--ports", "-p", 
                       help="Ports to scan (e.g., '80,443' or '1-1000')")
    parser.add_argument("--threads", "-n", type=int, default=30,
                       help="Number of threads (default: 30)")
    parser.add_argument("--timeout", "-to", type=float, default=2.0,
                       help="Connection timeout in seconds (default: 2.0)")
    
    # Features
    parser.add_argument("--banner", "-b", action="store_true",
                       help="Enable banner grabbing")
    parser.add_argument("--vuln", "-v", action="store_true",
                       help="Enable vulnerability scanning")
    
    # Output
    parser.add_argument("--report", "-r", 
                       choices=['csv', 'html', 'json', 'txt'],
                       help="Generate report in specified format")
    parser.add_argument("--output", "-o",
                       help="Output filename for report")
    
    # GUI mode
    parser.add_argument("--gui", "-g", action="store_true",
                       help="Launch Graphical User Interface")
    
    # Verbose mode
    parser.add_argument("--verbose", "-V", action="store_true",
                       help="Verbose output")
    
    args = parser.parse_args()
    
    # Check if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help()
        choice = input("\nLaunch GUI? (y/n): ").strip().lower()
        if choice == 'y':
            args.gui = True
        else:
            return
    
    # GUI mode
    if args.gui:
        try:
            root = tk.Tk()
            app = PySecureGUI(root)
            root.mainloop()
        except KeyboardInterrupt:
            print("\n[*] Application closed.")
        except Exception as e:
            print(f"[ERROR] Failed to launch GUI: {e}")
            sys.exit(1)
    
    # CLI mode
    elif args.target:
        run_cli_scan(args)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()