import socket
import threading
import ipaddress
import time
from typing import List, Dict, Any, Optional
import select


class ScannerEngine:
    """Core engine for network scanning and service detection."""
    
    def __init__(self, 
                 targets: str, 
                 ports: List[int] = None, 
                 threads: int = 30,
                 timeout: float = 2.0,
                 banner_grab: bool = True):
        
        self.targets = self.parse_targets(targets)
        self.ports = ports or self.get_default_ports()
        self.threads = min(threads, 200)  # Cap threads
        self.timeout = timeout
        self.banner_grab = banner_grab
        
        self.results = []
        self.lock = threading.Lock()
        self.scanning = True
        self.scanned_count = 0
        self.total_tasks = 0
    
    def get_default_ports(self) -> List[int]:
        """Get default ports to scan"""
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            6379,  # Redis
            8080,  # HTTP Proxy
            8443,  # HTTPS Alt
            27017, # MongoDB
        ]
        return common_ports
    
    def parse_targets(self, target_str: str) -> List[str]:
        """Parse IP addresses or subnets into a list of individual IPs."""
        targets = []
        
        try:
            # Check if it's a CIDR
            if "/" in target_str:
                network = ipaddress.ip_network(target_str, strict=False)
                # Limit to reasonable number of hosts
                hosts = list(network.hosts())
                if len(hosts) > 1000:
                    print(f"[!] Large network detected ({len(hosts)} hosts). Limiting to first 1000.")
                    hosts = hosts[:1000]
                targets = [str(ip) for ip in hosts]
            else:
                # Single IP or hostname
                targets = [target_str]
                
        except ValueError as e:
            print(f"[!] Invalid target format '{target_str}': {e}")
        except Exception as e:
            print(f"[!] Error parsing targets: {e}")
        
        return targets
    
    def get_service_name(self, port: int) -> str:
        """Get service name for a port."""
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB",
        }
        return common_services.get(port, "Unknown")
    
    def grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempt to grab banner from service."""
        banners = {
            21: b"\r\n",  # FTP
            22: b"SSH-2.0-Client\r\n",  # SSH
            25: b"EHLO example.com\r\n",  # SMTP
            80: b"GET / HTTP/1.0\r\n\r\n",  # HTTP
            110: b"USER test\r\n",  # POP3
            143: b"a001 LOGIN test test\r\n",  # IMAP
            443: b"GET / HTTP/1.0\r\n\r\n",  # HTTPS
        }
        
        try:
            # Send probe if we have one
            if port in banners:
                sock.sendall(banners[port])
            
            # Try to receive data
            sock.settimeout(1.0)
            ready = select.select([sock], [], [], 0.5)
            if ready[0]:
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:200]  # Limit banner length
                
        except (socket.timeout, socket.error, UnicodeDecodeError):
            pass
        
        return ""
    
    def scan_port(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single port."""
        if not self.scanning:
            return None
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Try to connect
            result = sock.connect_ex((ip, port))
            
            if result == 0:  # Port is open
                service = self.get_service_name(port)
                banner = ""
                
                # Grab banner if enabled
                if self.banner_grab:
                    banner = self.grab_banner(sock, port)
                
                sock.close()
                
                return {
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "banner": banner if banner else "No banner detected",
                    "status": "Open",
                    "timestamp": time.time()
                }
            
            sock.close()
            
        except socket.error:
            pass
        except Exception:
            pass
        
        return None
    
    def worker(self, task_queue: List[tuple]):
        """Worker thread function."""
        for ip, port in task_queue:
            if not self.scanning:
                break
            
            result = self.scan_port(ip, port)
            
            if result:
                with self.lock:
                    self.results.append(result)
            
            # Update progress
            with self.lock:
                self.scanned_count += 1
    
    def run(self) -> List[Dict[str, Any]]:
        """Execute the scan."""
        if not self.targets:
            print("[!] No valid targets to scan")
            return []
        
        print(f"[*] Starting scan on {len(self.targets)} target(s)")
        print(f"[*] Scanning {len(self.ports)} port(s) per target")
        print(f"[*] Using {self.threads} threads")
        print(f"[*] Timeout: {self.timeout}s")
        print("-" * 50)
        
        # Create task list
        tasks = [(ip, port) for ip in self.targets for port in self.ports]
        self.total_tasks = len(tasks)
        self.scanned_count = 0
        
        # Distribute tasks among threads
        chunk_size = max(1, len(tasks) // self.threads)
        threads = []
        
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            thread = threading.Thread(target=self.worker, args=(chunk,))
            threads.append(thread)
            thread.start()
        
        # Show progress (in CLI mode)
        if __name__ != "__main__" or "gui" not in __file__:
            self.show_progress(threads)
        else:
            # Wait for all threads in GUI mode
            for thread in threads:
                thread.join()
        
        print(f"\n[*] Scan complete. Found {len(self.results)} open port(s)")
        return self.results
    
    def show_progress(self, threads):
        """Show progress bar in CLI mode."""
        try:
            while any(t.is_alive() for t in threads):
                time.sleep(0.5)
                
                with self.lock:
                    scanned = self.scanned_count
                    total = self.total_tasks
                
                if total > 0:
                    percent = (scanned / total) * 100
                    bar_length = 30
                    filled = int(bar_length * scanned // total)
                    bar = "█" * filled + "░" * (bar_length - filled)
                    
                    print(f"\r[*] Progress: [{bar}] {percent:.1f}% ({scanned}/{total})", 
                          end="", flush=True)
            
            print()  # New line after progress bar
            
        except KeyboardInterrupt:
            print("\n\n[*] Stopping scan...")
            self.scanning = False
            
            # Wait for threads to finish
            for thread in threads:
                thread.join(timeout=1.0)
    
    def stop(self):
        """Stop the scan."""
        self.scanning = False


# CLI testing
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        ports = [int(p) for p in sys.argv[2].split(",")] if len(sys.argv) > 2 else None
        
        scanner = ScannerEngine(target, ports=ports, threads=20)
        results = scanner.run()
        
        print(f"\nResults ({len(results)} open ports):")
        for r in results:
            print(f"  {r['ip']}:{r['port']} - {r['service']}")
    else:
        print("Usage: python scanner.py <target> [ports]")
        print("Example: python scanner.py 127.0.0.1 80,443,8080")