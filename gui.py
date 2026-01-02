import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import os
import json
import webbrowser
from datetime import datetime
import socket
import ipaddress
from scanner import ScannerEngine
from report import Reporter
from vulnerabilities import VulnScanner


class PySecureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PySecure Scanner v2.0")
        self.root.geometry("1100x750")
        
        # Icon and theme
        try:
            self.root.iconbitmap('icon.ico')
        except:
            pass
        
        self.root.configure(bg='#f8f9fa')
        
        # State
        self.result_queue = queue.Queue()
        self.scanning = False
        self.results = []
        self.scan_thread = None
        self.scan_start_time = None
        
        # Load config
        self.config = self.load_config()
        
        # Setup
        self.setup_styles()
        self.create_menu()
        self.create_widgets()
        
        # Start queue processor
        self.root.after(100, self.process_queue)
        
    def load_config(self):
        """Load configuration from file"""
        default_config = {
            "default_target": "127.0.0.1",
            "default_ports": "21,22,23,25,53,80,110,443,3306,5432,8080,8443",
            "timeout": 2,
            "threads": 30,
            "banner_grab": True,
            "vuln_scan": False,
            "save_reports": True,
            "dark_mode": False,
            "recent_targets": []
        }
        
        try:
            if os.path.exists("config.json"):
                with open("config.json", "r") as f:
                    loaded = json.load(f)
                    default_config.update(loaded)
        except Exception:
            pass
            
        return default_config
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open("config.json", "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception:
            pass
    
    def setup_styles(self):
        """Configure styles for widgets"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Colors
        bg_color = '#2c3e50' if self.config['dark_mode'] else '#f8f9fa'
        fg_color = '#ecf0f1' if self.config['dark_mode'] else '#2c3e50'
        
        self.root.configure(bg=bg_color)
        
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'),
                       background=bg_color, foreground=fg_color)
        style.configure('Subtitle.TLabel', font=('Segoe UI', 10),
                       background=bg_color, foreground='#7f8c8d')
        style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'),
                       background='#3498db', foreground='white')
        
        # Treeview styling
        style.configure("Treeview.Heading",
                       font=('Segoe UI', 10, 'bold'),
                       background='#34495e',
                       foreground='white',
                       relief='flat')
        style.configure("Treeview",
                       font=('Segoe UI', 9),
                       rowheight=25,
                       background='white',
                       fieldbackground='white')
        style.map("Treeview", background=[('selected', '#3498db')])
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load Results...", command=self.load_results)
        file_menu.add_command(label="Save Results...", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="Quick Scan", command=self.quick_scan)
        scan_menu.add_command(label="Full Scan", command=self.full_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Stop Scan", command=self.stop_scan)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Port Checker", command=self.port_checker)
        tools_menu.add_command(label="Host Discovery", command=self.host_discovery)
        tools_menu.add_command(label="Vulnerability Scan", command=self.vuln_scan)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_docs)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main container
        main_frame = tk.Frame(self.root, bg='#f8f9fa', padx=15, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = tk.Frame(main_frame, bg='#f8f9fa')
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(header_frame, text="🔒 PySecure Scanner",
                font=('Segoe UI', 24, 'bold'),
                bg='#f8f9fa',
                fg='#2c3e50').pack(side=tk.LEFT)
        
        tk.Label(header_frame, text="Professional Network Security Tool",
                font=('Segoe UI', 10),
                bg='#f8f9fa',
                fg='#7f8c8d').pack(side=tk.LEFT, padx=(10, 0), pady=4)
        
        # Scan Configuration Panel
        config_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding=12)
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Target row
        target_row = tk.Frame(config_frame, bg='white')
        target_row.pack(fill=tk.X, pady=(0, 8))
        
        tk.Label(target_row, text="Target:", 
                font=('Segoe UI', 10, 'bold'),
                bg='white').pack(side=tk.LEFT, padx=(0, 10))
        
        self.target_var = tk.StringVar()
        self.target_combo = ttk.Combobox(target_row, 
                                        textvariable=self.target_var,
                                        width=35,
                                        font=('Segoe UI', 10))
        self.target_combo['values'] = self.config.get('recent_targets', [])
        self.target_combo.set(self.config.get('default_target', '127.0.0.1'))
        self.target_combo.pack(side=tk.LEFT, padx=(0, 10))
        
        # Quick target buttons
        quick_frame = tk.Frame(target_row, bg='white')
        quick_frame.pack(side=tk.LEFT)
        
        quick_targets = [
            ("Localhost", "127.0.0.1"),
            ("Gateway", "192.168.1.1"),
            ("Network", "192.168.1.0/24"),
            ("Custom", "")
        ]
        
        for text, value in quick_targets:
            btn = ttk.Button(quick_frame, text=text, width=8,
                           command=lambda v=value: self.set_target(v))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Port configuration
        port_row = tk.Frame(config_frame, bg='white')
        port_row.pack(fill=tk.X, pady=(0, 8))
        
        tk.Label(port_row, text="Ports:", 
                font=('Segoe UI', 10, 'bold'),
                bg='white').pack(side=tk.LEFT, padx=(0, 10))
        
        self.ports_entry = tk.Entry(port_row, 
                                   width=35,
                                   font=('Segoe UI', 10))
        self.ports_entry.insert(0, self.config['default_ports'])
        self.ports_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        # Port presets
        presets_frame = tk.Frame(port_row, bg='white')
        presets_frame.pack(side=tk.LEFT)
        
        presets = [
            ("Common", "21,22,23,25,53,80,110,443,3306,5432,8080,8443"),
            ("Web", "80,443,8080,8443,3000,5000,8000"),
            ("Database", "1433,1521,3306,3389,5432,6379,27017"),
            ("All", "1-1000")
        ]
        
        for text, ports in presets:
            btn = ttk.Button(presets_frame, text=text, width=8,
                           command=lambda p=ports: self.set_ports(p))
            btn.pack(side=tk.LEFT, padx=2)
        
        # Options row
        options_row = tk.Frame(config_frame, bg='white')
        options_row.pack(fill=tk.X, pady=(0, 8))
        
        self.banner_var = tk.BooleanVar(value=self.config['banner_grab'])
        banner_cb = tk.Checkbutton(options_row, text="Grab Banners",
                                  variable=self.banner_var,
                                  bg='white',
                                  font=('Segoe UI', 9))
        banner_cb.pack(side=tk.LEFT, padx=(0, 15))
        
        self.vuln_var = tk.BooleanVar(value=self.config['vuln_scan'])
        vuln_cb = tk.Checkbutton(options_row, text="Vulnerability Scan",
                                variable=self.vuln_var,
                                bg='white',
                                font=('Segoe UI', 9))
        vuln_cb.pack(side=tk.LEFT)
        
        # Scan control row
        control_row = tk.Frame(config_frame, bg='white')
        control_row.pack(fill=tk.X)
        
        self.scan_btn = ttk.Button(control_row, 
                                  text="▶ Start Scan",
                                  command=self.start_scan,
                                  style='Accent.TButton',
                                  width=12)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = ttk.Button(control_row,
                                  text="⏹ Stop",
                                  command=self.stop_scan,
                                  state=tk.DISABLED,
                                  width=8)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(control_row,
                                       mode='indeterminate',
                                       length=200)
        self.progress.pack(side=tk.LEFT, padx=(0, 10))
        
        # Status label
        self.status_label = tk.Label(control_row,
                                    text="Ready",
                                    font=('Segoe UI', 9),
                                    bg='white',
                                    fg='#27ae60')
        self.status_label.pack(side=tk.LEFT)
        
        # Timer label
        self.timer_label = tk.Label(control_row,
                                   text="",
                                   font=('Segoe UI', 9),
                                   bg='white',
                                   fg='#7f8c8d')
        self.timer_label.pack(side=tk.LEFT, padx=(20, 0))
        
        # Main results area with tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Results tab
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text="Results")
        
        # Treeview with scrollbars
        tree_container = tk.Frame(results_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)
        
        columns = ("IP", "Port", "Service", "Banner", "Risk", "Vulnerabilities")
        self.tree = ttk.Treeview(tree_container, columns=columns, show="headings", height=15)
        
        # Configure columns
        col_widths = {
            "IP": 120,
            "Port": 70,
            "Service": 100,
            "Banner": 250,
            "Risk": 80,
            "Vulnerabilities": 150
        }
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=col_widths.get(col, 100))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        
        # Double-click event
        self.tree.bind("<Double-1>", self.on_item_double_click)
        
        # Statistics tab
        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="Statistics")
        
        self.stats_text = tk.Text(stats_frame,
                                 height=10,
                                 font=('Consolas', 10),
                                 wrap=tk.WORD,
                                 bg='#f8f9fa')
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Log tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Log")
        
        self.log_text = tk.Text(log_frame,
                               height=10,
                               font=('Consolas', 9),
                               wrap=tk.WORD,
                               bg='#2c3e50',
                               fg='#ecf0f1')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bottom button bar
        button_frame = tk.Frame(main_frame, bg='#f8f9fa')
        button_frame.pack(fill=tk.X)
        
        # Left buttons
        left_buttons = tk.Frame(button_frame, bg='#f8f9fa')
        left_buttons.pack(side=tk.LEFT)
        
        export_menu = tk.Menu(self.root, tearoff=0)
        export_menu.add_command(label="CSV", command=lambda: self.export("csv"))
        export_menu.add_command(label="HTML", command=lambda: self.export("html"))
        export_menu.add_command(label="JSON", command=lambda: self.export("json"))
        export_menu.add_command(label="Text", command=lambda: self.export("txt"))
        
        export_btn = ttk.Button(left_buttons, text="📁 Export", width=10)
        export_btn.pack(side=tk.LEFT, padx=2)
        export_btn.bind("<Button-1>", lambda e: export_menu.post(e.widget.winfo_rootx(), 
                                                                 e.widget.winfo_rooty() + e.widget.winfo_height()))
        
        ttk.Button(left_buttons, text="🧹 Clear", 
                  command=self.clear_results, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(left_buttons, text="📋 Copy", 
                  command=self.copy_results, width=8).pack(side=tk.LEFT, padx=2)
        
        # Right buttons
        right_buttons = tk.Frame(button_frame, bg='#f8f9fa')
        right_buttons.pack(side=tk.RIGHT)
        
        ttk.Button(right_buttons, text="⚙️ Settings", 
                  command=self.open_settings, width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(right_buttons, text="📖 Help", 
                  command=self.show_help, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(right_buttons, text="🔄 Refresh", 
                  command=self.refresh_view, width=8).pack(side=tk.LEFT, padx=2)
        
        # Initialize log
        self.log("Application started successfully", "INFO")
    
    def log(self, message, level="INFO"):
        """Add message to log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Color coding
        colors = {
            "INFO": "#3498db",
            "WARN": "#f39c12", 
            "ERROR": "#e74c3c",
            "SUCCESS": "#27ae60"
        }
        
        color = colors.get(level, "#95a5a6")
        
        self.log_text.insert(tk.END, log_entry)
        start_idx = f"{self.log_text.index('end-2c').split('.')[0]}.0"
        end_idx = f"{self.log_text.index('end-2c').split('.')[0]}.end"
        
        self.log_text.tag_add(level, start_idx, end_idx)
        self.log_text.tag_config(level, foreground=color)
        self.log_text.see(tk.END)
    
    def process_queue(self):
        """Process messages from scan thread"""
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()
                
                if msg_type == "RESULT":
                    self.add_result(data)
                elif msg_type == "STATUS":
                    self.update_status(data)
                elif msg_type == "PROGRESS":
                    self.update_progress(data)
                elif msg_type == "COMPLETE":
                    self.scan_complete(data)
                elif msg_type == "ERROR":
                    self.show_error(data)
                    
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)
    
    def set_target(self, target):
        """Set target in entry field"""
        if target:
            self.target_var.set(target)
        else:
            # Custom target dialog
            custom = tk.simpledialog.askstring("Custom Target", 
                                              "Enter IP, CIDR, or hostname:")
            if custom:
                self.target_var.set(custom)
    
    def set_ports(self, ports):
        """Set ports in entry field"""
        self.ports_entry.delete(0, tk.END)
        self.ports_entry.insert(0, ports)
    
    def start_scan(self):
        """Start the scanning process"""
        target = self.target_var.get().strip()
        ports_str = self.ports_entry.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        # Validate target
        if not self.validate_target(target):
            messagebox.showerror("Error", "Invalid target format")
            return
        
        # Parse ports
        try:
            ports = self.parse_ports(ports_str)
            if not ports:
                raise ValueError("No valid ports specified")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid port format: {e}")
            return
        
        # Save to recent targets
        if target not in self.config['recent_targets']:
            self.config['recent_targets'].insert(0, target)
            self.config['recent_targets'] = self.config['recent_targets'][:10]  # Keep last 10
            self.target_combo['values'] = self.config['recent_targets']
            self.save_config()
        
        # Clear previous results
        self.clear_results()
        
        # Update UI
        self.scanning = True
        self.scan_start_time = datetime.now()
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start(10)
        self.status_label.config(text="Scanning...", fg="#3498db")
        self.timer_label.config(text="00:00")
        
        # Start timer update
        self.update_timer()
        
        self.log(f"Starting scan: {target} (Ports: {len(ports)})", "INFO")
        
        # Start scan in thread
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, ports),
            daemon=True
        )
        self.scan_thread.start()
    
    def validate_target(self, target):
        """Validate target IP/CIDR/hostname"""
        try:
            # Check if it's a CIDR
            if "/" in target:
                ipaddress.ip_network(target, strict=False)
                return True
            # Check if it's an IP
            elif "." in target or ":" in target:
                ipaddress.ip_address(target)
                return True
            # Assume it's a hostname
            else:
                return True
        except ValueError:
            return False
    
    def parse_ports(self, ports_str):
        """Parse port string into list of integers"""
        ports = []
        parts = ports_str.replace(" ", "").split(",")
        
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
        
        # Remove duplicates and sort
        ports = sorted(set(ports))
        # Filter valid ports
        ports = [p for p in ports if 1 <= p <= 65535]
        
        return ports
    
    def run_scan(self, target, ports):
        """Run scan in background thread"""
        try:
            scanner = ScannerEngine(target, ports=ports, threads=self.config['threads'])
            results = scanner.run()
            
            # Perform vulnerability scan if enabled
            if self.vuln_var.get():
                self.result_queue.put(("STATUS", "Checking vulnerabilities..."))
                for result in results:
                    vulns = VulnScanner.check_weak_credentials(result['ip'], 
                                                             result['port'], 
                                                             result['service'])
                    vulns.extend(VulnScanner.check_version_vulns(result['banner']))
                    result['vulnerabilities'] = vulns
            
            # Send results to GUI
            for result in results:
                self.result_queue.put(("RESULT", result))
            
            self.result_queue.put(("COMPLETE", len(results)))
            
        except Exception as e:
            self.result_queue.put(("ERROR", str(e)))
    
    def add_result(self, result):
        """Add a result to the treeview"""
        # Determine risk level
        risk = self.assess_risk(result)
        
        # Prepare values for treeview
        vulns = result.get('vulnerabilities', [])
        vuln_text = ", ".join(vulns) if vulns else "None"
        
        values = (
            result['ip'],
            result['port'],
            result['service'],
            result['banner'][:100] if result['banner'] else "No banner",
            risk,
            vuln_text
        )
        
        item_id = self.tree.insert("", tk.END, values=values)
        
        # Color code based on risk
        if risk == "High":
            self.tree.item(item_id, tags=("high",))
        elif risk == "Medium":
            self.tree.item(item_id, tags=("medium",))
        
        # Store full result
        self.results.append(result)
        
        # Update statistics
        self.update_statistics()
    
    def assess_risk(self, result):
        """Assess risk level based on port and service"""
        port = result['port']
        service = result['service'].lower()
        
        # High risk ports
        high_risk = {21, 22, 23, 3389, 5900, 445, 1433, 1521}
        
        # Medium risk ports
        medium_risk = {25, 110, 143, 3306, 5432, 6379, 27017, 8080}
        
        # Check for known vulnerabilities
        vulns = result.get('vulnerabilities', [])
        if vulns:
            return "Critical"
        
        if port in high_risk:
            return "High"
        elif port in medium_risk:
            return "Medium"
        elif "ssh" in service or "telnet" in service or "ftp" in service:
            return "High"
        elif "http" in service or "https" in service:
            return "Low"
        else:
            return "Low"
    
    def update_statistics(self):
        """Update statistics display"""
        if not self.results:
            return
        
        stats = {
            "Total Hosts": len(set(r['ip'] for r in self.results)),
            "Open Ports": len(self.results),
            "High Risk": sum(1 for r in self.results if self.assess_risk(r) in ["High", "Critical"]),
            "Medium Risk": sum(1 for r in self.results if self.assess_risk(r) == "Medium"),
            "Low Risk": sum(1 for r in self.results if self.assess_risk(r) == "Low"),
            "Services Found": len(set(r['service'] for r in self.results if r['service'] != "Unknown"))
        }
        
        stats_text = "📊 Scan Statistics\n" + "="*40 + "\n\n"
        for key, value in stats.items():
            stats_text += f"{key:20} {value:>5}\n"
        
        stats_text += "\n" + "="*40 + "\n"
        stats_text += f"Scan started: {self.scan_start_time.strftime('%H:%M:%S') if self.scan_start_time else 'N/A'}\n"
        stats_text += f"Duration: {self.get_scan_duration()}\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(1.0, stats_text)
    
    def get_scan_duration(self):
        """Get formatted scan duration"""
        if not self.scan_start_time:
            return "N/A"
        
        if self.scanning:
            duration = datetime.now() - self.scan_start_time
        else:
            # Use saved end time or current time
            duration = datetime.now() - self.scan_start_time
        
        total_seconds = int(duration.total_seconds())
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        
        return f"{minutes:02d}:{seconds:02d}"
    
    def update_timer(self):
        """Update the scan timer"""
        if self.scanning and self.scan_start_time:
            duration = datetime.now() - self.scan_start_time
            total_seconds = int(duration.total_seconds())
            minutes = total_seconds // 60
            seconds = total_seconds % 60
            self.timer_label.config(text=f"{minutes:02d}:{seconds:02d}")
            self.root.after(1000, self.update_timer)
    
    def scan_complete(self, count):
        """Handle scan completion"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        
        duration = self.get_scan_duration()
        self.status_label.config(text=f"Complete ({duration})", fg="#27ae60")
        
        self.log(f"Scan completed: {count} open ports found in {duration}", "SUCCESS")
        
        # Update statistics one last time
        self.update_statistics()
        
        if count > 0:
            messagebox.showinfo("Scan Complete", 
                              f"Found {count} open port{'s' if count != 1 else ''} in {duration}")
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning:
            self.scanning = False
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.progress.stop()
            
            self.status_label.config(text="Stopped", fg="#f39c12")
            self.log("Scan stopped by user", "WARN")
    
    def update_status(self, status):
        """Update status label"""
        self.status_label.config(text=status)
    
    def update_progress(self, value):
        """Update progress bar"""
        # Not implemented in current scanner
        pass
    
    def show_error(self, error_msg):
        """Show error message"""
        self.scanning = False
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        
        self.status_label.config(text="Error", fg="#e74c3c")
        self.log(f"Error: {error_msg}", "ERROR")
        messagebox.showerror("Scan Error", error_msg)
    
    def export(self, fmt):
        """Export results to file"""
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to export")
            return
        
        # Get filename from user
        filetypes = {
            "csv": ("CSV Files", "*.csv"),
            "html": ("HTML Files", "*.html"),
            "json": ("JSON Files", "*.json"),
            "txt": ("Text Files", "*.txt")
        }
        
        default_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[filetypes[fmt], ("All Files", "*.*")],
            initialfile=default_name
        )
        
        if not filename:
            return
        
        try:
            if fmt == "csv":
                Reporter.to_csv(self.results, filename)
            elif fmt == "html":
                Reporter.to_html(self.results, filename)
                if messagebox.askyesno("Open Report", "Open HTML report in browser?"):
                    webbrowser.open(f"file://{os.path.abspath(filename)}")
            elif fmt == "json":
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=2, default=str)
            elif fmt == "txt":
                with open(filename, 'w') as f:
                    f.write("PySecure Scan Report\n")
                    f.write("="*50 + "\n\n")
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target: {self.target_var.get()}\n")
                    f.write(f"Ports: {self.ports_entry.get()}\n\n")
                    
                    for result in self.results:
                        f.write(f"IP: {result['ip']}:{result['port']}\n")
                        f.write(f"Service: {result['service']}\n")
                        f.write(f"Banner: {result.get('banner', 'N/A')}\n")
                        f.write(f"Risk: {self.assess_risk(result)}\n")
                        vulns = result.get('vulnerabilities', [])
                        if vulns:
                            f.write(f"Vulnerabilities: {', '.join(vulns)}\n")
                        f.write("-"*40 + "\n")
            
            self.log(f"Exported {len(self.results)} results to {fmt.upper()}: {filename}", "INFO")
            messagebox.showinfo("Export Successful", 
                              f"Report exported to:\n{filename}")
        except Exception as e:
            self.log(f"Export failed: {str(e)}", "ERROR")
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def clear_results(self):
        """Clear all results"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results.clear()
        self.stats_text.delete(1.0, tk.END)
        self.status_label.config(text="Ready", fg="#27ae60")
        self.timer_label.config(text="")
        self.log("Results cleared", "INFO")
    
    def copy_results(self):
        """Copy selected results to clipboard"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Info", "No results selected")
            return
        
        text = ""
        for item_id in selection:
            values = self.tree.item(item_id, "values")
            text += "\t".join(str(v) for v in values) + "\n"
        
        self.root.clipboard_clear()
        self.root.clipboard_append(text.strip())
        self.log("Results copied to clipboard", "INFO")
    
    def refresh_view(self):
        """Refresh the view"""
        self.update_statistics()
        self.log("View refreshed", "INFO")
    
    def on_item_double_click(self, event):
        """Handle double-click on treeview item"""
        selection = self.tree.selection()
        if selection:
            item_id = selection[0]
            values = self.tree.item(item_id, "values")
            
            detail_win = tk.Toplevel(self.root)
            detail_win.title("Port Details")
            detail_win.geometry("500x400")
            
            # Find full result
            ip, port = values[0], int(values[1])
            result = next((r for r in self.results if r['ip'] == ip and r['port'] == port), None)
            
            if result:
                text = f"""Detailed Information
====================

IP Address: {result['ip']}
Port: {result['port']}
Service: {result['service']}
Status: {result.get('status', 'Open')}
Risk Level: {self.assess_risk(result)}

Banner Information:
{result.get('banner', 'No banner captured')}

"""
                
                vulns = result.get('vulnerabilities', [])
                if vulns:
                    text += f"\nVulnerabilities Found:\n"
                    for vuln in vulns:
                        text += f"  • {vuln}\n"
                
                text_widget = tk.Text(detail_win, wrap=tk.WORD, padx=10, pady=10)
                text_widget.insert(1.0, text)
                text_widget.config(state=tk.DISABLED)
                text_widget.pack(fill=tk.BOTH, expand=True)
                
                ttk.Button(detail_win, text="Close", 
                          command=detail_win.destroy).pack(pady=10)
    
    def quick_scan(self):
        """Perform a quick scan"""
        self.set_target("127.0.0.1")
        self.set_ports("21,22,23,80,443,3306,8080")
        self.start_scan()
    
    def full_scan(self):
        """Perform a full scan"""
        self.set_ports("1-1000")
        self.start_scan()
    
    def port_checker(self):
        """Open port checker tool"""
        checker_win = tk.Toplevel(self.root)
        checker_win.title("Port Checker")
        checker_win.geometry("400x200")
        
        frame = tk.Frame(checker_win, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(frame, text="Check Single Port", 
                font=('Arial', 12, 'bold')).pack(pady=(0, 15))
        
        # Host input
        host_frame = tk.Frame(frame)
        host_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(host_frame, text="Host:").pack(side=tk.LEFT, padx=(0, 10))
        host_entry = tk.Entry(host_frame, width=20)
        host_entry.insert(0, "localhost")
        host_entry.pack(side=tk.LEFT)
        
        # Port input
        port_frame = tk.Frame(frame)
        port_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(port_frame, text="Port:").pack(side=tk.LEFT, padx=(0, 10))
        port_entry = tk.Entry(port_frame, width=10)
        port_entry.insert(0, "80")
        port_entry.pack(side=tk.LEFT)
        
        result_label = tk.Label(frame, text="", fg="#2c3e50")
        result_label.pack(pady=10)
        
        def check_port():
            host = host_entry.get()
            try:
                port = int(port_entry.get())
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    result_label.config(text=f"Port {port} is OPEN", fg="#27ae60")
                    self.log(f"Port check: {host}:{port} - OPEN", "INFO")
                else:
                    result_label.config(text=f"Port {port} is CLOSED", fg="#e74c3c")
                    self.log(f"Port check: {host}:{port} - CLOSED", "INFO")
                    
            except Exception as e:
                result_label.config(text=f"Error: {str(e)}", fg="#e74c3c")
        
        ttk.Button(frame, text="Check Port", command=check_port).pack(pady=10)
    
    def host_discovery(self):
        """Simple host discovery tool"""
        discovery_win = tk.Toplevel(self.root)
        discovery_win.title("Host Discovery")
        discovery_win.geometry("500x300")
        
        frame = tk.Frame(discovery_win, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(frame, text="Network Discovery", 
                font=('Arial', 12, 'bold')).pack(pady=(0, 15))
        
        tk.Label(frame, text="Enter network (e.g., 192.168.1.0/24):").pack(anchor='w')
        
        network_entry = tk.Entry(frame, width=25)
        network_entry.insert(0, "192.168.1.0/24")
        network_entry.pack(anchor='w', pady=(0, 15))
        
        results_text = tk.Text(frame, height=8, width=50, state=tk.DISABLED)
        results_text.pack(pady=(0, 10))
        
        def discover_hosts():
            network = network_entry.get()
            try:
                net = ipaddress.ip_network(network, strict=False)
                hosts = list(net.hosts())[:50]  # Limit to first 50
                
                results_text.config(state=tk.NORMAL)
                results_text.delete(1.0, tk.END)
                
                results_text.insert(tk.END, f"Discovering hosts in {network}...\n\n")
                results_text.insert(tk.END, f"First {len(hosts)} hosts:\n")
                
                for host in hosts:
                    results_text.insert(tk.END, f"  {host}\n")
                
                results_text.config(state=tk.DISABLED)
                self.log(f"Host discovery completed for {network}", "INFO")
                
            except Exception as e:
                messagebox.showerror("Error", f"Invalid network: {str(e)}")
        
        ttk.Button(frame, text="Discover Hosts", command=discover_hosts).pack()
    
    def vuln_scan(self):
        """Run vulnerability scan on current results"""
        if not self.results:
            messagebox.showinfo("Info", "No scan results available")
            return
        
        self.log("Starting vulnerability scan...", "INFO")
        
        progress_win = tk.Toplevel(self.root)
        progress_win.title("Vulnerability Scan")
        progress_win.geometry("400x150")
        
        tk.Label(progress_win, text="Scanning for vulnerabilities...", 
                font=('Arial', 11)).pack(pady=20)
        
        progress_bar = ttk.Progressbar(progress_win, mode='indeterminate', length=300)
        progress_bar.pack(pady=10)
        progress_bar.start(10)
        
        def run_vuln_scan():
            vuln_count = 0
            
            for result in self.results:
                # Check for weak credentials
                vulns = VulnScanner.check_weak_credentials(
                    result['ip'], 
                    result['port'], 
                    result['service']
                )
                
                # Check version vulnerabilities
                vulns.extend(VulnScanner.check_version_vulns(result['banner']))
                
                if vulns:
                    result['vulnerabilities'] = vulns
                    vuln_count += len(vulns)
            
            progress_win.destroy()
            
            if vuln_count > 0:
                messagebox.showinfo("Vulnerability Scan", 
                                  f"Found {vuln_count} potential vulnerability/vulnerabilities")
                self.log(f"Vulnerability scan found {vuln_count} issues", "WARN")
                
                # Refresh treeview
                for item in self.tree.get_children():
                    self.tree.delete(item)
                
                for result in self.results:
                    self.add_result(result)
                    
            else:
                messagebox.showinfo("Vulnerability Scan", "No vulnerabilities found")
                self.log("Vulnerability scan completed - no issues found", "INFO")
        
        # Run in thread
        threading.Thread(target=run_vuln_scan, daemon=True).start()
    
    def load_results(self):
        """Load saved results from file"""
        filename = filedialog.askopenfilename(
            title="Load Results",
            filetypes=[("JSON files", "*.json"), 
                      ("CSV files", "*.csv"),
                      ("All files", "*.*")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'r') as f:
                        self.results = json.load(f)
                elif filename.endswith('.csv'):
                    import csv
                    self.results = []
                    with open(filename, 'r') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            self.results.append(row)
                
                # Clear and repopulate treeview
                self.clear_results()
                for result in self.results:
                    self.add_result(result)
                
                self.log(f"Loaded results from {filename}", "INFO")
                messagebox.showinfo("Success", f"Loaded {len(self.results)} results")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
                self.log(f"Failed to load {filename}: {str(e)}", "ERROR")
    
    def save_results(self):
        """Save results to file"""
        if not self.results:
            messagebox.showwarning("No Data", "No results to save")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), 
                      ("CSV files", "*.csv"),
                      ("All files", "*.*")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.results, f, indent=2, default=str)
                elif filename.endswith('.csv'):
                    Reporter.to_csv(self.results, filename)
                
                self.log(f"Saved results to {filename}", "INFO")
                messagebox.showinfo("Success", f"Results saved to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
                self.log(f"Failed to save {filename}: {str(e)}", "ERROR")
    
    def open_settings(self):
        """Open settings dialog"""
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Settings")
        settings_win.geometry("450x400")
        settings_win.resizable(False, False)
        
        notebook = ttk.Notebook(settings_win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General tab
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        tk.Label(general_frame, text="Default Target:").grid(row=0, column=0, sticky='w', pady=5, padx=10)
        default_target = tk.Entry(general_frame, width=25)
        default_target.insert(0, self.config['default_target'])
        default_target.grid(row=0, column=1, pady=5, padx=10)
        
        tk.Label(general_frame, text="Default Ports:").grid(row=1, column=0, sticky='w', pady=5, padx=10)
        default_ports = tk.Entry(general_frame, width=25)
        default_ports.insert(0, self.config['default_ports'])
        default_ports.grid(row=1, column=1, pady=5, padx=10)
        
        tk.Label(general_frame, text="Threads:").grid(row=2, column=0, sticky='w', pady=5, padx=10)
        threads_var = tk.StringVar(value=str(self.config['threads']))
        threads_spin = tk.Spinbox(general_frame, from_=1, to=200, width=10, textvariable=threads_var)
        threads_spin.grid(row=2, column=1, sticky='w', pady=5, padx=10)
        
        tk.Label(general_frame, text="Timeout (sec):").grid(row=3, column=0, sticky='w', pady=5, padx=10)
        timeout_var = tk.StringVar(value=str(self.config['timeout']))
        timeout_spin = tk.Spinbox(general_frame, from_=0.5, to=10, increment=0.5, width=10, textvariable=timeout_var)
        timeout_spin.grid(row=3, column=1, sticky='w', pady=5, padx=10)
        
        # Scan tab
        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text="Scan Options")
        
        banner_var = tk.BooleanVar(value=self.config['banner_grab'])
        banner_cb = tk.Checkbutton(scan_frame, text="Enable banner grabbing",
                                  variable=banner_var, bg='white')
        banner_cb.grid(row=0, column=0, sticky='w', pady=5, padx=10)
        
        vuln_var = tk.BooleanVar(value=self.config['vuln_scan'])
        vuln_cb = tk.Checkbutton(scan_frame, text="Enable vulnerability scanning",
                                variable=vuln_var, bg='white')
        vuln_cb.grid(row=1, column=0, sticky='w', pady=5, padx=10)
        
        save_var = tk.BooleanVar(value=self.config['save_reports'])
        save_cb = tk.Checkbutton(scan_frame, text="Auto-save reports",
                                variable=save_var, bg='white')
        save_cb.grid(row=2, column=0, sticky='w', pady=5, padx=10)
        
        dark_var = tk.BooleanVar(value=self.config['dark_mode'])
        dark_cb = tk.Checkbutton(scan_frame, text="Dark mode",
                                variable=dark_var, bg='white')
        dark_cb.grid(row=3, column=0, sticky='w', pady=5, padx=10)
        
        def save_settings():
            self.config['default_target'] = default_target.get()
            self.config['default_ports'] = default_ports.get()
            self.config['threads'] = int(threads_var.get())
            self.config['timeout'] = float(timeout_var.get())
            self.config['banner_grab'] = banner_var.get()
            self.config['vuln_scan'] = vuln_var.get()
            self.config['save_reports'] = save_var.get()
            self.config['dark_mode'] = dark_var.get()
            
            self.save_config()
            settings_win.destroy()
            
            # Apply dark mode if changed
            if dark_var.get() != self.config.get('dark_mode_old', False):
                messagebox.showinfo("Restart Required", 
                                  "Please restart application for theme changes to take effect.")
            
            self.log("Settings saved", "INFO")
        
        button_frame = tk.Frame(settings_win)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Save", command=save_settings, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=settings_win.destroy, width=12).pack(side=tk.LEFT, padx=5)
    
    def show_help(self):
        """Show help window"""
        help_text = """PySecure Scanner Help

Basic Usage:
1. Enter target (IP, CIDR, or hostname)
2. Specify ports (comma-separated or ranges)
3. Click Start Scan

Target Examples:
- Single IP: 192.168.1.1
- Network: 192.168.1.0/24
- Localhost: 127.0.0.1
- Hostname: example.com

Port Examples:
- Single: 80
- List: 80,443,8080
- Range: 1-1024
- Combined: 21,22,80,443,8000-9000

Features:
- Real-time results display
- Risk assessment
- Vulnerability scanning
- Multiple export formats
- Port checker tool
- Host discovery

Tips:
- Use common port presets for quick scans
- Export reports for documentation
- Check high-risk ports first
- Clear results between scans

Hotkeys:
- F5: Refresh view
- Ctrl+C: Copy selected
- Ctrl+S: Save results
- Delete: Clear results
"""
        
        help_win = tk.Toplevel(self.root)
        help_win.title("Help - PySecure Scanner")
        help_win.geometry("600x500")
        
        text_widget = tk.Text(help_win, wrap=tk.WORD, font=('Arial', 10), padx=15, pady=15)
        text_widget.insert(1.0, help_text)
        text_widget.config(state=tk.DISABLED)
        
        scrollbar = ttk.Scrollbar(help_win, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def show_docs(self):
        """Show documentation in browser"""
        docs_url = "https://github.com/smixosec/pysecure-scanner"
        webbrowser.open(docs_url)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """PySecure Scanner v2.0

A professional network security scanner
for penetration testing and network auditing.

Features:
- Port scanning
- Service detection
- Banner grabbing
- Vulnerability assessment
- Comprehensive reporting

Built with Python and Tkinter

License: MIT
© 2024 PySecure Team
"""
        
        about_win = tk.Toplevel(self.root)
        about_win.title("About PySecure Scanner")
        about_win.geometry("400x300")
        
        # Logo/Title
        title_frame = tk.Frame(about_win, bg='#2c3e50')
        title_frame.pack(fill=tk.X)
        
        tk.Label(title_frame, text="🔒", font=('Arial', 40), 
                bg='#2c3e50', fg='white').pack(pady=(20, 5))
        tk.Label(title_frame, text="PySecure Scanner", font=('Arial', 16, 'bold'), 
                bg='#2c3e50', fg='white').pack(pady=(0, 20))
        
        # Info
        info_frame = tk.Frame(about_win, padx=20, pady=20)
        info_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(info_frame, text="Version 2.0", font=('Arial', 11)).pack(pady=5)
        tk.Label(info_frame, text="Network Security Scanner", fg='#7f8c8d').pack(pady=5)
        
        tk.Label(info_frame, text="\nFor security testing and", 
                font=('Arial', 9)).pack(pady=5)
        tk.Label(info_frame, text="network auditing purposes only", 
                font=('Arial', 9)).pack(pady=5)
        
        # Close button
        ttk.Button(about_win, text="Close", 
                  command=about_win.destroy).pack(pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    app = PySecureGUI(root)
    
    # Configure treeview tags
    app.tree.tag_configure("high", background="#ffcccc")
    app.tree.tag_configure("medium", background="#fff3cd")
    
    # Center window
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()