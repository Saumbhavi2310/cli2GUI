import tkinter as tk
from tkinter import ttk, messagebox
import threading
import scapy.all as scapy
from datetime import datetime
import seaborn as sns
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import time
from collections import deque
import numpy as np
import pandas as pd

class NetworkIDS:
    def __init__(self, root):
        self.root = root
        self.root.title("Network IDS")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f5f9')
        
        # Set Seaborn style
        sns.set_style("whitegrid")
        sns.set_palette("husl")
        
        # Initialize data for graphs
        self.data_points = []  # Store data as list of dictionaries
        self.max_points = 50   # Maximum number of points to display
        self.start_time = time.time()
        
        # Configure styles with colors
        self.style = ttk.Style()
        self.style.configure('Header.TLabel', font=('Helvetica', 24, 'bold'), foreground='#1e3d59', background='#f0f5f9')
        self.style.configure('SubHeader.TLabel', font=('Helvetica', 12), background='#f0f5f9')
        self.style.configure('Custom.TButton', font=('Helvetica', 10), padding=5)
        self.style.configure('Alert.TLabel', font=('Helvetica', 10), foreground='red', background='#f0f5f9')
        self.style.configure('Stats.TLabel', font=('Helvetica', 12, 'bold'), foreground='#1e3d59', background='#e8f1f5')
        self.style.configure('TLabelframe', background='#f0f5f9')
        self.style.configure('TLabelframe.Label', background='#f0f5f9', foreground='#1e3d59', font=('Helvetica', 10, 'bold'))
        self.style.configure('TFrame', background='#f0f5f9')
        
        self.sniffing_flag = False
        self.packet_stats = {
            'total': 0, 
            'tcp': 0, 
            'udp': 0, 
            'alerts': 0,
            'port_scan': 0,
            'syn_flood': 0,
            'suspicious_port': 0
        }
        self.connection_tracker = {}
        self.port_scan_tracker = {}
        self.custom_rules = []
        
        self.interfaces = self.get_interfaces()
        self.create_ui()
        self.bind_shortcuts()
        
        # Start graph update loop
        self.update_graph()

    def get_interfaces(self):
        try:
            return scapy.get_if_list()
        except:
            return ['eth0', 'wlan0']

    def create_ui(self):
        # Main container with background color
        main_container = ttk.Frame(self.root, padding="10", style='TFrame')
        main_container.pack(fill=tk.BOTH, expand=True)

        # Header with icon and background
        header_frame = ttk.Frame(main_container, style='TFrame')
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        header_text = "🛡️ Network Intrusion Detection System"
        ttk.Label(header_frame, text=header_text, style='Header.TLabel').pack(side=tk.LEFT)

        # Interface selection frame with light background
        interface_frame = ttk.LabelFrame(main_container, 
                                       text="🌐 Network Interface Selection", 
                                       padding="10",
                                       style='TLabelframe')
        interface_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.interface_var = tk.StringVar(value=self.interfaces[0] if self.interfaces else "")
        self.interface_combo = ttk.Combobox(interface_frame, 
                                          textvariable=self.interface_var,
                                          values=self.interfaces,
                                          state="readonly",
                                          width=40)
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        # Control Panel with colored buttons and light background
        control_frame = ttk.LabelFrame(main_container, 
                                     text="🎮 Control Panel", 
                                     padding="10",
                                     style='TLabelframe')
        control_frame.pack(fill=tk.X, pady=(0, 10))

        button_frame = ttk.Frame(control_frame, style='TFrame')
        button_frame.pack(fill=tk.X)

        # Start button (Soft Green)
        self.start_button = tk.Button(button_frame, 
                                    text="▶ Start Monitoring",
                                    command=self.start_sniffing,
                                    bg='#a8e6cf',  # Light green
                                    fg='#1e3d59',  # Dark blue
                                    font=('Helvetica', 10, 'bold'),
                                    width=20,
                                    relief='groove',
                                    cursor='hand2')
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Stop button (Soft Red)
        self.stop_button = tk.Button(button_frame,
                                   text="⏹ Stop Monitoring",
                                   command=self.stop_sniffing,
                                   bg='#ffb7b2',  # Light red
                                   fg='#1e3d59',  # Dark blue
                                   font=('Helvetica', 10, 'bold'),
                                   state=tk.DISABLED,
                                   width=20,
                                   relief='groove',
                                   cursor='hand2')
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Generate Rules button (Soft Blue)
        self.generate_rules_button = tk.Button(button_frame,
                                             text="⚙ Generate Rules",
                                             command=self.generate_rules,
                                             bg='#b7d7e8',  # Light blue
                                             fg='#1e3d59',  # Dark blue
                                             font=('Helvetica', 10, 'bold'),
                                             width=20,
                                             relief='groove',
                                             cursor='hand2')
        self.generate_rules_button.pack(side=tk.LEFT, padx=5)

        # Statistics Frame with light background
        stats_frame = ttk.LabelFrame(main_container, 
                                   text="📊 Network Statistics", 
                                   padding="10",
                                   style='TLabelframe')
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Create separate labels for each statistic with light backgrounds
        stats_container = ttk.Frame(stats_frame, style='TFrame')
        stats_container.pack(fill=tk.X)

        # Stat boxes with light backgrounds
        self.total_label = tk.Label(stats_container, 
                                  text="📦 Total Packets: 0",
                                  font=('Helvetica', 12, 'bold'),
                                  bg='#e8f1f5',  # Light blue-grey
                                  fg='#1e3d59',  # Dark blue
                                  padx=15,
                                  pady=5,
                                  relief='ridge')
        self.total_label.pack(side=tk.LEFT, padx=10)

        self.tcp_label = tk.Label(stats_container,
                                text="🔷 TCP: 0",
                                font=('Helvetica', 12, 'bold'),
                                bg='#e8f1f5',
                                fg='#1e3d59',
                                padx=15,
                                pady=5,
                                relief='ridge')
        self.tcp_label.pack(side=tk.LEFT, padx=10)

        self.udp_label = tk.Label(stats_container,
                                text="🔶 UDP: 0",
                                font=('Helvetica', 12, 'bold'),
                                bg='#e8f1f5',
                                fg='#1e3d59',
                                padx=15,
                                pady=5,
                                relief='ridge')
        self.udp_label.pack(side=tk.LEFT, padx=10)

        self.alerts_label = tk.Label(stats_container,
                                   text="🚨 Alerts: 0",
                                   font=('Helvetica', 12, 'bold'),
                                   bg='#e8f1f5',
                                   fg='#1e3d59',
                                   padx=15,
                                   pady=5,
                                   relief='ridge')
        self.alerts_label.pack(side=tk.LEFT, padx=10)

        # Notebook with light backgrounds
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Network Traffic tab
        self.tab1 = ttk.Frame(self.notebook, padding="10", style='TFrame')
        self.notebook.add(self.tab1, text="📊 Network Traffic")

        self.packet_listbox = tk.Listbox(self.tab1,
                                       font=('Consolas', 10),
                                       selectmode=tk.SINGLE,
                                       activestyle='none',
                                       bg='#ffffff',  # White background
                                       fg='#1e3d59')  # Dark blue text
        self.packet_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(self.tab1, orient="vertical", 
                                command=self.packet_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_listbox.config(yscrollcommand=scrollbar.set)

        # Alerts & Logs tab
        self.tab2 = ttk.Frame(self.notebook, padding="10", style='TFrame')
        self.notebook.add(self.tab2, text="🚨 Alerts & Logs")

        self.log_text = tk.Text(self.tab2,
                              wrap=tk.WORD,
                              font=('Consolas', 10),
                              bg='#ffffff',  # White background
                              fg='#1e3d59')  # Dark blue text
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_text.tag_configure("alert", foreground="#e74c3c", font=('Consolas', 10, 'bold'))
        self.log_text.insert(tk.END, "=== IDS Alerts Log ===\n\n")
        self.log_text.config(state=tk.DISABLED)

        log_scrollbar = ttk.Scrollbar(self.tab2, orient="vertical",
                                    command=self.log_text.yview)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=log_scrollbar.set)

        # Live Graph tab
        self.tab3 = ttk.Frame(self.notebook, padding="10", style='TFrame')
        self.notebook.add(self.tab3, text="📈 Live Traffic")

        # Create the graph
        self.create_graph()

        # Status bar with light background
        self.status_label = tk.Label(main_container,
                                   text="✅ Status: Ready",
                                   font=('Helvetica', 10, 'bold'),
                                   bg='#e8f1f5',  # Light blue-grey
                                   fg='#1e3d59',  # Dark blue
                                   relief='ridge',
                                   padx=10,
                                   pady=5)
        self.status_label.pack(fill=tk.X, pady=(5, 0))

    def generate_rules(self):
        rule_window = tk.Toplevel(self.root)
        rule_window.title("IDS Rule Generator")
        rule_window.geometry("600x800")
        rule_window.configure(bg='#f0f5f9')

        # Main frame
        main_frame = ttk.Frame(rule_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, 
                               text="Advanced Rule Generator",
                               style='Header.TLabel')
        title_label.pack(pady=(0, 20))

        # Create notebook for different rule types
        rule_notebook = ttk.Notebook(main_frame)
        rule_notebook.pack(fill=tk.BOTH, expand=True)

        # Basic Rule Tab
        basic_frame = ttk.Frame(rule_notebook, padding="10")
        rule_notebook.add(basic_frame, text="Basic Rules")

        # Traffic Filter Tab
        traffic_frame = ttk.Frame(rule_notebook, padding="10")
        rule_notebook.add(traffic_frame, text="Traffic Filters")

        # Payload Analysis Tab
        payload_frame = ttk.Frame(rule_notebook, padding="10")
        rule_notebook.add(payload_frame, text="Payload Analysis")

        # Basic Rule Configuration
        basic_config = ttk.LabelFrame(basic_frame, text="Basic Rule Configuration", padding="10")
        basic_config.pack(fill=tk.X, pady=5)

        # Rule Name
        ttk.Label(basic_config, text="Rule Name:", style='SubHeader.TLabel').pack(pady=(5,0))
        rule_name_entry = ttk.Entry(basic_config, width=40)
        rule_name_entry.pack(pady=5)

        # Source IP
        ttk.Label(basic_config, text="Source IP:", style='SubHeader.TLabel').pack(pady=(5,0))
        src_ip_entry = ttk.Entry(basic_config, width=40)
        src_ip_entry.pack(pady=5)
        ttk.Label(basic_config, text="Examples: 192.168.1.1, 192.168.1.0/24, any", 
                  font=('Helvetica', 8)).pack()

        # Destination IP
        ttk.Label(basic_config, text="Destination IP:", style='SubHeader.TLabel').pack(pady=(5,0))
        dst_ip_entry = ttk.Entry(basic_config, width=40)
        dst_ip_entry.pack(pady=5)

        # Protocol Selection
        ttk.Label(basic_config, text="Protocol:", style='SubHeader.TLabel').pack(pady=(5,0))
        protocol_var = tk.StringVar(value="TCP")
        protocol_frame = ttk.Frame(basic_config)
        protocol_frame.pack(pady=5)
        
        protocols = ["TCP", "UDP", "ICMP", "Any"]
        for proto in protocols:
            ttk.Radiobutton(protocol_frame, text=proto, value=proto, 
                           variable=protocol_var).pack(side=tk.LEFT, padx=10)

        # Traffic Filter Configuration
        traffic_config = ttk.LabelFrame(traffic_frame, text="Traffic Filter Settings", padding="10")
        traffic_config.pack(fill=tk.X, pady=5)

        # Port Configuration
        port_frame = ttk.Frame(traffic_config)
        port_frame.pack(fill=tk.X, pady=5)

        # Source Port
        ttk.Label(port_frame, text="Source Port:", style='SubHeader.TLabel').pack(pady=(5,0))
        src_port_entry = ttk.Entry(port_frame, width=20)
        src_port_entry.pack(pady=5)
        ttk.Label(port_frame, text="Example: 80, 1024:65535, any", 
                  font=('Helvetica', 8)).pack()

        # Destination Port
        ttk.Label(port_frame, text="Destination Port:", style='SubHeader.TLabel').pack(pady=(5,0))
        dst_port_entry = ttk.Entry(port_frame, width=20)
        dst_port_entry.pack(pady=5)

        # Flow Settings
        flow_frame = ttk.LabelFrame(traffic_config, text="Flow Settings", padding="10")
        flow_frame.pack(fill=tk.X, pady=5)

        flow_var = tk.StringVar(value="bidirectional")
        ttk.Radiobutton(flow_frame, text="Bidirectional", value="bidirectional", 
                        variable=flow_var).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(flow_frame, text="To Destination", value="to_dst", 
                        variable=flow_var).pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(flow_frame, text="To Source", value="to_src", 
                        variable=flow_var).pack(side=tk.LEFT, padx=10)

        # Payload Analysis Configuration
        payload_config = ttk.LabelFrame(payload_frame, text="Payload Analysis Settings", padding="10")
        payload_config.pack(fill=tk.X, pady=5)

        # Content Matching
        ttk.Label(payload_config, text="Content Match:", style='SubHeader.TLabel').pack(pady=(5,0))
        content_entry = ttk.Entry(payload_config, width=40)
        content_entry.pack(pady=5)
        ttk.Label(payload_config, text="Example: 'login', 'password', hex:FF00FF", 
                  font=('Helvetica', 8)).pack()

        # Pattern Matching
        pattern_frame = ttk.Frame(payload_config)
        pattern_frame.pack(fill=tk.X, pady=5)

        pattern_types = ["Contains", "Starts with", "Ends with", "Regular Expression"]
        pattern_var = tk.StringVar(value="Contains")
        ttk.Label(pattern_frame, text="Pattern Type:", style='SubHeader.TLabel').pack(pady=(5,0))
        pattern_combo = ttk.Combobox(pattern_frame, values=pattern_types, 
                                    textvariable=pattern_var, state="readonly")
        pattern_combo.pack(pady=5)

        # Case Sensitivity
        case_sensitive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(payload_config, text="Case Sensitive", 
                        variable=case_sensitive_var).pack(pady=5)

        # Action Configuration
        action_frame = ttk.LabelFrame(main_frame, text="Rule Action", padding="10")
        action_frame.pack(fill=tk.X, pady=10)

        # Action Selection
        action_var = tk.StringVar(value="alert")
        actions = ["alert", "log", "drop", "reject"]
        for action in actions:
            ttk.Radiobutton(action_frame, text=action.capitalize(), value=action, 
                           variable=action_var).pack(side=tk.LEFT, padx=10)

        # Priority Selection
        priority_frame = ttk.Frame(action_frame)
        priority_frame.pack(side=tk.RIGHT, padx=10)
        ttk.Label(priority_frame, text="Priority:").pack(side=tk.LEFT)
        priority_var = tk.StringVar(value="1")
        priority_combo = ttk.Combobox(priority_frame, values=["1", "2", "3"], 
                                     textvariable=priority_var, state="readonly", width=5)
        priority_combo.pack(side=tk.LEFT, padx=5)

        # Description
        desc_frame = ttk.LabelFrame(main_frame, text="Rule Description", padding="10")
        desc_frame.pack(fill=tk.X, pady=10)
        description_text = tk.Text(desc_frame, height=3, width=50, font=('Helvetica', 10))
        description_text.pack(pady=5)

        def add_rule():
            try:
                rule = {
                    'name': rule_name_entry.get(),
                    'src_ip': src_ip_entry.get(),
                    'dst_ip': dst_ip_entry.get(),
                    'protocol': protocol_var.get(),
                    'src_port': src_port_entry.get(),
                    'dst_port': dst_port_entry.get(),
                    'flow': flow_var.get(),
                    'content': content_entry.get(),
                    'pattern_type': pattern_var.get(),
                    'case_sensitive': case_sensitive_var.get(),
                    'action': action_var.get(),
                    'priority': priority_var.get(),
                    'description': description_text.get("1.0", tk.END).strip()
                }
                
                # Validate rule
                if not rule['name']:
                    raise ValueError("Rule name is required")
                if not rule['description']:
                    raise ValueError("Rule description is required")
                
                # Add rule to custom_rules list
                self.custom_rules.append(rule)
                
                # Show success message
                messagebox.showinfo("Success", 
                                  f"Rule '{rule['name']}' added successfully!")
                rule_window.destroy()
                
            except ValueError as e:
                messagebox.showerror("Error", str(e))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add rule: {str(e)}")

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Add Rule", command=add_rule, 
                   style='Custom.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                   command=rule_window.destroy, 
                   style='Custom.TButton').pack(side=tk.LEFT, padx=5)

        # Preview Rule
        def preview_rule():
            try:
                rule_text = f"""Rule Preview:
Name: {rule_name_entry.get()}
Source IP: {src_ip_entry.get()}
Destination IP: {dst_ip_entry.get()}
Protocol: {protocol_var.get()}
Source Port: {src_port_entry.get()}
Destination Port: {dst_port_entry.get()}
Flow: {flow_var.get()}
Content: {content_entry.get()}
Pattern Type: {pattern_var.get()}
Case Sensitive: {case_sensitive_var.get()}
Action: {action_var.get()}
Priority: {priority_var.get()}
Description: {description_text.get("1.0", tk.END).strip()}
"""
                messagebox.showinfo("Rule Preview", rule_text)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to preview rule: {str(e)}")

        ttk.Button(button_frame, text="Preview", 
                   command=preview_rule, 
                   style='Custom.TButton').pack(side=tk.LEFT, padx=5)

    def bind_shortcuts(self):
        # Bind keyboard shortcuts
        self.root.bind('<Control-q>', lambda e: self.on_closing())
        self.root.bind('<Control-s>', lambda e: self.start_sniffing())
        self.root.bind('<Control-x>', lambda e: self.stop_sniffing())
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        self.sniffing_flag = False
        self.root.destroy()

    def process_packet(self, packet):
        if not self.sniffing_flag:
            return
            
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if scapy.IP in packet:
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                proto = packet[scapy.IP].proto
                
                packet_info = f"[{timestamp}] {src_ip} → {dst_ip}"
                
                if scapy.TCP in packet:
                    self.packet_stats['tcp'] += 1
                    src_port = packet[scapy.TCP].sport
                    dst_port = packet[scapy.TCP].dport
                    flags = packet[scapy.TCP].flags
                    packet_info += f" TCP {src_port}→{dst_port} [Flags: {flags}]"
                    
                    if self.detect_threats(packet, src_ip, dst_ip, src_port, dst_port, flags):
                        self.root.after(0, self.update_packet_display, packet_info, 'alert')
                    else:
                        self.root.after(0, self.update_packet_display, packet_info, 'normal')
                        
                elif scapy.UDP in packet:
                    self.packet_stats['udp'] += 1
                    src_port = packet[scapy.UDP].sport
                    dst_port = packet[scapy.UDP].dport
                    packet_info += f" UDP {src_port}→{dst_port}"
                    self.root.after(0, self.update_packet_display, packet_info, 'normal')
                
                self.packet_stats['total'] += 1
                self.root.after(0, self.update_stats)
                
        except Exception as e:
            print(f"Error processing packet: {str(e)}")

    def update_packet_display(self, packet_info, tag):
        index = self.packet_listbox.size()
        self.packet_listbox.insert(tk.END, packet_info)
        if tag == 'alert':
            self.packet_listbox.itemconfig(index, {'fg': 'red'})
            self.log_alert(packet_info)
        self.packet_listbox.yview(tk.END)

    def log_alert(self, alert_info):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, alert_info + "\n", "alert")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def sniff_packets(self):
        try:
            selected_interface = self.interface_var.get()
            if not selected_interface:
                messagebox.showerror("Error", "Please select a network interface")
                self.stop_sniffing()
                return

            self.packet_listbox.insert(tk.END, f"[*] Starting capture on interface: {selected_interface}\n")
            
            # Start the actual packet capture
            scapy.sniff(
                iface=selected_interface,
                prn=self.process_packet,
                store=0,
                filter="ip",
                stop_filter=lambda _: not self.sniffing_flag
            )
        except Exception as e:
            # self.root.after(0, lambda: messagebox.showerror("Error", f"Sniffing error: {str(e)}"))
            self.root.after(0, self.stop_sniffing)

    def start_sniffing(self):
        if self.sniffing_flag:
            messagebox.showinfo("Info", "Sniffing is already running.")
            return
            
        try:
            self.packet_listbox.delete(0, tk.END)
            self.log_text.config(state=tk.NORMAL)
            self.log_text.delete(1.0, tk.END)
            self.log_text.insert(tk.END, "=== IDS Alerts Log ===\n\n")
            self.log_text.config(state=tk.DISABLED)
            
            self.packet_stats = {
                'total': 0, 
                'tcp': 0, 
                'udp': 0, 
                'alerts': 0,
                'port_scan': 0,
                'syn_flood': 0,
                'suspicious_port': 0
            }
            self.connection_tracker.clear()
            self.port_scan_tracker.clear()
            
            self.status_label.config(text="🔄 Status: Starting capture...")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.interface_combo.config(state=tk.DISABLED)
            
            self.sniffing_flag = True
            self.capture_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.capture_thread.start()
            
            self.root.after(1000, lambda: self.status_label.config(text="✅ Status: Capturing"))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {str(e)}")
            self.stop_sniffing()

    def stop_sniffing(self):
        self.sniffing_flag = False
        self.interface_combo.config(state=tk.NORMAL)
        self.status_label.config(text="⏹ Status: Stopped")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Capture stopped\n")
        self.log_text.config(state=tk.DISABLED)

    def update_stats(self):
        """Update the statistics display"""
        self.total_label.config(text=f"📦 Total Packets: {self.packet_stats['total']}")
        self.tcp_label.config(text=f"🔷 TCP: {self.packet_stats['tcp']}")
        self.udp_label.config(text=f"🔶 UDP: {self.packet_stats['udp']}")
        self.alerts_label.config(text=f"🚨 Alerts: {self.packet_stats['alerts']}")

    def create_graph(self):
        # Create figure with subplots
        self.fig = Figure(figsize=(12, 6), dpi=100)
        
        # Traffic vs Alerts subplot
        self.ax1 = self.fig.add_subplot(121)
        self.ax2 = self.fig.add_subplot(122)
        
        # Set style for both subplots
        for ax in [self.ax1, self.ax2]:
            ax.set_facecolor('#f8f9fa')
            
        self.fig.set_facecolor('#f0f5f9')
        self.fig.tight_layout()
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab3)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    def update_graph(self):
        if self.sniffing_flag:
            current_time = time.time() - self.start_time
            
            # Add new data point
            new_point = {
                'time': current_time,
                'total_traffic': self.packet_stats['total'],
                'alerts': self.packet_stats['alerts'],
                'port_scan': self.packet_stats['port_scan'],
                'syn_flood': self.packet_stats['syn_flood'],
                'suspicious_port': self.packet_stats['suspicious_port']
            }
            self.data_points.append(new_point)
            
            # Keep only the last max_points
            if len(self.data_points) > self.max_points:
                self.data_points.pop(0)
            
            # Convert to DataFrame
            df = pd.DataFrame(self.data_points)
            
            # Clear previous plots
            self.ax1.clear()
            self.ax2.clear()
            
            # Plot Traffic vs Alerts using Seaborn
            if not df.empty:
                # Line plot for traffic and alerts
                sns.lineplot(data=df, x='time', y='total_traffic', 
                           label='Total Traffic', ax=self.ax1, 
                           color='#3498db', linewidth=2)
                sns.lineplot(data=df, x='time', y='alerts', 
                           label='Alerts', ax=self.ax1, 
                           color='#e74c3c', linewidth=2)
                
                # Line plot for different types of intrusions
                sns.lineplot(data=df, x='time', y='port_scan', 
                           label='Port Scan', ax=self.ax2, 
                           color='#e67e22', linewidth=2)
                sns.lineplot(data=df, x='time', y='syn_flood', 
                           label='SYN Flood', ax=self.ax2, 
                           color='#9b59b6', linewidth=2)
                sns.lineplot(data=df, x='time', y='suspicious_port', 
                           label='Suspicious Port', ax=self.ax2, 
                           color='#2ecc71', linewidth=2)
                
                # Customize plots
                self.ax1.set_title('Network Traffic vs Alerts', fontsize=10, pad=10)
                self.ax1.set_xlabel('Time (s)', fontsize=8)
                self.ax1.set_ylabel('Count', fontsize=8)
                
                self.ax2.set_title('Intrusion Types Distribution', fontsize=10, pad=10)
                self.ax2.set_xlabel('Time (s)', fontsize=8)
                self.ax2.set_ylabel('Count', fontsize=8)
                
                # Rotate x-axis labels for better readability
                for ax in [self.ax1, self.ax2]:
                    ax.tick_params(axis='both', which='major', labelsize=8)
                    ax.legend(fontsize=8)
                
                # Add grid with lower alpha for better visibility
                self.ax1.grid(True, alpha=0.3)
                self.ax2.grid(True, alpha=0.3)
                
                # Adjust layout
                self.fig.tight_layout()
            
            # Redraw canvas
            self.canvas.draw()
        
        # Schedule next update
        self.root.after(1000, self.update_graph)

    def create_stats_display(self):
        # Create a frame for detailed statistics
        stats_detail_frame = ttk.LabelFrame(self.tab3, text="Detailed Statistics", padding=10)
        stats_detail_frame.pack(fill=tk.X, pady=(10, 0))

        # Create labels for each statistic with modern styling
        self.detailed_stats = {}
        stats_items = [
            ('Total Traffic', 'total'),
            ('Alerts', 'alerts'),
            ('Port Scans', 'port_scan'),
            ('SYN Floods', 'syn_flood'),
            ('Suspicious Ports', 'suspicious_port')
        ]

        for i, (label_text, stat_key) in enumerate(stats_items):
            frame = ttk.Frame(stats_detail_frame)
            frame.grid(row=0, column=i, padx=10)
            
            ttk.Label(frame, text=label_text, style='SubHeader.TLabel').pack()
            stat_label = ttk.Label(frame, text="0", style='Stats.TLabel')
            stat_label.pack()
            self.detailed_stats[stat_key] = stat_label

    def update_stats_display(self):
        # Update detailed statistics
        for key, label in self.detailed_stats.items():
            label.config(text=str(self.packet_stats[key]))

    def detect_threats(self, packet, src_ip, dst_ip, src_port, dst_port, flags):
        alerts = []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            # Port scan detection with improved tracking
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = {
                    'ports': set(),
                    'last_seen': time.time(),
                    'count': 0
                }
            
            tracker = self.port_scan_tracker[src_ip]
            current_time = time.time()
            
            # Reset counter if too much time has passed
            if current_time - tracker['last_seen'] > 5:  # 5 seconds window
                tracker['ports'].clear()
                tracker['count'] = 0
            
            tracker['last_seen'] = current_time
            tracker['ports'].add(dst_port)
            tracker['count'] += 1
            
            # Alert if many different ports are scanned in a short time
            if len(tracker['ports']) > 5 or tracker['count'] > 10:
                alerts.append({
                    'type': 'Port Scan',
                    'severity': 'High',
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'details': f"Scanned ports: {', '.join(map(str, tracker['ports']))}",
                    'icon': '🔍'
                })
                self.packet_stats['port_scan'] += 1
                tracker['ports'].clear()
                tracker['count'] = 0

            # SYN flood detection with improved tracking
            if flags == 0x02:  # SYN flag
                if src_ip not in self.connection_tracker:
                    self.connection_tracker[src_ip] = {
                        'count': 0,
                        'first_seen': current_time,
                        'ports': set()
                    }
                
                conn_track = self.connection_tracker[src_ip]
                conn_track['count'] += 1
                conn_track['ports'].add(dst_port)
                
                # Alert if many SYN packets in a short time
                if (current_time - conn_track['first_seen'] <= 3 and  # 3 seconds window
                    conn_track['count'] > 10):
                    alerts.append({
                        'type': 'SYN Flood',
                        'severity': 'Critical',
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'details': f"SYN flood: {conn_track['count']} packets to ports {', '.join(map(str, conn_track['ports']))}",
                        'icon': '⚠️'
                    })
                    self.packet_stats['syn_flood'] += 1
                    self.connection_tracker[src_ip] = {
                        'count': 0,
                        'first_seen': current_time,
                        'ports': set()
                    }

            # Suspicious port detection with context
            suspicious_ports = {
                21: 'FTP',
                22: 'SSH',
                23: 'Telnet',
                3389: 'RDP',
                445: 'SMB',
                1433: 'MSSQL',
                3306: 'MySQL'
            }
            
            if dst_port in suspicious_ports:
                alerts.append({
                    'type': 'Suspicious Port',
                    'severity': 'Medium',
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'details': f"Connection attempt to {suspicious_ports[dst_port]} (Port {dst_port})",
                    'icon': '🚨'
                })
                self.packet_stats['suspicious_port'] += 1

            # Custom rule checking
            for rule in self.custom_rules:
                if self.check_rule_match(packet, rule, src_ip, dst_ip, src_port, dst_port):
                    alerts.append({
                        'type': 'Custom Rule',
                        'severity': 'High',
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'details': f"Matched rule: {rule.get('name', 'Unnamed')} - {rule.get('description', '')}",
                        'icon': '⚡'
                    })

            if alerts:
                self.packet_stats['alerts'] += len(alerts)
                for alert in alerts:
                    self.log_alert(alert)
                return True

            return False

        except Exception as e:
            print(f"Error in detect_threats: {e}")
            return False

    def log_alert(self, alert):
        """Enhanced alert logging with formatting"""
        try:
            self.log_text.config(state=tk.NORMAL)
            
            # Create formatted alert message
            alert_message = (
                f"\n{alert['icon']} [{alert['timestamp']}] "
                f"{alert['type'].upper()} - Severity: {alert['severity']}\n"
                f"    Source IP: {alert['src_ip']}\n"
                f"    Destination IP: {alert['dst_ip']}\n"
                f"    Details: {alert['details']}\n"
                f"{'='*50}\n"
            )
            
            # Add alert with appropriate tag based on severity
            if alert['severity'] == 'Critical':
                self.log_text.tag_configure("critical", foreground="#e74c3c", font=('Consolas', 10, 'bold'))
                self.log_text.insert(tk.END, alert_message, "critical")
            elif alert['severity'] == 'High':
                self.log_text.tag_configure("high", foreground="#e67e22", font=('Consolas', 10, 'bold'))
                self.log_text.insert(tk.END, alert_message, "high")
            elif alert['severity'] == 'Medium':
                self.log_text.tag_configure("medium", foreground="#f1c40f", font=('Consolas', 10))
                self.log_text.insert(tk.END, alert_message, "medium")
            else:
                self.log_text.tag_configure("low", foreground="#2ecc71", font=('Consolas', 10))
                self.log_text.insert(tk.END, alert_message, "low")
            
            # Auto-scroll to the bottom
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
            
            # Update statistics display
            self.update_stats()
            
        except Exception as e:
            print(f"Error in log_alert: {e}")

    def create_alert_tab(self):
        """Create enhanced alert tab with filtering and search"""
        self.tab2 = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.tab2, text="🚨 Alerts & Logs")

        # Create alert controls frame
        control_frame = ttk.Frame(self.tab2)
        control_frame.pack(fill=tk.X, pady=(0, 5))

        # Add severity filter
        ttk.Label(control_frame, text="Severity Filter:").pack(side=tk.LEFT, padx=5)
        self.severity_var = tk.StringVar(value="All")
        severity_combo = ttk.Combobox(control_frame, 
                                     textvariable=self.severity_var,
                                     values=["All", "Critical", "High", "Medium", "Low"],
                                     state="readonly",
                                     width=10)
        severity_combo.pack(side=tk.LEFT, padx=5)

        # Add alert type filter
        ttk.Label(control_frame, text="Alert Type:").pack(side=tk.LEFT, padx=5)
        self.alert_type_var = tk.StringVar(value="All")
        alert_type_combo = ttk.Combobox(control_frame,
                                       textvariable=self.alert_type_var,
                                       values=["All", "Port Scan", "SYN Flood", "Suspicious Port", "Custom Rule"],
                                       state="readonly",
                                       width=15)
        alert_type_combo.pack(side=tk.LEFT, padx=5)

        # Add search box
        ttk.Label(control_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(control_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Create the log text widget with improved styling
        self.log_text = tk.Text(self.tab2,
                               wrap=tk.WORD,
                               font=('Consolas', 10),
                               bg='#ffffff',
                               fg='#2c3e50')
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add scrollbar
        log_scrollbar = ttk.Scrollbar(self.tab2, orient="vertical",
                                    command=self.log_text.yview)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=log_scrollbar.set)
        
        # Initialize the log
        self.log_text.insert(tk.END, "=== IDS Alerts Log ===\n\n")
        self.log_text.config(state=tk.DISABLED)

        # Bind filters to update function
        def update_filters(*args):
            self.filter_alerts()

        severity_combo.bind('<<ComboboxSelected>>', update_filters)
        alert_type_combo.bind('<<ComboboxSelected>>', update_filters)
        self.search_var.trace('w', update_filters)

    def filter_alerts(self):
        """Filter alerts based on selected criteria"""
        severity = self.severity_var.get()
        alert_type = self.alert_type_var.get()
        search_text = self.search_var.get().lower()

        # Store current alerts
        current_text = self.log_text.get(1.0, tk.END)
        alerts = current_text.split('='*50 + '\n')

        # Clear current display
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, "=== IDS Alerts Log ===\n\n")

        # Apply filters
        for alert in alerts:
            if alert.strip():
                should_display = True
                
                # Check severity
                if severity != "All" and f"Severity: {severity}" not in alert:
                    should_display = False
                    
                # Check alert type
                if alert_type != "All" and alert_type not in alert:
                    should_display = False
                    
                # Check search text
                if search_text and search_text not in alert.lower():
                    should_display = False

                # Display if passes all filters
                if should_display:
                    # Determine severity for coloring
                    if "Severity: Critical" in alert:
                        self.log_text.insert(tk.END, alert + '='*50 + '\n', "critical")
                    elif "Severity: High" in alert:
                        self.log_text.insert(tk.END, alert + '='*50 + '\n', "high")
                    elif "Severity: Medium" in alert:
                        self.log_text.insert(tk.END, alert + '='*50 + '\n', "medium")
                    else:
                        self.log_text.insert(tk.END, alert + '='*50 + '\n', "low")

        self.log_text.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkIDS(root)
    root.mainloop()
