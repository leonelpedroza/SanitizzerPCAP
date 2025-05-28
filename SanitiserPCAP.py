#!/usr/bin/env python3
"""
PCAP/PCAPNG Sanitizer GUI

A GUI application for sanitizing PCAP and PCAPNG files by anonymizing MAC addresses, IP addresses, and VLAN IDs.

Requirements:
    pip install scapy
    
Optional (for better performance and pcapng support):
    pip install pypcapfile python-pcapng

Note: On Windows, you may also need to install Npcap from https://npcap.com/
"""

from datetime import datetime
import ipaddress
import os
import textwrap
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from random import randint
import json
import time
import sys
import subprocess
import tempfile
import csv

# Try to import optional modules
try:
    from pcapfile import savefile
    USE_PCAPFILE = True
except ImportError:
    USE_PCAPFILE = False

try:
    import pcapng
    from pcapng import FileScanner
    from pcapng.blocks import EnhancedPacket, SimplePacket, Packet
    USE_PCAPNG = True
except ImportError:
    USE_PCAPNG = False

try:
    from scapy.all import *
    from scapy.utils import PcapWriter, PcapReader, PcapNgReader
except ImportError:
    print("Error: Scapy is required. Please install it:")
    print("  pip install scapy")
    sys.exit(1)


class MACGenerator(object):
    def __init__(self, start_mac, sequential, mask):
        self.start_mac = self._last_mac = start_mac
        self.started = False
        self.mappings = {}
        self.sequential = sequential
        self.mask = mask

    def _increment(self, address):
        def pad_bin(unpadded):
            return format(int('0x' + unpadded.replace(':', '').replace('.', ''), 16), '048b')

        mac_bin = pad_bin(self._last_mac)

        if '0' not in mac_bin[self.mask:]:
            raise OverflowError('Ran out of MAC addresses, try a smaller mask or lower starting MAC.')

        if self.started:
            if self.mask > 0:
                masked = format(int(pad_bin(address)[:self.mask], 2), '0' + str(self.mask) + 'b')
                unmasked = format(int(mac_bin[self.mask:], 2) + 1, '0' + str(48 - self.mask) + 'b')
                returned_bin = format(int(masked + unmasked, 2), '012x')
            else:
                returned_bin = format(int(mac_bin, 2) + 1, '012x')
        else:
            self.started = True
            if self.mask > 0:
                masked = format(int(pad_bin(address)[:self.mask], 2), '0%sb' % str(self.mask))
                unmasked = format(int(mac_bin[self.mask:], 2), '0%sb' % str(48 - self.mask))
                returned_bin = format(int(masked + unmasked, 2), '012x')
            else:
                returned_bin = format(int(mac_bin, 2), '012x')

        return ':'.join(textwrap.wrap(returned_bin, 2))

    def _random_mac(self, address):
        def pad_bin(unpadded):
            return format(int('0x' + unpadded.replace(':', '').replace('.', ''), 16), '048b')

        unmasked = ''.join(str(randint(0, 1)) for x in range(0, 48 - self.mask))
        full_bin = pad_bin(address)[:self.mask] + unmasked
        return ':'.join(textwrap.wrap(format(int(full_bin, 2), '012x'), 2))

    def _next_mac(self, address):
        if self.sequential:
            self._last_mac = self._increment(address)
        else:
            self._last_mac = self._random_mac(address)

        if self._last_mac not in iter(self.mappings.values()):
            return self._last_mac
        else:
            return self._next_mac(address)

    def get_mac(self, address):
        generic_addresses = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00']
        if address not in generic_addresses:
            try:
                return self.mappings[address]
            except KeyError:
                self.mappings[address] = self._next_mac(address)
                return self.mappings[address]
        else:
            return address


class IPv4Generator(object):
    def __init__(self, start_ip, sequential, mask):
        self.start_ip = self._last_ip = start_ip
        self.started = False
        self.mappings = {}
        self.sequential = sequential
        self.mask = mask

    def _increment(self, address):
        def pad_bin(unpadded):
            return format(int(ipaddress.IPv4Address(str(unpadded))), '032b')

        ip_bin = pad_bin(self._last_ip)

        if '0' not in ip_bin[self.mask:]:
            raise OverflowError('Ran out of IP addresses, try a smaller mask or lower starting IP.')

        if self.started:
            full_bin = pad_bin(address)[:self.mask] + format(int(ip_bin[self.mask:], 2) + 1,
                                                             '0' + str(32 - self.mask) + 'b')
        else:
            self.started = True
            full_bin = pad_bin(address)[:self.mask] + format(int(ip_bin[self.mask:], 2),
                                                             '0' + str(32 - self.mask) + 'b')

        return str(ipaddress.IPv4Address(int(full_bin, 2)))

    def _random_ip(self, address):
        def pad_bin(unpadded):
            return format(int(ipaddress.IPv4Address(str(unpadded))), '032b')

        unmasked = ''.join(str(randint(0, 1)) for _ in range(0, 32 - self.mask))

        if self.started:
            full_bin = pad_bin(address)[:self.mask] + unmasked
        else:
            self.started = True
            full_bin = pad_bin(address)[:self.mask] + unmasked

        return str(ipaddress.IPv4Address(int(full_bin, 2)))

    def _next_ip(self, address):
        if self.sequential:
            self._last_ip = self._increment(address)
        else:
            self._last_ip = self._random_ip(address)

        if self._last_ip not in iter(self.mappings.values()):
            return self._last_ip
        else:
            return self._next_ip(address)

    def get_ip(self, address):
        generic_addresses = ['255.255.255.255', '0.0.0.0']
        if address not in generic_addresses:
            try:
                return self.mappings[address]
            except KeyError:
                self.mappings[address] = self._next_ip(address)
                return self.mappings[address]
        else:
            return address


class IPv6Generator(object):
    def __init__(self, start_ip, sequential, mask):
        self.start_ip = self._last_ip = start_ip
        self.started = False
        self.mappings = {}
        self.sequential = sequential
        self.mask = mask

    def _increment(self, address):
        def pad_bin(unpadded):
            return format(int(ipaddress.IPv6Address(str(unpadded))), '0128b')

        ip_bin = pad_bin(self._last_ip)

        if '0' not in ip_bin[self.mask:]:
            raise OverflowError('Ran out of IP addresses, try a smaller mask or lower starting IP.')

        if self.started:
            full_bin = pad_bin(address)[:self.mask] + format(int(ip_bin[self.mask:], 2) + 1,
                                                             '0' + str(128 - self.mask) + 'b')
        else:
            self.started = True
            full_bin = pad_bin(address)[:self.mask] + format(int(ip_bin[self.mask:], 2),
                                                             '0' + str(128 - self.mask) + 'b')

        return str(ipaddress.IPv6Address(int(full_bin, 2)))

    def _random_ip(self, address):
        def pad_bin(unpadded):
            return format(int(ipaddress.IPv6Address(str(unpadded))), '0128b')

        unmasked = ''.join(str(randint(0, 1)) for _ in range(0, 128 - self.mask))

        if self.started:
            full_bin = pad_bin(address)[:self.mask] + unmasked
        else:
            self.started = True
            full_bin = pad_bin(address)[:self.mask] + unmasked

        return str(ipaddress.IPv6Address(int(full_bin, 2)))

    def _next_ip(self, address):
        if self.sequential:
            self._last_ip = self._increment(address)
        else:
            self._last_ip = self._random_ip(address)

        if self._last_ip not in iter(self.mappings.values()):
            return self._last_ip
        else:
            return self._next_ip(address)

    def get_ip(self, address):
        if not address.startswith("ff02"):
            try:
                return self.mappings[address]
            except KeyError:
                self.mappings[address] = self._next_ip(address)
                return self.mappings[address]
        else:
            return address


class PCAPSanitizerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP/PCAPNG Sanitizer GUI")
        self.root.geometry("900x700")
        
        # Set application icon
        self.set_application_icon()
        
        # Variables
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.progress = tk.DoubleVar()
        self.status_text = tk.StringVar(value="Ready")
        
        # Settings variables
        self.sequential = tk.BooleanVar(value=True)
        self.append = tk.BooleanVar(value=False)
        self.ipv4_mask = tk.IntVar(value=0)
        self.ipv6_mask = tk.IntVar(value=0)
        self.mac_mask = tk.IntVar(value=0)
        self.start_ipv4 = tk.StringVar(value="10.0.0.1")
        self.start_ipv6 = tk.StringVar(value="2001:aa::1")
        self.start_mac = tk.StringVar(value="00:aa:00:00:00:01")
        self.fixed_vlan = tk.StringVar(value="")
        self.output_format = tk.StringVar(value="pcap")
        
        # Results storage
        self.conversion_log = {}
        self.processing_thread = None
        
        self.create_widgets()
        
        # Check dependencies on startup
        self.check_dependencies()
    
    def set_application_icon(self):
        """Set the application icon for all platforms"""
        # Icon data (base64 encoded PNG)
        icondata = '''
        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
        '''
        
        try:
            # Create PhotoImage from base64 data
            icon = tk.PhotoImage(data=icondata)
            
            # Set icon for all platforms
            self.root.iconphoto(True, icon)
            
            # Additional platform-specific icon setting
            if sys.platform.startswith('win'):
                # Windows specific
                self.root.iconphoto(False, icon)
            elif sys.platform.startswith('darwin'):
                # macOS specific - may need additional handling
                pass
            else:
                # Linux/Unix
                self.root.tk.call('wm', 'iconphoto', self.root._w, icon)
                
        except Exception as e:
            # If icon fails to load, just continue without it
            print(f"Warning: Could not set application icon: {e}")
        
    def check_dependencies(self):
        """Check if required dependencies are installed"""
        missing = []
        warnings = []
        
        if not USE_PCAPFILE:
            missing.append("pypcapfile (optional, for better pcap performance)")
            
        if not USE_PCAPNG:
            warnings.append("python-pcapng (required for native pcapng support)")
            
        # Check for editcap
        if not self.check_editcap():
            warnings.append("editcap (from Wireshark) for pcapng conversion fallback")
            
        if warnings:
            deps_msg = "Missing optional dependencies:\n\n"
            deps_msg += "\n".join(f"- {dep}" for dep in missing + warnings)
            deps_msg += "\n\nThe application will work but with limitations."
            if not USE_PCAPNG:
                deps_msg += "\n\nFor pcapng support, install: pip install python-pcapng"
            
            self.status_text.set("Some optional dependencies missing (see Help)")
            
    def check_editcap(self):
        """Check if editcap is available"""
        try:
            subprocess.run(['editcap', '-v'], capture_output=True, check=False)
            return True
        except FileNotFoundError:
            return False
        
    def create_widgets(self):
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Main tab
        main_frame = ttk.Frame(notebook)
        notebook.add(main_frame, text="Main")
        self.create_main_tab(main_frame)
        
        # Settings tab
        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text="Settings")
        self.create_settings_tab(settings_frame)
        
        # Results tab
        results_frame = ttk.Frame(notebook)
        notebook.add(results_frame, text="Results")
        self.create_results_tab(results_frame)
        
        # Help tab
        help_frame = ttk.Frame(notebook)
        notebook.add(help_frame, text="Help")
        self.create_help_tab(help_frame)
        
    def create_main_tab(self, parent):
        # File selection frame
        file_frame = ttk.LabelFrame(parent, text="File Selection", padding=10)
        file_frame.pack(fill="x", padx=10, pady=10)
        
        # Input file
        ttk.Label(file_frame, text="Input File:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(file_frame, textvariable=self.input_file, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_input_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Output file
        ttk.Label(file_frame, text="Output File:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(file_frame, textvariable=self.output_file, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_output_file).grid(row=1, column=2, padx=5, pady=5)
        
        # Output format
        ttk.Label(file_frame, text="Output Format:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        format_frame = ttk.Frame(file_frame)
        format_frame.grid(row=2, column=1, sticky="w", padx=5, pady=5)
        ttk.Radiobutton(format_frame, text="PCAP", variable=self.output_format, 
                       value="pcap", command=self.update_output_extension).pack(side="left", padx=10)
        ttk.Radiobutton(format_frame, text="PCAPNG", variable=self.output_format, 
                       value="pcapng", command=self.update_output_extension).pack(side="left", padx=10)
        
        # Control frame with process and save buttons
        control_frame = ttk.LabelFrame(parent, text="Actions", padding=10)
        control_frame.pack(fill="x", padx=10, pady=10)
        
        # Create a centered button container
        button_container = ttk.Frame(control_frame)
        button_container.pack()
        
        # Process button
        self.process_button = ttk.Button(button_container, text="▶️ Process File", command=self.process_pcap, width=20)
        self.process_button.pack(side="left", padx=5)
        
        # Save log button (disabled initially)
        self.save_log_button = ttk.Button(button_container, text="💾 Save Log File", command=self.save_log_file, width=20, state="disabled")
        self.save_log_button.pack(side="left", padx=5)
        
        # Progress frame
        progress_frame = ttk.LabelFrame(parent, text="Progress", padding=10)
        progress_frame.pack(fill="x", padx=10, pady=10)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress, maximum=100)
        self.progress_bar.pack(fill="x", padx=5, pady=5)
        
        # Status label
        ttk.Label(progress_frame, textvariable=self.status_text).pack(pady=5)
        
        # Summary frame
        self.summary_frame = ttk.LabelFrame(parent, text="Summary", padding=10)
        self.summary_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.summary_text = scrolledtext.ScrolledText(self.summary_frame, height=10, width=70)
        self.summary_text.pack(fill="both", expand=True)
        
    def create_settings_tab(self, parent):
        # Create scrollable frame
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # General settings
        general_frame = ttk.LabelFrame(scrollable_frame, text="General Settings", padding=10)
        general_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Checkbutton(general_frame, text="Use Sequential IPs/MACs", 
                       variable=self.sequential).pack(anchor="w", pady=5)
        ttk.Checkbutton(general_frame, text="Append to output file", 
                       variable=self.append).pack(anchor="w", pady=5)
        
        # Mask settings
        mask_frame = ttk.LabelFrame(scrollable_frame, text="Mask Settings", padding=10)
        mask_frame.pack(fill="x", padx=10, pady=10)
        
        # IPv4 mask
        ttk.Label(mask_frame, text="IPv4 Mask (0-32):").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Spinbox(mask_frame, from_=0, to=32, textvariable=self.ipv4_mask, width=10).grid(row=0, column=1, padx=5, pady=5)
        ttk.Label(mask_frame, text="(e.g., 8 preserves first octet)").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        
        # IPv6 mask
        ttk.Label(mask_frame, text="IPv6 Mask (0-128):").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        ttk.Spinbox(mask_frame, from_=0, to=128, textvariable=self.ipv6_mask, width=10).grid(row=1, column=1, padx=5, pady=5)
        ttk.Label(mask_frame, text="(e.g., 16 preserves first segment)").grid(row=1, column=2, sticky="w", padx=5, pady=5)
        
        # MAC mask
        ttk.Label(mask_frame, text="MAC Mask (0-48):").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        ttk.Spinbox(mask_frame, from_=0, to=48, textvariable=self.mac_mask, width=10).grid(row=2, column=1, padx=5, pady=5)
        ttk.Label(mask_frame, text="(e.g., 24 preserves manufacturer)").grid(row=2, column=2, sticky="w", padx=5, pady=5)
        
        # Starting addresses
        start_frame = ttk.LabelFrame(scrollable_frame, text="Starting Addresses", padding=10)
        start_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(start_frame, text="Start IPv4:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(start_frame, textvariable=self.start_ipv4, width=20).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(start_frame, text="Start IPv6:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(start_frame, textvariable=self.start_ipv6, width=30).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(start_frame, text="Start MAC:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(start_frame, textvariable=self.start_mac, width=20).grid(row=2, column=1, padx=5, pady=5)
        
        # VLAN settings
        vlan_frame = ttk.LabelFrame(scrollable_frame, text="VLAN Settings", padding=10)
        vlan_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Label(vlan_frame, text="Fixed VLAN ID (leave empty for no change):").pack(anchor="w", pady=5)
        ttk.Entry(vlan_frame, textvariable=self.fixed_vlan, width=10).pack(anchor="w", padx=20, pady=5)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def create_results_tab(self, parent):
        # Create a frame to hold everything
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Button frame at the TOP for better visibility
        button_frame = ttk.LabelFrame(main_frame, text="Export Options", padding=10)
        button_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        # Create buttons with better styling
        save_btn = ttk.Button(button_frame, text="💾 Save Log File", command=self.save_log_file, width=20)
        save_btn.pack(side="left", padx=5)
        
        clear_btn = ttk.Button(button_frame, text="🗑️ Clear Results", command=self.clear_results, width=20)
        clear_btn.pack(side="left", padx=5)
        
        # Add label for file format info
        ttk.Label(button_frame, text="Formats: TXT, CSV, HTML, JSON", foreground="gray").pack(side="left", padx=20)
        
        # Results text area with monospace font for better table alignment
        results_frame = ttk.LabelFrame(main_frame, text="Conversion Mappings", padding=5)
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=20, width=80, font=("Courier", 10))
        self.results_text.pack(fill="both", expand=True)
        
    def create_help_tab(self, parent):
        help_text = scrolledtext.ScrolledText(parent, height=20, width=80, wrap=tk.WORD)
        help_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        help_content = """PCAP/PCAPNG Sanitizer GUI - Help

This tool sanitizes PCAP and PCAPNG files by replacing MAC addresses, IP addresses, and optionally VLAN IDs with anonymized values.

SUPPORTED FORMATS:
- PCAP (classic format) - Full support
- PCAPNG (next generation format) - Supported with python-pcapng or editcap

INSTALLATION:
Required packages:
  pip install scapy

Optional packages:
  pip install pypcapfile      # Better PCAP performance
  pip install python-pcapng   # Native PCAPNG support

External tools (optional):
  - Wireshark (includes editcap) - For PCAPNG conversion fallback
  - On Windows: Npcap from https://npcap.com/

MAIN TAB:
- Select input file (PCAP or PCAPNG)
- Choose output file location and format
- Click "Process File" to start sanitization
- Monitor progress and view summary

SETTINGS TAB:
- Sequential: Use sequential addresses instead of random
- Append: Append to existing output file instead of overwriting
- Masks: Preserve parts of addresses (e.g., IPv4 mask of 8 preserves first octet)
- Starting Addresses: Set the starting point for sequential address generation
- Fixed VLAN: Replace all VLAN IDs with this value (leave empty to preserve original)

OUTPUT FORMAT:
- PCAP: Classic format, widely supported
- PCAPNG: Next generation format, preserves more metadata (requires python-pcapng)

RESULTS TAB:
- View detailed conversion mappings
- Save log file for future reference
- Log includes all address mappings (original → sanitized)

PCAPNG SUPPORT:
The program handles PCAPNG files in three ways:
1. Native support with python-pcapng (best option)
2. Conversion using editcap if available
3. Scapy's limited PCAPNG support (may not work for all files)

TIPS:
- Use masks to preserve network structure
- Sequential mode is useful for analysis
- Random mode provides better anonymization
- Save the log file for reverse-lookup capabilities
- For large PCAPNG files, native support is faster than conversion

TROUBLESHOOTING:
- "No module named 'pcapng'": Install with 'pip install python-pcapng'
- "No module named 'scapy'": Install with 'pip install scapy'
- "editcap not found": Install Wireshark for conversion fallback
- PCAPNG issues: Try converting to PCAP first with editcap
- On Windows: Install Npcap if you get packet capture errors

LIMITATIONS:
- Very large files may take time to process
- Some PCAPNG-specific features may be lost when converting to PCAP
- Ensure sufficient memory for large capture files"""
        
        help_text.insert("1.0", help_content)
        help_text.config(state="disabled")
        
    def update_output_extension(self):
        """Update output file extension based on selected format"""
        if self.output_file.get():
            base = os.path.splitext(self.output_file.get())[0]
            if self.output_format.get() == "pcapng":
                self.output_file.set(base + ".pcapng")
            else:
                self.output_file.set(base + ".pcap")
                
    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            title="Select capture file",
            filetypes=[
                ("All capture files", "*.pcap *.cap *.pcapng"),
                ("PCAP files", "*.pcap *.cap"),
                ("PCAPNG files", "*.pcapng"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.input_file.set(filename)
            # Auto-generate output filename
            timestamp = datetime.now().strftime('%y%m%d-%H%M%S')
            base = os.path.splitext(filename)[0]
            
            # Detect input format and set output format accordingly
            if filename.lower().endswith('.pcapng'):
                if USE_PCAPNG:
                    self.output_format.set("pcapng")
                    ext = ".pcapng"
                else:
                    self.output_format.set("pcap")
                    ext = ".pcap"
            else:
                self.output_format.set("pcap")
                ext = ".pcap"
                
            output = f"{base}_sanitized_{timestamp}{ext}"
            self.output_file.set(output)
            
    def browse_output_file(self):
        ext = ".pcapng" if self.output_format.get() == "pcapng" else ".pcap"
        filename = filedialog.asksaveasfilename(
            title="Save sanitized file as",
            defaultextension=ext,
            filetypes=[
                ("PCAP files", "*.pcap") if ext == ".pcap" else ("PCAPNG files", "*.pcapng"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.output_file.set(filename)
            
    def process_pcap(self):
        if not self.input_file.get():
            messagebox.showerror("Error", "Please select an input file")
            return
            
        if not self.output_file.get():
            messagebox.showerror("Error", "Please specify an output file")
            return
            
        # Disable process button
        self.process_button.config(state="disabled")
        
        # Clear previous results
        self.summary_text.delete(1.0, tk.END)
        self.results_text.delete(1.0, tk.END)
        self.conversion_log.clear()
        
        # Start processing in a separate thread
        self.processing_thread = threading.Thread(target=self.sanitize_pcap)
        self.processing_thread.start()
        
    def detect_file_format(self, filename):
        """Detect if file is PCAP or PCAPNG"""
        with open(filename, 'rb') as f:
            magic = f.read(4)
            if magic == b'\xa1\xb2\xc3\xd4' or magic == b'\xd4\xc3\xb2\xa1':
                return 'pcap'
            elif magic == b'\x0a\x0d\x0d\x0a':
                return 'pcapng'
            else:
                # Try to detect by extension
                if filename.lower().endswith('.pcapng'):
                    return 'pcapng'
                else:
                    return 'pcap'
                    
    def sanitize_pcap(self):
        try:
            self.status_text.set("Processing...")
            self.progress.set(0)
            
            # Detect input format
            input_format = self.detect_file_format(self.input_file.get())
            self.status_text.set(f"Detected {input_format.upper()} format...")
            
            # Get settings
            fixed_vlan = None
            if self.fixed_vlan.get().strip():
                try:
                    fixed_vlan = int(self.fixed_vlan.get())
                except ValueError:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Invalid VLAN ID"))
                    return
                    
            # Initialize generators
            mac_gen = MACGenerator(
                sequential=self.sequential.get(),
                mask=self.mac_mask.get(),
                start_mac=self.start_mac.get()
            )
            ip4_gen = IPv4Generator(
                sequential=self.sequential.get(),
                mask=self.ipv4_mask.get(),
                start_ip=self.start_ipv4.get()
            )
            ip6_gen = IPv6Generator(
                sequential=self.sequential.get(),
                mask=self.ipv6_mask.get(),
                start_ip=self.start_ipv6.get()
            )
            
            vlan_changes = {}
            
            # Process based on input format
            if input_format == 'pcapng':
                total_packets = self.process_pcapng(mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
            else:
                total_packets = self.process_pcap_file(mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
                
            # Store conversion log
            self.conversion_log = {
                'MAC_mappings': mac_gen.mappings,
                'IPv4_mappings': ip4_gen.mappings,
                'IPv6_mappings': ip6_gen.mappings,
                'VLAN_mappings': vlan_changes,
                'settings': {
                    'sequential': self.sequential.get(),
                    'ipv4_mask': self.ipv4_mask.get(),
                    'ipv6_mask': self.ipv6_mask.get(),
                    'mac_mask': self.mac_mask.get(),
                    'start_ipv4': self.start_ipv4.get(),
                    'start_ipv6': self.start_ipv6.get(),
                    'start_mac': self.start_mac.get(),
                    'fixed_vlan': fixed_vlan,
                    'input_format': input_format,
                    'output_format': self.output_format.get()
                }
            }
            
            # Update UI with results
            self.root.after(0, self.show_results, len(mac_gen.mappings), 
                           len(ip4_gen.mappings), len(ip6_gen.mappings), 
                           len(vlan_changes), total_packets)
                           
            self.progress.set(100)
            self.status_text.set("Processing complete!")
            
        except Exception as e:
            error_msg = str(e)
            if "No supported Magic Number found" in error_msg:
                error_msg = "Error: File format not recognized. Try converting the file first."
            self.root.after(0, lambda: messagebox.showerror("Error", error_msg))
            self.status_text.set("Error occurred")
            
        finally:
            self.root.after(0, lambda: self.process_button.config(state="normal"))
            # Enable save log button after processing
            if hasattr(self, 'save_log_button'):
                self.root.after(0, lambda: self.save_log_button.config(state="normal"))
            
    def process_pcapng(self, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes):
        """Process PCAPNG file"""
        if USE_PCAPNG:
            # Use native pcapng support
            return self.process_pcapng_native(mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
        elif self.check_editcap():
            # Use editcap conversion
            return self.process_pcapng_editcap(mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
        else:
            # Try Scapy's limited support
            return self.process_pcapng_scapy(mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
            
    def process_pcapng_native(self, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes):
        """Process PCAPNG using python-pcapng"""
        self.status_text.set("Processing PCAPNG with native support...")
        
        # Count packets first
        total_packets = 0
        with open(self.input_file.get(), 'rb') as f:
            scanner = FileScanner(f)
            for block in scanner:
                if isinstance(block, (EnhancedPacket, SimplePacket, Packet)):
                    total_packets += 1
                    
        # Process packets
        pktwriter = PcapWriter(self.output_file.get(), append=self.append.get())
        packet_count = 0
        
        try:
            with open(self.input_file.get(), 'rb') as f:
                scanner = FileScanner(f)
                for block in scanner:
                    if isinstance(block, (EnhancedPacket, SimplePacket, Packet)):
                        packet_count += 1
                        # Update progress
                        progress_val = (packet_count / total_packets) * 100
                        self.progress.set(progress_val)
                        self.status_text.set(f"Processing packet {packet_count}/{total_packets}")
                        
                        # Get packet data
                        packet_data = block.packet_data
                        
                        # Create Scapy packet
                        pkt = Ether(packet_data)
                        
                        # Process packet
                        self._process_packet(pkt, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
                        
                        # Write to output
                        pktwriter.write(pkt)
                        
        finally:
            pktwriter.close()
            
        return total_packets
        
    def process_pcapng_editcap(self, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes):
        """Process PCAPNG by converting to PCAP first using editcap"""
        self.status_text.set("Converting PCAPNG to PCAP using editcap...")
        
        # Create temporary PCAP file
        temp_pcap = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        temp_pcap.close()
        
        try:
            # Convert PCAPNG to PCAP
            subprocess.run(['editcap', '-F', 'pcap', self.input_file.get(), temp_pcap.name], 
                          check=True, capture_output=True)
            
            # Process the temporary PCAP file
            self.input_file.set(temp_pcap.name)
            total_packets = self.process_pcap_file(mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
            
            # If output format is PCAPNG, convert back
            if self.output_format.get() == "pcapng":
                self.status_text.set("Converting output back to PCAPNG...")
                temp_output = self.output_file.get() + ".tmp"
                os.rename(self.output_file.get(), temp_output)
                subprocess.run(['editcap', '-F', 'pcapng', temp_output, self.output_file.get()], 
                             check=True, capture_output=True)
                os.remove(temp_output)
                
        finally:
            # Clean up temporary file
            if os.path.exists(temp_pcap.name):
                os.remove(temp_pcap.name)
                
        return total_packets
        
    def process_pcapng_scapy(self, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes):
        """Process PCAPNG using Scapy's limited support"""
        self.status_text.set("Processing PCAPNG with Scapy (limited support)...")
        
        try:
            # Try to use Scapy's PcapNgReader
            packets = rdpcap(self.input_file.get())
            total_packets = len(packets)
            
            pktwriter = PcapWriter(self.output_file.get(), append=self.append.get())
            
            try:
                for i, pkt in enumerate(packets):
                    # Update progress
                    progress_val = (i / total_packets) * 100
                    self.progress.set(progress_val)
                    self.status_text.set(f"Processing packet {i+1}/{total_packets}")
                    
                    # Process packet
                    self._process_packet(pkt, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
                    
                    pktwriter.write(pkt)
                    
            finally:
                pktwriter.close()
                
            return total_packets
            
        except Exception as e:
            raise Exception(f"Failed to process PCAPNG file. Error: {str(e)}\n\n"
                          "Please install python-pcapng or Wireshark (for editcap) "
                          "for better PCAPNG support.")
            
    def process_pcap_file(self, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes):
        """Process regular PCAP file"""
        if USE_PCAPFILE:
            # Use pcapfile method
            with open(self.input_file.get(), 'rb') as capfile:
                cap = savefile.load_savefile(capfile, verbose=False)
                total_packets = len(cap.packets)
                
                pktwriter = PcapWriter(self.output_file.get(), append=self.append.get())
                
                try:
                    for i, pkt in enumerate(cap.packets):
                        # Update progress
                        progress_val = (i / total_packets) * 100
                        self.progress.set(progress_val)
                        self.status_text.set(f"Processing packet {i+1}/{total_packets}")
                        
                        # Create scapy packet
                        new_pkt = Ether(pkt.raw())
                        
                        # Process packet
                        self._process_packet(new_pkt, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
                        
                        pktwriter.write(new_pkt)
                        
                finally:
                    pktwriter.close()
        else:
            # Use Scapy-only method
            # First, count packets
            self.status_text.set("Counting packets...")
            total_packets = 0
            with PcapReader(self.input_file.get()) as pcap_reader:
                for _ in pcap_reader:
                    total_packets += 1
            
            # Process packets
            pktwriter = PcapWriter(self.output_file.get(), append=self.append.get())
            
            try:
                with PcapReader(self.input_file.get()) as pcap_reader:
                    for i, pkt in enumerate(pcap_reader):
                        # Update progress
                        progress_val = (i / total_packets) * 100
                        self.progress.set(progress_val)
                        self.status_text.set(f"Processing packet {i+1}/{total_packets}")
                        
                        # Process packet
                        self._process_packet(pkt, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes)
                        
                        pktwriter.write(pkt)
                        
            finally:
                pktwriter.close()
                
        return total_packets
        
    def _process_packet(self, pkt, mac_gen, ip4_gen, ip6_gen, fixed_vlan, vlan_changes):
        """Process a single packet"""
        # MAC addresses
        try:
            pkt.src = mac_gen.get_mac(pkt.src)
            pkt.dst = mac_gen.get_mac(pkt.dst)
        except:
            pass
            
        # VLAN number
        if fixed_vlan is not None:
            try:
                orig_vlan = pkt['Dot1Q'].vlan
                pkt['Dot1Q'].vlan = fixed_vlan
                vlan_changes[orig_vlan] = fixed_vlan
            except:
                pass
                
        # IP Addresses
        try:
            pkt['IP'].src = ip4_gen.get_ip(pkt['IP'].src)
            pkt['IP'].dst = ip4_gen.get_ip(pkt['IP'].dst)
        except IndexError:
            pass
        try:
            pkt['IPv6'].src = ip6_gen.get_ip(pkt['IPv6'].src)
            pkt['IPv6'].dst = ip6_gen.get_ip(pkt['IPv6'].dst)
        except IndexError:
            pass
            
        # ARP addresses
        try:
            pkt['ARP'].hwsrc = mac_gen.get_mac(pkt['ARP'].hwsrc)
            pkt['ARP'].hwdst = mac_gen.get_mac(pkt['ARP'].hwdst)
            pkt['ARP'].psrc = ip4_gen.get_ip(pkt['ARP'].psrc)
            pkt['ARP'].pdst = ip4_gen.get_ip(pkt['ARP'].pdst)
        except IndexError:
            pass
            
        # Fix checksums
        for layer in range(12, 0, -1):
            try:
                del pkt[layer].chksum
            except:
                pass
                
    def show_results(self, mac_count, ipv4_count, ipv6_count, vlan_count, total_packets):
        # Update summary
        input_format = self.conversion_log['settings']['input_format'].upper()
        output_format = self.conversion_log['settings']['output_format'].upper()
        
        summary = f"""Processing Complete!

Total packets processed: {total_packets}
Input format: {input_format}
Output format: {output_format}
Output file: {self.output_file.get()}

Modifications:
- MAC addresses: {mac_count}
- IPv4 addresses: {ipv4_count}
- IPv6 addresses: {ipv6_count}
- VLAN IDs: {vlan_count}

Settings used:
- Sequential mode: {'Yes' if self.sequential.get() else 'No (Random)'}
- IPv4 mask: {self.ipv4_mask.get()} bits
- IPv6 mask: {self.ipv6_mask.get()} bits
- MAC mask: {self.mac_mask.get()} bits
"""
        self.summary_text.insert(1.0, summary)
        
        # Update results tab with formatted table
        self.update_results_display()
        
        # Show success message
        messagebox.showinfo("Success", f"File sanitized successfully!\n\n"
                                      f"Format: {input_format} → {output_format}\n"
                                      f"Total modifications:\n"
                                      f"- MAC addresses: {mac_count}\n"
                                      f"- IPv4 addresses: {ipv4_count}\n"
                                      f"- IPv6 addresses: {ipv6_count}\n"
                                      f"- VLAN IDs: {vlan_count}")
    
    def update_results_display(self):
        """Update the results tab with formatted conversion tables"""
        self.results_text.delete(1.0, tk.END)
        
        # Check if we have data to display
        if not self.conversion_log:
            self.results_text.insert(tk.END, "No conversion data available. Process a file first.\n")
            return
        
        # Header
        self.results_text.insert(tk.END, "=" * 80 + "\n", "header")
        self.results_text.insert(tk.END, "PCAP/PCAPNG SANITIZATION RESULTS\n", "header")
        self.results_text.insert(tk.END, "=" * 80 + "\n\n", "header")
        
        # Configure text tags for formatting
        self.results_text.tag_config("header", font=("Courier", 12, "bold"))
        self.results_text.tag_config("section", font=("Courier", 11, "bold"), foreground="blue")
        self.results_text.tag_config("table_header", font=("Courier", 10, "bold"), background="lightgray")
        self.results_text.tag_config("data", font=("Courier", 10))
        
        # Metadata
        metadata = f"""Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Input file: {self.input_file.get()}
Output file: {self.output_file.get()}
Input format: {self.conversion_log['settings'].get('input_format', 'Unknown').upper()}
Output format: {self.conversion_log['settings'].get('output_format', 'Unknown').upper()}

"""
        self.results_text.insert(tk.END, metadata, "data")
        
        # Settings
        self.results_text.insert(tk.END, "SANITIZATION SETTINGS:\n", "section")
        self.results_text.insert(tk.END, "-" * 40 + "\n", "data")
        settings = self.conversion_log.get('settings', {})
        settings_text = f"""Sequential mode: {'Yes' if settings.get('sequential', False) else 'No (Random)'}
IPv4 mask: {settings.get('ipv4_mask', 0)} bits
IPv6 mask: {settings.get('ipv6_mask', 0)} bits
MAC mask: {settings.get('mac_mask', 0)} bits
Starting IPv4: {settings.get('start_ipv4', 'N/A')}
Starting IPv6: {settings.get('start_ipv6', 'N/A')}
Starting MAC: {settings.get('start_mac', 'N/A')}
"""
        if settings.get('fixed_vlan'):
            settings_text += f"Fixed VLAN: {settings['fixed_vlan']}\n"
        settings_text += "\n"
        self.results_text.insert(tk.END, settings_text, "data")
        
        # MAC Address Mappings
        mac_mappings = self.conversion_log.get('MAC_mappings', {})
        if mac_mappings:
            self.results_text.insert(tk.END, "MAC ADDRESS MAPPINGS:\n", "section")
            self.results_text.insert(tk.END, "-" * 60 + "\n", "data")
            self.results_text.insert(tk.END, f"{'Original MAC':<20} | {'Sanitized MAC':<20}\n", "table_header")
            self.results_text.insert(tk.END, "-" * 60 + "\n", "data")
            
            for orig, new in sorted(mac_mappings.items()):
                self.results_text.insert(tk.END, f"{orig:<20} | {new:<20}\n", "data")
            self.results_text.insert(tk.END, f"\nTotal unique MAC addresses: {len(mac_mappings)}\n\n", "data")
        
        # IPv4 Address Mappings
        ipv4_mappings = self.conversion_log.get('IPv4_mappings', {})
        if ipv4_mappings:
            self.results_text.insert(tk.END, "IPv4 ADDRESS MAPPINGS:\n", "section")
            self.results_text.insert(tk.END, "-" * 60 + "\n", "data")
            self.results_text.insert(tk.END, f"{'Original IPv4':<20} | {'Sanitized IPv4':<20}\n", "table_header")
            self.results_text.insert(tk.END, "-" * 60 + "\n", "data")
            
            for orig, new in sorted(ipv4_mappings.items()):
                self.results_text.insert(tk.END, f"{orig:<20} | {new:<20}\n", "data")
            self.results_text.insert(tk.END, f"\nTotal unique IPv4 addresses: {len(ipv4_mappings)}\n\n", "data")
        
        # IPv6 Address Mappings
        ipv6_mappings = self.conversion_log.get('IPv6_mappings', {})
        if ipv6_mappings:
            self.results_text.insert(tk.END, "IPv6 ADDRESS MAPPINGS:\n", "section")
            self.results_text.insert(tk.END, "-" * 80 + "\n", "data")
            self.results_text.insert(tk.END, f"{'Original IPv6':<40} | {'Sanitized IPv6':<40}\n", "table_header")
            self.results_text.insert(tk.END, "-" * 80 + "\n", "data")
            
            for orig, new in sorted(ipv6_mappings.items()):
                self.results_text.insert(tk.END, f"{orig:<40} | {new:<40}\n", "data")
            self.results_text.insert(tk.END, f"\nTotal unique IPv6 addresses: {len(ipv6_mappings)}\n\n", "data")
        
        # VLAN Mappings
        vlan_mappings = self.conversion_log.get('VLAN_mappings', {})
        if vlan_mappings:
            self.results_text.insert(tk.END, "VLAN ID MAPPINGS:\n", "section")
            self.results_text.insert(tk.END, "-" * 40 + "\n", "data")
            self.results_text.insert(tk.END, f"{'Original VLAN':<15} | {'Sanitized VLAN':<15}\n", "table_header")
            self.results_text.insert(tk.END, "-" * 40 + "\n", "data")
            
            for orig, new in sorted(vlan_mappings.items()):
                self.results_text.insert(tk.END, f"{orig:<15} | {new:<15}\n", "data")
            self.results_text.insert(tk.END, f"\nTotal unique VLANs: {len(vlan_mappings)}\n\n", "data")
        
        # Summary
        self.results_text.insert(tk.END, "=" * 80 + "\n", "header")
        self.results_text.insert(tk.END, "SUMMARY:\n", "section")
        self.results_text.insert(tk.END, "-" * 40 + "\n", "data")
        summary_text = f"""Total MAC addresses sanitized: {len(mac_mappings)}
Total IPv4 addresses sanitized: {len(ipv4_mappings)}
Total IPv6 addresses sanitized: {len(ipv6_mappings)}
Total VLAN IDs changed: {len(vlan_mappings)}
"""
        self.results_text.insert(tk.END, summary_text, "data")
        self.results_text.insert(tk.END, "=" * 80 + "\n", "header")
        
        # Scroll to top
        self.results_text.see("1.0")
        
        # Force update of the GUI
        self.results_text.update_idletasks()
                                      
    def save_log_file(self):
        if not self.conversion_log:
            messagebox.showwarning("Warning", "No conversion log available. Process a file first.")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save log file",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("HTML files", "*.html"),
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    # Save as JSON for machine-readable format
                    with open(filename, 'w') as f:
                        json.dump(self.conversion_log, f, indent=2)
                elif filename.endswith('.csv'):
                    # Save as CSV for spreadsheet import
                    self.save_log_as_csv(filename)
                elif filename.endswith('.html'):
                    # Save as HTML with nice formatting
                    self.save_log_as_html(filename)
                else:
                    # Save as formatted text with tables
                    self.save_log_as_text(filename)
                        
                messagebox.showinfo("Success", f"Log file saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save log file: {str(e)}")
                
    def save_log_as_text(self, filename):
        """Save log as formatted text file with tables"""
        with open(filename, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("PCAP/PCAPNG SANITIZATION LOG\n")
            f.write("=" * 80 + "\n\n")
            
            # Metadata
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Input file: {self.input_file.get()}\n")
            f.write(f"Output file: {self.output_file.get()}\n")
            f.write(f"Input format: {self.conversion_log['settings']['input_format'].upper()}\n")
            f.write(f"Output format: {self.conversion_log['settings']['output_format'].upper()}\n\n")
            
            # Settings
            f.write("SANITIZATION SETTINGS:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Sequential mode: {'Yes' if self.conversion_log['settings']['sequential'] else 'No (Random)'}\n")
            f.write(f"IPv4 mask: {self.conversion_log['settings']['ipv4_mask']} bits\n")
            f.write(f"IPv6 mask: {self.conversion_log['settings']['ipv6_mask']} bits\n")
            f.write(f"MAC mask: {self.conversion_log['settings']['mac_mask']} bits\n")
            f.write(f"Starting IPv4: {self.conversion_log['settings']['start_ipv4']}\n")
            f.write(f"Starting IPv6: {self.conversion_log['settings']['start_ipv6']}\n")
            f.write(f"Starting MAC: {self.conversion_log['settings']['start_mac']}\n")
            if self.conversion_log['settings']['fixed_vlan']:
                f.write(f"Fixed VLAN: {self.conversion_log['settings']['fixed_vlan']}\n")
            f.write("\n")
            
            # MAC Address Mappings
            if self.conversion_log.get('MAC_mappings'):
                f.write("MAC ADDRESS MAPPINGS:\n")
                f.write("-" * 60 + "\n")
                f.write(f"{'Original MAC':<20} | {'Sanitized MAC':<20} | {'Count':<10}\n")
                f.write("-" * 60 + "\n")
                
                # Count occurrences (in real scenario, you might track this during processing)
                for orig, new in sorted(self.conversion_log['MAC_mappings'].items()):
                    f.write(f"{orig:<20} | {new:<20} | {'N/A':<10}\n")
                f.write(f"\nTotal unique MAC addresses: {len(self.conversion_log['MAC_mappings'])}\n\n")
            
            # IPv4 Address Mappings
            if self.conversion_log.get('IPv4_mappings'):
                f.write("IPv4 ADDRESS MAPPINGS:\n")
                f.write("-" * 60 + "\n")
                f.write(f"{'Original IPv4':<20} | {'Sanitized IPv4':<20} | {'Count':<10}\n")
                f.write("-" * 60 + "\n")
                
                for orig, new in sorted(self.conversion_log['IPv4_mappings'].items()):
                    f.write(f"{orig:<20} | {new:<20} | {'N/A':<10}\n")
                f.write(f"\nTotal unique IPv4 addresses: {len(self.conversion_log['IPv4_mappings'])}\n\n")
            
            # IPv6 Address Mappings
            if self.conversion_log.get('IPv6_mappings'):
                f.write("IPv6 ADDRESS MAPPINGS:\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'Original IPv6':<40} | {'Sanitized IPv6':<40}\n")
                f.write("-" * 80 + "\n")
                
                for orig, new in sorted(self.conversion_log['IPv6_mappings'].items()):
                    f.write(f"{orig:<40} | {new:<40}\n")
                f.write(f"\nTotal unique IPv6 addresses: {len(self.conversion_log['IPv6_mappings'])}\n\n")
            
            # VLAN Mappings
            if self.conversion_log.get('VLAN_mappings'):
                f.write("VLAN ID MAPPINGS:\n")
                f.write("-" * 40 + "\n")
                f.write(f"{'Original VLAN':<15} | {'Sanitized VLAN':<15}\n")
                f.write("-" * 40 + "\n")
                
                for orig, new in sorted(self.conversion_log['VLAN_mappings'].items()):
                    f.write(f"{orig:<15} | {new:<15}\n")
                f.write(f"\nTotal unique VLANs: {len(self.conversion_log['VLAN_mappings'])}\n\n")
            
            # Summary
            f.write("=" * 80 + "\n")
            f.write("SUMMARY:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total MAC addresses sanitized: {len(self.conversion_log.get('MAC_mappings', {}))}\n")
            f.write(f"Total IPv4 addresses sanitized: {len(self.conversion_log.get('IPv4_mappings', {}))}\n")
            f.write(f"Total IPv6 addresses sanitized: {len(self.conversion_log.get('IPv6_mappings', {}))}\n")
            f.write(f"Total VLAN IDs changed: {len(self.conversion_log.get('VLAN_mappings', {}))}\n")
            f.write("=" * 80 + "\n")
    
    def save_log_as_csv(self, filename):
        """Save log as CSV file"""
        import csv
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write metadata
            writer.writerow(['PCAP/PCAPNG Sanitization Log'])
            writer.writerow(['Generated on', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['Input file', self.input_file.get()])
            writer.writerow(['Output file', self.output_file.get()])
            writer.writerow([])
            
            # MAC mappings
            if self.conversion_log.get('MAC_mappings'):
                writer.writerow(['MAC Address Mappings'])
                writer.writerow(['Original MAC', 'Sanitized MAC'])
                for orig, new in sorted(self.conversion_log['MAC_mappings'].items()):
                    writer.writerow([orig, new])
                writer.writerow([])
            
            # IPv4 mappings
            if self.conversion_log.get('IPv4_mappings'):
                writer.writerow(['IPv4 Address Mappings'])
                writer.writerow(['Original IPv4', 'Sanitized IPv4'])
                for orig, new in sorted(self.conversion_log['IPv4_mappings'].items()):
                    writer.writerow([orig, new])
                writer.writerow([])
            
            # IPv6 mappings
            if self.conversion_log.get('IPv6_mappings'):
                writer.writerow(['IPv6 Address Mappings'])
                writer.writerow(['Original IPv6', 'Sanitized IPv6'])
                for orig, new in sorted(self.conversion_log['IPv6_mappings'].items()):
                    writer.writerow([orig, new])
                writer.writerow([])
            
            # VLAN mappings
            if self.conversion_log.get('VLAN_mappings'):
                writer.writerow(['VLAN ID Mappings'])
                writer.writerow(['Original VLAN', 'Sanitized VLAN'])
                for orig, new in sorted(self.conversion_log['VLAN_mappings'].items()):
                    writer.writerow([orig, new])
    
    def save_log_as_html(self, filename):
        """Save log as HTML file with nice formatting"""
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>PCAP Sanitization Log</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        h1, h2 {
            color: #333;
        }
        .metadata {
            background-color: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 30px;
            background-color: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.2);
        }
        th {
            background-color: #007bff;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            border: 1px solid #ddd;
            padding: 8px;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .summary {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .settings {
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <h1>PCAP/PCAPNG Sanitization Log</h1>
    
    <div class="metadata">
        <strong>Generated on:</strong> {timestamp}<br>
        <strong>Input file:</strong> {input_file}<br>
        <strong>Output file:</strong> {output_file}<br>
        <strong>Input format:</strong> {input_format}<br>
        <strong>Output format:</strong> {output_format}
    </div>
    
    <div class="settings">
        <h2>Sanitization Settings</h2>
        <strong>Sequential mode:</strong> {sequential}<br>
        <strong>IPv4 mask:</strong> {ipv4_mask} bits<br>
        <strong>IPv6 mask:</strong> {ipv6_mask} bits<br>
        <strong>MAC mask:</strong> {mac_mask} bits<br>
        <strong>Starting IPv4:</strong> {start_ipv4}<br>
        <strong>Starting IPv6:</strong> {start_ipv6}<br>
        <strong>Starting MAC:</strong> {start_mac}<br>
        {fixed_vlan_line}
    </div>
"""
        
        # Fill in metadata
        settings = self.conversion_log['settings']
        fixed_vlan_line = f"<strong>Fixed VLAN:</strong> {settings['fixed_vlan']}<br>" if settings.get('fixed_vlan') else ""
        
        html_content = html_content.format(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            input_file=self.input_file.get(),
            output_file=self.output_file.get(),
            input_format=settings['input_format'].upper(),
            output_format=settings['output_format'].upper(),
            sequential='Yes' if settings['sequential'] else 'No (Random)',
            ipv4_mask=settings['ipv4_mask'],
            ipv6_mask=settings['ipv6_mask'],
            mac_mask=settings['mac_mask'],
            start_ipv4=settings['start_ipv4'],
            start_ipv6=settings['start_ipv6'],
            start_mac=settings['start_mac'],
            fixed_vlan_line=fixed_vlan_line
        )
        
        # MAC mappings table
        if self.conversion_log.get('MAC_mappings'):
            html_content += """
    <h2>MAC Address Mappings</h2>
    <table>
        <tr>
            <th>Original MAC</th>
            <th>Sanitized MAC</th>
        </tr>
"""
            for orig, new in sorted(self.conversion_log['MAC_mappings'].items()):
                html_content += f"        <tr><td>{orig}</td><td>{new}</td></tr>\n"
            html_content += "    </table>\n"
        
        # IPv4 mappings table
        if self.conversion_log.get('IPv4_mappings'):
            html_content += """
    <h2>IPv4 Address Mappings</h2>
    <table>
        <tr>
            <th>Original IPv4</th>
            <th>Sanitized IPv4</th>
        </tr>
"""
            for orig, new in sorted(self.conversion_log['IPv4_mappings'].items()):
                html_content += f"        <tr><td>{orig}</td><td>{new}</td></tr>\n"
            html_content += "    </table>\n"
        
        # IPv6 mappings table
        if self.conversion_log.get('IPv6_mappings'):
            html_content += """
    <h2>IPv6 Address Mappings</h2>
    <table>
        <tr>
            <th>Original IPv6</th>
            <th>Sanitized IPv6</th>
        </tr>
"""
            for orig, new in sorted(self.conversion_log['IPv6_mappings'].items()):
                html_content += f"        <tr><td>{orig}</td><td>{new}</td></tr>\n"
            html_content += "    </table>\n"
        
        # VLAN mappings table
        if self.conversion_log.get('VLAN_mappings'):
            html_content += """
    <h2>VLAN ID Mappings</h2>
    <table>
        <tr>
            <th>Original VLAN</th>
            <th>Sanitized VLAN</th>
        </tr>
"""
            for orig, new in sorted(self.conversion_log['VLAN_mappings'].items()):
                html_content += f"        <tr><td>{orig}</td><td>{new}</td></tr>\n"
            html_content += "    </table>\n"
        
        # Summary
        html_content += f"""
    <div class="summary">
        <h2>Summary</h2>
        <strong>Total MAC addresses sanitized:</strong> {len(self.conversion_log.get('MAC_mappings', {}))}<br>
        <strong>Total IPv4 addresses sanitized:</strong> {len(self.conversion_log.get('IPv4_mappings', {}))}<br>
        <strong>Total IPv6 addresses sanitized:</strong> {len(self.conversion_log.get('IPv6_mappings', {}))}<br>
        <strong>Total VLAN IDs changed:</strong> {len(self.conversion_log.get('VLAN_mappings', {}))}<br>
    </div>
</body>
</html>
"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
                
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.conversion_log.clear()
        

def main():
    root = tk.Tk()
    app = PCAPSanitizerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()