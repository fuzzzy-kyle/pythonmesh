"""Meshtastic GUI Application

A tkinter-based GUI for the Meshtastic Python library that provides
a user-friendly interface for connecting to devices, viewing mesh nodes,
sending messages, and managing device configuration.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import logging
from typing import Optional, Dict, Any, List
import json

from pubsub import pub

from . import BROADCAST_ADDR
from .ble_interface import BLEInterface
from .serial_interface import SerialInterface
from .tcp_interface import TCPInterface
from .mesh_interface import MeshInterface
from .protobuf import portnums_pb2


class MeshtasticGUI:
    """Main GUI application for Meshtastic"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Meshtastic Dashboard")
        self.root.geometry("1200x800")
        
        self.interface: Optional[MeshInterface] = None
        self.nodes: Dict[str, Any] = {}
        self.connection_thread: Optional[threading.Thread] = None
        self.active_chats_data: Dict[str, List[str]] = {}  # node_id -> list of messages
        
        # GUI state
        self.is_connected = False
        self.selected_node = None
        self.sort_column = None
        self.sort_reverse = False
        self.favorite_nodes = set()  # Store favorite node IDs
        
        # Create main layout
        self.create_widgets()
        self.setup_pubsub()
        self.setup_styles()
        
        # Configure logging
        logging.basicConfig(level=logging.INFO)
        
    def create_widgets(self):
        """Create the main GUI layout"""
        
        # Create main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connection tab
        self.create_connection_tab()
        
        # Nodes tab
        self.create_nodes_tab()
        
        # Messages tab
        self.create_messages_tab()
        
        # Configuration tab
        self.create_config_tab()
        
        # Monitor tab
        self.create_monitor_tab()
        
        # Status bar
        self.create_status_bar()
        
    def create_connection_tab(self):
        """Create the device connection tab"""
        conn_frame = ttk.Frame(self.notebook)
        self.notebook.add(conn_frame, text="Connection")
        
        # Connection method selection
        method_frame = ttk.LabelFrame(conn_frame, text="Connection Method")
        method_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Connection method selection (only one at a time)
        self.conn_method = tk.StringVar(value="serial")
        
        tk.Radiobutton(method_frame, text="Serial/USB", variable=self.conn_method, 
                      value="serial", command=self.on_connection_method_changed, indicatoron=True).grid(row=0, column=0, sticky=tk.W, padx=5)
        tk.Radiobutton(method_frame, text="Bluetooth LE", variable=self.conn_method, 
                      value="ble", command=self.on_connection_method_changed, indicatoron=True).grid(row=0, column=1, sticky=tk.W, padx=5)
        tk.Radiobutton(method_frame, text="TCP/IP", variable=self.conn_method, 
                      value="tcp", command=self.on_connection_method_changed, indicatoron=True).grid(row=0, column=2, sticky=tk.W, padx=5)
        
        # Connection parameters
        self.params_frame = ttk.LabelFrame(conn_frame, text="Connection Parameters")
        self.params_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Serial parameters
        self.serial_label = ttk.Label(self.params_frame, text="Serial Port:")
        self.serial_label.grid(row=0, column=0, sticky=tk.W, padx=5)
        self.serial_port = ttk.Combobox(self.params_frame, width=20)
        self.serial_port.grid(row=0, column=1, padx=5, pady=2)
        self.serial_port.set("/dev/ttyACM0")
        
        # BLE parameters
        self.ble_label = ttk.Label(self.params_frame, text="BLE Device:")
        self.ble_label.grid(row=1, column=0, sticky=tk.W, padx=5)
        self.ble_device = ttk.Combobox(self.params_frame, width=20)
        self.ble_device.grid(row=1, column=1, padx=5, pady=2)
        
        # TCP parameters
        self.tcp_label = ttk.Label(self.params_frame, text="TCP Host:")
        self.tcp_label.grid(row=2, column=0, sticky=tk.W, padx=5)
        self.tcp_host = ttk.Combobox(self.params_frame, width=20)
        self.tcp_host.grid(row=2, column=1, padx=5, pady=2)
        self.tcp_host.set("localhost")
        
        # Initialize available connections
        self.refresh_connection_options()
        
        # Initialize visibility
        self.on_connection_method_changed()
        
        # Scan/Connect buttons
        button_frame = ttk.Frame(conn_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.scan_btn = ttk.Button(button_frame, text="Scan BLE Devices", 
                                  command=self.scan_ble_devices)
        # Don't pack initially - will be shown/hidden by on_connection_method_changed()
        
        self.connect_btn = ttk.Button(button_frame, text="Connect", 
                                     command=self.connect_device)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = ttk.Button(button_frame, text="Disconnect", 
                                        command=self.disconnect_device, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        # Connection status and info
        info_frame = ttk.LabelFrame(conn_frame, text="Connected Device Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.device_info = scrolledtext.ScrolledText(info_frame, height=10, bg='black', fg='green', insertbackground='green')
        self.device_info.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def create_nodes_tab(self):
        """Create the mesh nodes tab"""
        nodes_frame = ttk.Frame(self.notebook)
        self.notebook.add(nodes_frame, text="Mesh Nodes")
        
        # Search bar
        search_frame = ttk.Frame(nodes_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame, width=20)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind('<KeyRelease>', self.on_search_changed)
        
        ttk.Label(search_frame, text="in:").pack(side=tk.LEFT, padx=5)
        self.search_category = ttk.Combobox(search_frame, values=["All", "Node", "ID", "Name"], 
                                           state="readonly", width=10)
        self.search_category.set("All")
        self.search_category.pack(side=tk.LEFT, padx=5)
        self.search_category.bind('<<ComboboxSelected>>', self.on_search_changed)
        
        # Clear search button
        ttk.Button(search_frame, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=5)
        
        # Nodes list
        self.list_frame = ttk.LabelFrame(nodes_frame, text="Network Nodes")
        self.list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview for nodes
        self.nodes_tree = ttk.Treeview(self.list_frame, columns=("node", "id", "name", "distance", "snr", "battery"), 
                                      show="tree headings")
        
        self.nodes_tree.heading("#0", text="⭐")
        self.nodes_tree.heading("node", text="Short Name")
        self.nodes_tree.heading("id", text="Node ID")
        self.nodes_tree.heading("name", text="Long Name")
        self.nodes_tree.heading("distance", text="Distance")
        self.nodes_tree.heading("snr", text="SNR")
        self.nodes_tree.heading("battery", text="Battery")
        
        # Configure column widths
        self.nodes_tree.column("#0", width=20)
        self.nodes_tree.column("node", width=37, anchor="center")
        self.nodes_tree.column("id", width=75, anchor="center")
        self.nodes_tree.column("name", width=238)
        self.nodes_tree.column("distance", width=80)
        self.nodes_tree.column("snr", width=60)
        self.nodes_tree.column("battery", width=80)
        
        # Scrollbar for treeview (pack first to appear on the right)
        scrollbar = ttk.Scrollbar(self.list_frame, orient=tk.VERTICAL, command=self.nodes_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Pack treeview after scrollbar
        self.nodes_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.nodes_tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind column header clicks for sorting
        for col in ("#0", "node", "id", "name", "distance", "snr", "battery"):
            self.nodes_tree.heading(col, command=lambda c=col: self.sort_nodes_by_column(c))
        
        # Node actions
        actions_frame = ttk.Frame(nodes_frame)
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(actions_frame, text="Refresh Nodes", 
                  command=self.refresh_nodes).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Ping Node", 
                  command=self.ping_node).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Favorite Node", 
                  command=self.favorite_node_node).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Traceroute", 
                  command=self.traceroute_node).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Message", 
                  command=self.message_node).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Request Position", 
                  command=self.request_position).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Request Telemetry", 
                  command=self.request_telemetry).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Remove Node", 
                  command=self.remove_node).pack(side=tk.LEFT, padx=5)
        
    def create_messages_tab(self):
        """Create the messaging tab"""
        msg_frame = ttk.Frame(self.notebook)
        self.notebook.add(msg_frame, text="Messages")
        
        # Create main paned window for messages
        paned_window = ttk.PanedWindow(msg_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Active chats panel
        chats_frame = ttk.LabelFrame(paned_window, text="Active Chats")
        paned_window.add(chats_frame, weight=1)
        
        # Active chats list
        self.active_chats = tk.Listbox(chats_frame, width=25)
        self.active_chats.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.active_chats.bind('<<ListboxSelect>>', self.on_chat_selected)
        
        # Message area frame
        message_area_frame = ttk.Frame(paned_window)
        paned_window.add(message_area_frame, weight=3)
        
        # Message history
        history_frame = ttk.LabelFrame(message_area_frame, text="Message History")
        history_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.message_history = scrolledtext.ScrolledText(history_frame, state=tk.DISABLED, bg='black', fg='green', insertbackground='green')
        self.message_history.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message composition
        compose_frame = ttk.LabelFrame(message_area_frame, text="Send Message")
        compose_frame.pack(fill=tk.X, pady=5)
        
        # Destination selection
        dest_frame = ttk.Frame(compose_frame)
        dest_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(dest_frame, text="To:").pack(side=tk.LEFT)
        self.dest_var = tk.StringVar()
        self.dest_combo = ttk.Combobox(dest_frame, textvariable=self.dest_var, width=20)
        self.dest_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(dest_frame, text="Channel:").pack(side=tk.LEFT, padx=(20, 0))
        self.channel_var = tk.StringVar(value="0")
        self.channel_combo = ttk.Combobox(dest_frame, textvariable=self.channel_var, 
                                         values=["0", "1", "2", "3", "4", "5", "6", "7"], width=5)
        self.channel_combo.pack(side=tk.LEFT, padx=5)
        
        # Message text
        text_frame = ttk.Frame(compose_frame)
        text_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Label(text_frame, text="Message:").pack(side=tk.LEFT)
        self.message_entry = ttk.Entry(text_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_entry.bind("<Return>", self.send_message)
        
        # Send button
        self.send_btn = ttk.Button(compose_frame, text="Send", command=self.send_message)
        self.send_btn.pack(side=tk.RIGHT, padx=5, pady=2)
        
    def create_config_tab(self):
        """Create the device configuration tab"""
        config_frame = ttk.Frame(self.notebook)
        self.notebook.add(config_frame, text="Configuration")
        
        # Configuration buttons at the bottom of the entire config tab
        config_btn_frame = ttk.Frame(config_frame)
        config_btn_frame.pack(fill=tk.X, padx=10, pady=5, side=tk.BOTTOM)
        
        ttk.Button(config_btn_frame, text="Refresh Config", 
                  command=self.refresh_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(config_btn_frame, text="Save to Device", 
                  command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(config_btn_frame, text="Reset to Default", 
                  command=self.reset_config_section).pack(side=tk.LEFT, padx=5)
        ttk.Button(config_btn_frame, text="Export YAML", 
                  command=self.export_config).pack(side=tk.LEFT, padx=5)
        
        # Main content frame to hold sections and details side by side
        main_content_frame = ttk.Frame(config_frame)
        main_content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Configuration sections
        sections_frame = ttk.Frame(main_content_frame)
        sections_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10), pady=5)
        
        
        self.config_sections = tk.Listbox(sections_frame, width=20)
        self.config_sections.pack(fill=tk.Y, expand=True)
        self.config_sections.bind('<<ListboxSelect>>', self.on_config_section_select)
        
        # Add configuration sections mapped to actual config types
        self.config_section_map = {
            "Device": "device",
            "LoRa": "lora", 
            "Position": "position",
            "Power": "power",
            "Network": "network",
            "Bluetooth": "bluetooth",
            "Display": "display",
            "MQTT": "mqtt",
            "Serial": "serial",
            "External Notification": "external_notification",
            "Store & Forward": "store_forward",
            "Range Test": "range_test",
            "Telemetry": "telemetry",
            "Canned Message": "canned_message",
            "Audio": "audio",
            "Remote Hardware": "remote_hardware"
        }
        
        for section_name in self.config_section_map.keys():
            self.config_sections.insert(tk.END, section_name)
        
        # Configuration details
        details_frame = ttk.LabelFrame(main_content_frame, text="Configuration Settings")
        details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, pady=5)
        
        # Create scrollable frame for config fields
        canvas = tk.Canvas(details_frame)
        scrollbar = ttk.Scrollbar(details_frame, orient="vertical", command=canvas.yview)
        self.config_fields_frame = ttk.Frame(canvas)
        
        self.config_fields_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.config_fields_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Store reference for cleanup
        self.config_canvas = canvas
        self.config_widgets = {}  # Store config field widgets
        self.current_config_section = None
        ttk.Button(config_btn_frame, text="Import YAML", 
                  command=self.import_config).pack(side=tk.LEFT, padx=5)
    
    def create_monitor_tab(self):
        """Create the Monitor tab for tx/rx activity and CLI commands"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Console")
        
        # Activity console
        console_frame = ttk.LabelFrame(monitor_frame, text="Console Output")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.monitor_console = scrolledtext.ScrolledText(
            console_frame, 
            state=tk.DISABLED, 
            wrap=tk.WORD,
            bg='black',
            fg='green',
            font=('Courier', 14)
        )
        self.monitor_console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # CLI command input
        cli_frame = ttk.LabelFrame(monitor_frame, text="Meshtastic CLI Commands")
        cli_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Command input
        input_frame = ttk.Frame(cli_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Command:").pack(side=tk.LEFT)
        self.cli_entry = ttk.Entry(input_frame)
        self.cli_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cli_entry.bind('<Return>', self.execute_cli_command)
        
        ttk.Button(input_frame, text="Send", 
                  command=self.execute_cli_command).pack(side=tk.LEFT, padx=5)
        
        # Export button
        export_frame = ttk.Frame(cli_frame)
        export_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(export_frame, text="Export Console History", 
                  command=self.export_console_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Export Raw Packets", 
                  command=self.export_raw_packets).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Clear Console", 
                  command=self.clear_console).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Help", 
                  command=self.show_help).pack(side=tk.LEFT, padx=5)
        
        # Initialize monitor data
        self.monitor_data = []
        self.raw_packet_data = []  # Store raw packet data for export
        
        # Log initial message
        self.add_monitor_message("Monitor console initialized", "SYSTEM")
        
        # Redirect stdout/stderr to capture all prints
        import sys
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
    
    def create_status_bar(self):
        """Create the status bar"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(self.status_bar, text="Not connected")
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Device statistics
        self.stats_label = ttk.Label(self.status_bar, text="")
        self.stats_label.pack(side=tk.LEFT, padx=20, pady=5)
        
        # Connection indicator
        self.conn_indicator = tk.Canvas(self.status_bar, width=20, height=20)
        self.conn_indicator.pack(side=tk.RIGHT, padx=10, pady=5)
        self.conn_indicator.create_oval(5, 5, 15, 15, fill="red", tags="indicator")
        
    def setup_pubsub(self):
        """Setup PubSub event handlers"""
        # Primary subscription to all received packets
        pub.subscribe(self.on_receive, "meshtastic.receive")
        pub.subscribe(self.on_connection, "meshtastic.connection")
        pub.subscribe(self.on_connection, "meshtastic.connection.established") 
        pub.subscribe(self.on_node_updated, "meshtastic.node.updated")
        
        # Subscribe to all packet types for monitor console (remove duplicate receive subscription)
        pub.subscribe(self.on_packet_monitor, "meshtastic.send")
        
        # Subscribe to text message specific events
        pub.subscribe(self.on_text_message, "meshtastic.receive.text")
        pub.subscribe(self.on_text_message, "meshtastic.receive.data.TEXT_MESSAGE_APP")
        
        # Subscribe to Store & Forward messages for message history
        try:
            pub.subscribe(self.on_store_forward_message, "meshtastic.receive.data.STORE_FORWARD_APP")
        except:
            pass
        
        # Note: RX packets are handled in on_receive method to avoid duplicates
        
        print("PubSub subscriptions set up")  # Debug
        self.add_monitor_message("PubSub subscriptions initialized", "SYSTEM")
    
    def on_text_message(self, packet, interface):
        """Handle specific text message events"""
        try:
            print(f"Text message event received: {packet}")
            
            # Extract text from the packet
            text = ""
            if isinstance(packet, dict):
                text = packet.get('text', '')
                from_id = packet.get('from', packet.get('fromId', 'Unknown'))
                to_id = packet.get('to', packet.get('toId', 'Unknown'))
            else:
                # Handle if packet is a text string directly
                text = str(packet) if packet else ""
                from_id = "Unknown"
                to_id = "Unknown"
            
            if text:
                sender_name = self.get_node_display_name(from_id)
                timestamp = time.strftime('%H:%M:%S')
                msg_text = f"[{timestamp}] Text from {sender_name} ({from_id}): {text}\n"
                
                self.root.after(0, lambda t=msg_text, f=from_id: self.add_message_to_history(t, f))
                self.root.after(0, lambda: self.add_monitor_message(f"TEXT: {text} from {sender_name}", "RX"))
                
        except Exception as e:
            print(f"Error in on_text_message: {e}")
            import traceback
            traceback.print_exc()
    
    def setup_styles(self):
        """Setup consistent UI styles"""
        self.style = ttk.Style()
        
        # Configure checkbox style for better visibility
        self.style.configure('Custom.TCheckbutton', 
                           focuscolor='lightblue',
                           borderwidth=2,
                           relief='solid')
        
    def on_receive(self, packet, interface):
        """Handle incoming packets"""
        try:
            print(f"Received packet: {packet}")  # Debug print
            
            # Handle different packet formats
            decoded = packet.get('decoded', {})
            
            # Also check if this is an encrypted message that needs special handling
            is_pki_encrypted = packet.get('pki_encrypted', False)
            if is_pki_encrypted:
                print(f"PKI encrypted message detected - checking for decrypted text")  # Debug print
            
            if decoded:
                portnum = decoded.get('portnum')
                print(f"Portnum: {portnum}")  # Debug print
                
                # Check for text messages - handle both string and numeric portnums
                is_text_message = False
                if portnum == 'TEXT_MESSAGE_APP':
                    is_text_message = True
                elif hasattr(portnums_pb2.PortNum, 'TEXT_MESSAGE_APP'):
                    if portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
                        is_text_message = True
                elif isinstance(portnum, int) and portnum == 1:  # TEXT_MESSAGE_APP is typically port 1
                    is_text_message = True
                
                if is_text_message:
                    # Try different methods to get the text
                    text = None
                    if 'text' in decoded:
                        text = decoded['text']
                    elif 'payload' in decoded:
                        # Try to decode payload as text
                        try:
                            payload = decoded['payload']
                            if isinstance(payload, bytes):
                                text = payload.decode('utf-8')
                            elif isinstance(payload, str):
                                text = payload
                        except:
                            pass
                    
                    # Use the correct ID fields
                    from_id = packet.get('fromId') or packet.get('from')
                    to_id = packet.get('toId') or packet.get('to')
                    my_node_id = None
                    
                    # Get our node ID to check if message is directed to us
                    try:
                        if self.interface:
                            my_info = self.interface.getMyNodeInfo()
                            if my_info:
                                my_node_id = my_info.get('num')
                    except:
                        pass
                    
                    if text:
                        print(f"Received text message from {from_id} to {to_id}: {text}")  # Debug print
                        
                        # Check if this message is for us or broadcast
                        # Get our device's node ID in both formats
                        my_node_id = self.interface.myInfo.my_node_num if self.interface and self.interface.myInfo else None
                        my_node_hex = f"!{my_node_id:08x}" if my_node_id else None
                        
                        is_for_us = (to_id == my_node_id or to_id == my_node_hex or 
                                   to_id == BROADCAST_ADDR or
                                   str(to_id) == str(BROADCAST_ADDR) or
                                   str(to_id) == "4294967295")  # Broadcast as decimal
                        
                        if is_for_us:
                            # Get sender name if available
                            sender_name = self.get_node_display_name(from_id)
                            
                            # Add to message history
                            timestamp = time.strftime('%H:%M:%S')
                            is_broadcast = (to_id == BROADCAST_ADDR or 
                                          str(to_id) == str(BROADCAST_ADDR) or
                                          str(to_id) == "4294967295")
                            dest_text = "Broadcast" if is_broadcast else "You"
                            
                            # Add PKI encryption indicator if applicable
                            encryption_indicator = " [PKI]" if is_pki_encrypted else ""
                            msg_text = f"[{timestamp}] From {sender_name} ({from_id}) to {dest_text}: {text}{encryption_indicator}\n"
                            
                            self.root.after(0, lambda t=msg_text, f=from_id, b=is_broadcast: self.add_message_to_history(t, f, b))
                            
                            # Add to monitor console
                            self.root.after(0, lambda: self.add_monitor_message(f"{text} from {sender_name} ({from_id})", "RX"))
                            
                            # Also show a notification in status bar
                            self.root.after(0, lambda s=sender_name: self.update_status(f"Message received from {s}"))
                        else:
                            print(f"Message not for us (from {from_id} to {to_id})")
                    else:
                        print(f"Text message packet but no text found: {decoded}")
                else:
                    print(f"Non-text message received, portnum: {portnum}")  # Debug print
            # Handle PKI encrypted messages without decoded text
            elif is_pki_encrypted:
                # This is an encrypted message - try to handle it even without decrypted content
                from_id = packet.get('fromId') or packet.get('from')
                to_id = packet.get('toId') or packet.get('to')
                my_node_id = None
                
                # Get our node ID to check if message is directed to us
                try:
                    if self.interface:
                        my_info = self.interface.getMyNodeInfo()
                        if my_info:
                            my_node_id = my_info.get('num')
                except:
                    pass
                
                # Check if this encrypted message is for us
                is_for_us = (to_id == my_node_id or 
                           to_id == BROADCAST_ADDR or
                           str(to_id) == str(BROADCAST_ADDR) or
                                                      str(to_id) == "4294967295")
                
                if is_for_us:
                    sender_name = self.get_node_display_name(from_id)
                    timestamp = time.strftime('%H:%M:%S')
                    
                    # Check for any decrypted payload that might be available
                    text_content = "Encrypted message (could not decrypt)"
                    
                    # Try to get text from alternate sources in the packet
                    if 'text' in packet:
                        text_content = packet['text']
                    elif 'decoded' in packet and 'text' in packet['decoded']:
                        text_content = packet['decoded']['text']
                    
                    is_broadcast = (to_id == BROADCAST_ADDR or 
                                  str(to_id) == str(BROADCAST_ADDR) or
                                                                    str(to_id) == "4294967295")
                    dest_text = "Broadcast" if is_broadcast else "You"
                    
                    msg_text = f"[{timestamp}] From {sender_name} ({from_id}) to {dest_text}: {text_content} [PKI]\n"
                    
                    self.root.after(0, lambda t=msg_text, f=from_id, b=is_broadcast: self.add_message_to_history(t, f, b))
                    print(f"Processed PKI encrypted message from {from_id} to {to_id}")  # Debug print
            else:
                print("Packet has no decoded data")  # Debug print
            
            # Add to console monitor (moved from on_packet_monitor to avoid duplicates)
            self.add_packet_to_console_monitor(packet, interface, "RX")
                
        except Exception as e:
            logging.error(f"Error processing received packet: {e}")
            print(f"Exception in on_receive: {e}")  # Debug print
            import traceback
            traceback.print_exc()
    
    def on_packet_monitor(self, packet, interface):
        """Handle TX packets for monitor console"""
        try:
            # This only handles TX (send) packets now
            self.add_packet_to_console_monitor(packet, interface, "TX")
            
            # Extract basic packet info - packet is a dictionary
            from_id = packet.get('fromId', packet.get('from', 'Unknown'))
            to_id = packet.get('toId', packet.get('to', 'Unknown'))
            packet_id = packet.get('id', 'N/A')
            
            # Get packet type/portnum from decoded section
            decoded = packet.get('decoded', {})
            if decoded:
                portnum = decoded.get('portnum', 'Unknown')
                payload_info = f"portnum={portnum}"
                
                # Add payload details if available
                payload = decoded.get('payload')
                if payload:
                    payload_size = len(payload) if isinstance(payload, bytes) else len(str(payload))
                    payload_info += f", size={payload_size}B"
                
                # Add specific content info based on portnum
                if portnum == 'POSITION_APP' and 'position' in decoded:
                    pos = decoded['position']
                    if 'latitude' in pos and 'longitude' in pos:
                        payload_info += f", lat={pos['latitude']:.4f}, lon={pos['longitude']:.4f}"
                        if 'altitude' in pos:
                            payload_info += f", alt={pos['altitude']}m"
                elif portnum == 'TELEMETRY_APP' and 'telemetry' in decoded:
                    telem = decoded['telemetry']
                    if 'deviceMetrics' in telem:
                        metrics = telem['deviceMetrics']
                        if 'batteryLevel' in metrics:
                            battery_level = min(100, max(0, round(metrics['batteryLevel'])))
                            payload_info += f", bat={battery_level}%"
                        if 'voltage' in metrics:
                            payload_info += f", v={metrics['voltage']:.2f}V"
                elif portnum == 'TEXT_MESSAGE_APP' and 'text' in decoded:
                    text = decoded['text'][:50] + ("..." if len(decoded['text']) > 50 else "")
                    payload_info += f", text=\"{text}\""
                elif portnum == 'NODEINFO_APP' and 'user' in decoded:
                    user = decoded['user']
                    if 'longName' in user:
                        payload_info += f", user=\"{user['longName']}\""
            else:
                payload_info = "encrypted/unknown"
            
            # Format monitor message with node names when possible
            from_name = self.get_node_display_name(from_id) if from_id != 'Unknown' else from_id
            to_name = self.get_node_display_name(to_id) if to_id != 'Unknown' else to_id
            
            msg = f"Packet ID:{packet_id} {from_name}→{to_name} ({payload_info})"
            self.root.after(0, lambda msg=msg, direction=direction: self.add_monitor_message(msg, direction))
            
        except Exception as e:
            print(f"Error in packet monitor: {e}")
            import traceback
            traceback.print_exc()
    
    def add_packet_to_console_monitor(self, packet, interface, direction):
        """Add packet to console monitor (consolidated from on_packet_monitor)"""
        try:
            # Store raw packet data for export
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            raw_packet_entry = {
                'timestamp': timestamp,
                'packet': packet,
                'interface_type': interface.__class__.__name__ if interface else 'Unknown'
            }
            self.raw_packet_data.append(raw_packet_entry)
            
            # Extract basic packet info - packet is a dictionary
            from_id = packet.get('fromId', packet.get('from', 'Unknown'))
            to_id = packet.get('toId', packet.get('to', 'Unknown'))
            packet_id = packet.get('id', 'N/A')
            
            # Get packet type/portnum from decoded section
            decoded = packet.get('decoded', {})
            if decoded:
                portnum = decoded.get('portnum', 'Unknown')
                payload_info = f"portnum={portnum}"
                
                # Add payload details if available
                payload = decoded.get('payload')
                if payload:
                    payload_size = len(payload) if isinstance(payload, bytes) else len(str(payload))
                    payload_info += f", size={payload_size}B"
                
                # Add specific packet type information
                if 'text' in decoded:
                    payload_info += f", text=\"{decoded['text']}\""
                elif portnum == 'POSITION_APP' or portnum == 3:
                    # Position packet
                    if 'position' in decoded:
                        pos = decoded['position']
                        lat = pos.get('latitude', pos.get('latitudeI', 0))
                        lon = pos.get('longitude', pos.get('longitudeI', 0)) 
                        alt = pos.get('altitude', 0)
                        if lat != 0 or lon != 0:
                            if lat > 1000000:  # Integer format (degrees * 1e7)
                                lat = lat / 1e7
                                lon = lon / 1e7
                            payload_info += f", lat={lat:.4f}, lon={lon:.4f}, alt={alt}m"
                elif portnum == 'TELEMETRY_APP' or portnum == 67:
                    # Telemetry packet
                    if 'telemetry' in decoded:
                        telem = decoded['telemetry']
                        if 'deviceMetrics' in telem:
                            dm = telem['deviceMetrics']
                            if 'batteryLevel' in dm and 'voltage' in dm:
                                battery_level = min(100, max(0, round(dm['batteryLevel'])))
                                payload_info += f", bat={battery_level}%, v={dm['voltage']:.2f}V"
                elif portnum == 'NODEINFO_APP' or portnum == 4:
                    # Node info packet
                    if 'user' in decoded:
                        user = decoded['user']
                        if 'longName' in user:
                            payload_info += f", user=\"{user['longName']}\""
            else:
                payload_info = "encrypted/unknown"
            
            # Format monitor message with node names when possible
            from_name = self.get_node_display_name(from_id) if from_id != 'Unknown' else from_id
            to_name = self.get_node_display_name(to_id) if to_id != 'Unknown' else to_id
            
            msg = f"{direction}: Packet ID:{packet_id} {from_name}→{to_name} ({payload_info})"
            self.root.after(0, lambda: self.add_monitor_message(msg, direction))
            
        except Exception as e:
            print(f"Error in add_packet_to_console_monitor: {e}")
            import traceback
            traceback.print_exc()
    
    def on_connection(self, interface, topic=None):
        """Handle connection events"""
        self.root.after(0, self.update_connection_status)
    
    def on_node_updated(self, node, interface=None):
        """Handle node updates"""
        self.root.after(0, self.refresh_nodes)
    
    def add_message_to_history(self, message, node_id=None, is_broadcast=False):
        """Add message to history display and active chats"""
        # Route broadcast messages to ^all chat
        if is_broadcast:
            self.add_to_active_chats('^all', message)
        elif node_id:
            self.add_to_active_chats(node_id, message)
        
        # Only update main history if no specific chat is selected or if it matches current selection
        current_chat_selection = None
        selection = self.active_chats.curselection()
        if selection:
            chat_display = self.active_chats.get(selection[0])
            if " - " in chat_display:
                current_chat_selection = chat_display.split(" - ")[0]
            else:
                current_chat_selection = chat_display
        
        # Update main history display only if no chat selected or if it's the current chat
        if not current_chat_selection or current_chat_selection == node_id:
            self.message_history.config(state=tk.NORMAL)
            self.message_history.insert(tk.END, message)
            self.message_history.see(tk.END)
            self.message_history.config(state=tk.DISABLED)
    
    def scan_ble_devices(self):
        """Scan for BLE devices"""
        def scan_worker():
            try:
                devices = BLEInterface.scan()
                device_list = [f"{d.name} ({d.address})" for d in devices]
                self.root.after(0, lambda: self.update_ble_devices(device_list))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"BLE scan failed: {e}"))
        
        threading.Thread(target=scan_worker, daemon=True).start()
        self.update_status("Scanning for BLE devices...")
    
    def update_ble_devices(self, devices):
        """Update BLE device list"""
        if devices:
            # Update the BLE dropdown with found devices
            self.ble_device['values'] = devices
            if devices:
                self.ble_device.set(devices[0])  # Select first device
            messagebox.showinfo("BLE Devices", f"Found {len(devices)} devices:\n" + "\n".join(devices))
        else:
            messagebox.showinfo("BLE Devices", "No Meshtastic BLE devices found")
        self.update_status("BLE scan completed")
    
    def connect_device(self):
        """Connect to selected device"""
        def connect_worker():
            interface = None
            error_msg = None
            
            try:
                method = self.conn_method.get()
                interface = None
                
                # Create interface based on selected method
                if method == "serial":
                    port = self.serial_port.get() or None
                    print(f"Connecting to serial port: {port}")
                    interface = SerialInterface(port)
                elif method == "ble":
                    device = self.ble_device.get() or None
                    print(f"Connecting to BLE device: {device}")
                    interface = BLEInterface(device)
                elif method == "tcp":
                    host = self.tcp_host.get() or "localhost"
                    print(f"Connecting to TCP host: {host}")
                    interface = TCPInterface(host)
                else:
                    error_msg = "No connection method selected"
                
                if interface:
                    print("Interface created, waiting for stabilization...")
                    time.sleep(2)
                    print("Connection process completed")
                else:
                    error_msg = "Failed to create interface"
                    
            except FileNotFoundError as e:
                error_msg = f"Device not found: {str(e)}"
            except PermissionError as e:
                error_msg = f"Permission denied: {str(e)}"
            except Exception as e:
                error_msg = str(e)
            
            # Use root.after to update GUI from main thread
            if interface and not error_msg:
                self.interface = interface
                self.root.after(0, self.on_connected)
            else:
                self.root.after(0, lambda msg=error_msg: self.on_connection_error(msg))
        
        # Disable connect button and show connecting status
        self.connect_btn.config(state=tk.DISABLED)
        self.update_status("Connecting...")
        print("Starting connection thread...")
        
        # Start connection in background thread
        self.connection_thread = threading.Thread(target=connect_worker, daemon=True)
        self.connection_thread.start()
    
    def on_connected(self):
        """Handle successful connection"""
        self.is_connected = True
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)
        
        # Update connection indicator
        self.conn_indicator.itemconfig("indicator", fill="green")
        self.update_status("Connected")
        
        # Update device info
        if self.interface:
            info = f"Interface: {self.interface.__class__.__name__}\n"
            if hasattr(self.interface, 'devPath') and self.interface.devPath:
                info += f"Path: {self.interface.devPath}\n"
            
            # Get comprehensive device info
            try:
                my_info = self.interface.getMyNodeInfo()
                if my_info:
                    # Basic node info
                    node_id = my_info.get('num', 'Unknown')
                    user_info = my_info.get('user', {})
                    user_name = user_info.get('longName', 'Unknown')
                    short_name = user_info.get('shortName', 'Unknown')
                    
                    info += f"\n=== Node Information ===\n"
                    info += f"Node ID: {node_id}\n"
                    info += f"Long Name: {user_name}\n"
                    info += f"Short Name: {short_name}\n"
                    
                    # Firmware version from multiple sources
                    firmware_version = None
                    
                    try:
                        # Try firmware_version (underscore format from CLI)
                        if hasattr(self.interface, 'myInfo') and self.interface.myInfo:
                            if hasattr(self.interface.myInfo, 'metadata') and self.interface.myInfo.metadata:
                                firmware_version = getattr(self.interface.myInfo.metadata, 'firmware_version', None)
                        
                        # Try firmwareVersion (camelCase format)  
                        if not firmware_version and hasattr(self.interface, 'myInfo') and self.interface.myInfo:
                            if hasattr(self.interface.myInfo, 'metadata') and self.interface.myInfo.metadata:
                                firmware_version = getattr(self.interface.myInfo.metadata, 'firmwareVersion', None)
                        
                        # Try direct interface metadata
                        if not firmware_version and hasattr(self.interface, 'metadata') and self.interface.metadata:
                            firmware_version = getattr(self.interface.metadata, 'firmware_version', None) or getattr(self.interface.metadata, 'firmwareVersion', None)
                        
                    except Exception as e:
                        print(f"Error getting firmware version: {e}")
                        firmware_version = None
                    
                    # Display firmware version if found
                    if firmware_version:
                        info += f"Firmware Version: {firmware_version}\n"
                    else:
                        info += f"Firmware Version: N/A\n"
                    
                    # Hardware model information
                    if 'hwModel' in user_info:
                        info += f"Hardware Model: {user_info['hwModel']}\n"
                    if 'macaddr' in user_info:
                        mac_bytes = user_info['macaddr']
                        if isinstance(mac_bytes, bytes):
                            mac_str = ':'.join([f'{b:02x}' for b in mac_bytes])
                            info += f"MAC Address: {mac_str}\n"
                    
                    # Device metrics
                    device_metrics = my_info.get('deviceMetrics', {})
                    if device_metrics:
                        info += f"\n=== Device Metrics ===\n"
                        if 'batteryLevel' in device_metrics:
                            battery_level = min(100, max(0, round(device_metrics['batteryLevel'])))
                            info += f"Battery Level: {battery_level}%\n"
                        if 'voltage' in device_metrics:
                            info += f"Voltage: {device_metrics['voltage']:.2f}V\n"
                        if 'channelUtilization' in device_metrics:
                            info += f"Channel Utilization: {device_metrics['channelUtilization']:.1f}%\n"
                        if 'airUtilTx' in device_metrics:
                            info += f"Air Util TX: {device_metrics['airUtilTx']:.1f}%\n"
                        if 'uptimeSeconds' in device_metrics:
                            uptime = device_metrics['uptimeSeconds']
                            hours = uptime // 3600
                            minutes = (uptime % 3600) // 60
                            info += f"Uptime: {hours}h {minutes}m\n"
                    
                    # Position information
                    position = my_info.get('position', {})
                    info += f"\n=== Position ===\n"
                    
                    # Check both current position and fixed position config
                    has_position = False
                    lat_val = None
                    lon_val = None 
                    alt_val = None
                    
                    # First try to get from current position
                    if position and 'latitude' in position:
                        lat_val = position['latitude']
                        has_position = True
                    if position and 'longitude' in position:
                        lon_val = position['longitude'] 
                        has_position = True
                    if position and 'altitude' in position:
                        alt_val = position['altitude']
                    
                    # If no current position, try to get from fixed position in config
                    if not has_position:
                        try:
                            local_node = self.interface.localNode
                            if hasattr(local_node, 'localConfig') and hasattr(local_node.localConfig, 'position'):
                                pos_config = local_node.localConfig.position
                                if hasattr(pos_config, 'fixed_position') and pos_config.fixed_position:
                                    # Device has fixed position enabled, but we need to check if there's stored position data
                                    # The actual fixed position coordinates are stored in the device and should appear in position data
                                    pass
                        except:
                            pass
                    
                    # Display position information
                    if lat_val is not None:
                        info += f"Latitude: {lat_val:.6f}\n"
                    else:
                        info += f"Latitude: N/A\n"
                    
                    if lon_val is not None:
                        info += f"Longitude: {lon_val:.6f}\n"
                    else:
                        info += f"Longitude: N/A\n"
                    
                    if alt_val is not None:
                        info += f"Altitude: {alt_val}m\n"
                    else:
                        info += f"Altitude: N/A\n"
                        
                    if position and 'satsInView' in position:
                        info += f"Satellites in View: {position['satsInView']}\n"
                    else:
                        info += f"Satellites in View: N/A\n"
                    
                    # Local node configuration info
                    try:
                        local_node = self.interface.localNode
                        if hasattr(local_node, 'localConfig'):
                            config = local_node.localConfig
                            info += f"\n=== Configuration ===\n"
                            
                            # Device config
                            if hasattr(config, 'device'):
                                device_config = config.device
                                if hasattr(device_config, 'role'):
                                    info += f"Role: {device_config.role}\n"
                                if hasattr(device_config, 'serialEnabled'):
                                    info += f"Serial Enabled: {device_config.serialEnabled}\n"
                            
                            # LoRa config
                            if hasattr(config, 'lora'):
                                lora_config = config.lora
                                if hasattr(lora_config, 'region'):
                                    info += f"LoRa Region: {lora_config.region}\n"
                                if hasattr(lora_config, 'modemPreset'):
                                    info += f"Modem Preset: {lora_config.modemPreset}\n"
                    except:
                        pass
                    
                    # Update status bar with device stats
                    self.update_device_stats()
                    
            except Exception as e:
                info += f"Error getting device info: {e}\n"
                import traceback
                info += f"Traceback: {traceback.format_exc()}\n"
            
            self.device_info.delete('1.0', tk.END)
            self.device_info.insert('1.0', info)
        
        # Refresh nodes and update destination combo
        self.refresh_nodes()
        
        # Load previous message history
        self.load_message_history_from_device()
        
        # Start message monitoring
        self.start_message_monitoring()
    
    def on_connection_error(self, error):
        """Handle connection error"""
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.update_status("Connection failed")
        
        # Update connection indicator to red
        self.conn_indicator.itemconfig("indicator", fill="red")
        
        messagebox.showerror("Connection Error", f"Failed to connect: {error}")
    
    def disconnect_device(self):
        """Disconnect from device"""
        if self.interface:
            try:
                self.interface.close()
            except:
                pass
            self.interface = None
        
        self.is_connected = False
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        
        # Update connection indicator
        self.conn_indicator.itemconfig("indicator", fill="red")
        self.update_status("Disconnected")
        
        # Clear device info
        self.device_info.delete('1.0', tk.END)
        
        # Clear nodes
        for item in self.nodes_tree.get_children():
            self.nodes_tree.delete(item)
        
        # Stop message monitoring
        if hasattr(self, 'message_monitor_active'):
            self.stop_message_monitoring()
    
    def refresh_nodes(self):
        """Refresh the nodes list"""
        if not self.interface:
            self.list_frame.config(text="Network Nodes (0)")
            return
        
        # Clear existing nodes
        for item in self.nodes_tree.get_children():
            self.nodes_tree.delete(item)
        
        # Update destination combo options
        destinations = [BROADCAST_ADDR]
        
        try:
            nodes = self.interface.nodes
            node_count = len(nodes) if nodes else 0
            
            # Update header with node count
            self.list_frame.config(text=f"Network Nodes ({node_count})")
            
            # Get local node position for distance calculation
            local_position = None
            if self.interface:
                my_info = self.interface.getMyNodeInfo()
                if my_info:
                    local_position = my_info.get('position', {})
            
            for node_id, node in nodes.items():
                user = node.get('user', {})
                name = user.get('longName', 'Unknown')
                short_name = user.get('shortName', '')
                
                # Format battery level
                battery_level = node.get('deviceMetrics', {}).get('batteryLevel', '')
                if battery_level == '' or battery_level is None:
                    battery_display = 'not available'
                else:
                    # Ensure battery level is properly rounded and capped at 100%
                    battery_level = min(100, max(0, round(battery_level)))
                    battery_display = f"{battery_level}%"
                
                # Calculate distance
                distance_display = ''
                node_position = node.get('position', {})
                if (local_position and 'latitude' in local_position and 'longitude' in local_position and
                    node_position and 'latitude' in node_position and 'longitude' in node_position):
                    try:
                        import math
                        # Haversine formula for distance calculation
                        lat1, lon1 = math.radians(local_position['latitude']), math.radians(local_position['longitude'])
                        lat2, lon2 = math.radians(node_position['latitude']), math.radians(node_position['longitude'])
                        
                        dlat = lat2 - lat1
                        dlon = lon2 - lon1
                        a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
                        c = 2 * math.asin(math.sqrt(a))
                        distance_km = 6371 * c  # Earth radius in km
                        
                        if distance_km < 1:
                            distance_display = f"{distance_km*1000:.0f}m"
                        else:
                            distance_display = f"{distance_km:.1f}km"
                    except:
                        distance_display = ''
                
                # Add to tree
                self.nodes_tree.insert('', 'end', 
                    text='⭐' if node_id in self.favorite_nodes else '',
                    values=(
                        short_name or name,
                        node_id.lstrip('!'),
                        name,
                        distance_display,
                        node.get('snr', ''),
                        battery_display
                    ))
                
                # Format destination string with ID, Node, and Name
                node_text = short_name or name
                dest_display = f"{node_id} - {node_text} ({name})"
                destinations.append(dest_display)
            
            # Update destination combo
            self.dest_combo['values'] = destinations
            if not self.dest_var.get():
                self.dest_var.set(BROADCAST_ADDR)
                
        except Exception as e:
            logging.error(f"Error refreshing nodes: {e}")
    
    def sort_nodes_by_column(self, column):
        """Sort nodes by the clicked column"""
        # Toggle sort direction if same column clicked
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        
        # Get all items with their data
        items = []
        for item_id in self.nodes_tree.get_children():
            item = self.nodes_tree.item(item_id)
            text = item['text']
            values = item['values']
            items.append((item_id, text, values))
        
        # Define sorting key function
        def get_sort_key(item):
            _, text, values = item
            
            if column == "#0":  # Node column (text)
                return str(text).lower()
            elif column == "id":  # ID column
                return str(values[0]).lower() if len(values) > 0 else ""
            elif column == "name":  # Name column
                return str(values[1]).lower() if len(values) > 1 else ""
            elif column == "distance":  # Distance column
                try:
                    val = values[2] if len(values) > 2 else ""
                    if not val or val == "":
                        return float('inf')
                    # Parse distance with units (e.g., "1.2km", "500m")
                    val_str = str(val).lower()
                    if 'km' in val_str:
                        return float(val_str.replace('km', '')) * 1000  # Convert to meters for sorting
                    elif 'm' in val_str:
                        return float(val_str.replace('m', ''))
                    else:
                        return float(val)
                except (ValueError, TypeError):
                    return float('inf')
            elif column == "snr":  # SNR column
                try:
                    val = values[3] if len(values) > 3 else ""
                    return float(val) if val and val != "" else float('-inf')
                except (ValueError, TypeError):
                    return float('-inf')
            elif column == "battery":  # Battery column
                try:
                    val = values[4] if len(values) > 4 else ""
                    # Remove '%' if present and convert to float
                    if val and val != "":
                        val_str = str(val).replace('%', '')
                        return float(val_str) if val_str else float('-inf')
                    return float('-inf')
                except (ValueError, TypeError):
                    return float('-inf')
            
            return ""
        
        # Sort items
        items.sort(key=get_sort_key, reverse=self.sort_reverse)
        
        # Reorder items in treeview
        for index, (item_id, _, _) in enumerate(items):
            self.nodes_tree.move(item_id, "", index)
        
        # Update column header to show sort direction
        for col in ("#0", "id", "name", "distance", "snr", "battery"):
            if col == "#0":
                header_text = "Node"
            elif col == "id":
                header_text = "ID"
            elif col == "name":
                header_text = "Name"
            elif col == "distance":
                header_text = "Distance"
            elif col == "snr":
                header_text = "SNR"
            elif col == "battery":
                header_text = "Battery"
            
            if col == column:
                arrow = " ↓" if self.sort_reverse else " ↑"
                header_text += arrow
            
            self.nodes_tree.heading(col, text=header_text)
    
    def send_message(self, event=None):
        """Send a text message"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        dest_display = self.dest_var.get()
        channel = int(self.channel_var.get())
        message = self.message_entry.get().strip()
        
        if not message:
            return
        
        # Extract actual destination ID from formatted string
        if " - " in dest_display:
            dest = dest_display.split(" - ")[0]
        else:
            dest = dest_display
        
        try:
            self.interface.sendText(message, dest, channelIndex=channel)
            
            # Add to message history
            timestamp = time.strftime('%H:%M:%S')
            msg_text = f"[{timestamp}] To {dest}: {message}\n"
            self.add_message_to_history(msg_text, dest)
            
            # Add to monitor console
            dest_name = self.get_node_display_name(dest)
            self.add_monitor_message(f"{message} to {dest_name} ({dest})", "TX")
            
            # Clear message entry
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
    
    def ping_node(self):
        """Send ping message to selected node"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        # Get selected node
        selection = self.nodes_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a node to ping")
            return
        
        selected_item = selection[0]
        item = self.nodes_tree.item(selected_item)
        values = item['values']
        
        if not values or len(values) < 2:
            messagebox.showwarning("Warning", "Invalid node selection")
            return
        
        node_id = values[1]  # Node ID is the second value (after column reorder)
        node_name = values[0]  # Short Name is the first value
        
        # Add back the ! prefix that was stripped for display
        node_id_with_prefix = f"!{node_id}"
        
        try:
            # Send ping message
            self.interface.sendText("ping", node_id_with_prefix)
            
            # Add to message history
            timestamp = time.strftime('%H:%M:%S')
            msg_text = f"[{timestamp}] PING to {node_name} ({node_id})\n"
            self.add_message_to_history(msg_text, node_id)
            
            messagebox.showinfo("Ping Sent", f"Ping sent to {node_name} ({node_id})")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to ping node: {e}")
    
    def traceroute_node(self):
        """Perform traceroute to selected node"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        # Get selected node
        selection = self.nodes_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a node for traceroute")
            return
        
        selected_item = selection[0]
        item = self.nodes_tree.item(selected_item)
        values = item['values']
        
        if not values or len(values) < 2:
            messagebox.showwarning("Warning", "Invalid node selection")
            return
        
        node_id = values[1]  # Node ID is the second value (after column reorder)
        node_name = values[0]  # Short Name is the first value
        
        # Add back the ! prefix that was stripped for display
        node_id_with_prefix = f"!{node_id}"
        
        # Show progress dialog
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Traceroute in Progress")
        progress_window.geometry("400x150")
        progress_window.transient(self.root)
        progress_window.grab_set()
        
        ttk.Label(progress_window, text=f"Running traceroute to {node_name} ({node_id})...").pack(pady=20)
        progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
        progress_bar.pack(pady=10)
        progress_bar.start()
        
        def run_traceroute():
            try:
                # Store traceroute results
                traceroute_results = []
                traceroute_complete = threading.Event()
                
                # Store original response handler
                original_response_handler = None
                if hasattr(self.interface, 'onResponseTraceRoute'):
                    original_response_handler = self.interface.onResponseTraceRoute
                
                def custom_traceroute_handler(p: dict):
                    """Custom traceroute response handler"""
                    try:
                        import google.protobuf.json_format
                        from meshtastic.protobuf import mesh_pb2
                        
                        UNK_SNR = -128  # Value representing unknown SNR
                        
                        # Parse the route discovery data
                        routeDiscovery = mesh_pb2.RouteDiscovery()
                        routeDiscovery.ParseFromString(p["decoded"]["payload"])
                        asDict = google.protobuf.json_format.MessageToDict(routeDiscovery)
                        
                        print(f"Received traceroute response: {asDict}")  # Debug
                        
                        # Build route information
                        route_info = {
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'destination': self.interface._nodeNumToId(p["to"], False) or f"{p['to']:08x}",
                            'origin': self.interface._nodeNumToId(p["from"], False) or f"{p['from']:08x}",
                            'hops_forward': [],
                            'hops_back': []
                        }
                        
                        # Process forward route (towards destination)
                        if "route" in asDict:
                            route_forward = asDict["route"]
                            snr_towards = asDict.get("snrTowards", [])
                            
                            for idx, nodeNum in enumerate(route_forward):
                                node_id = self.interface._nodeNumToId(nodeNum, False) or f"{nodeNum:08x}"
                                node_name = self.get_node_display_name(node_id)
                                snr = None
                                if idx < len(snr_towards) and snr_towards[idx] != UNK_SNR:
                                    snr = snr_towards[idx] / 4  # SNR is stored as 4x actual value
                                
                                route_info['hops_forward'].append({
                                    'hop': idx + 1,
                                    'node_id': node_id,
                                    'node_name': node_name,
                                    'snr': snr
                                })
                        
                        # Process return route (back to us)
                        if "routeBack" in asDict:
                            route_back = asDict["routeBack"]
                            snr_back = asDict.get("snrBack", [])
                            
                            for idx, nodeNum in enumerate(route_back):
                                node_id = self.interface._nodeNumToId(nodeNum, False) or f"{nodeNum:08x}"
                                node_name = self.get_node_display_name(node_id)
                                snr = None
                                if idx < len(snr_back) and snr_back[idx] != UNK_SNR:
                                    snr = snr_back[idx] / 4
                                
                                route_info['hops_back'].append({
                                    'hop': idx + 1,
                                    'node_id': node_id,
                                    'node_name': node_name,
                                    'snr': snr
                                })
                        
                        traceroute_results.append(route_info)
                        traceroute_complete.set()
                        
                        # Also call original handler for console output
                        if original_response_handler:
                            original_response_handler(p)
                            
                    except Exception as e:
                        print(f"Error in custom traceroute handler: {e}")
                        import traceback
                        traceback.print_exc()
                        traceroute_complete.set()
                
                # Replace the response handler temporarily
                self.interface.onResponseTraceRoute = custom_traceroute_handler
                
                # Send the actual traceroute request
                try:
                    print(f"Sending traceroute to {node_id}")
                    # Convert hex node_id to decimal
                    dest_id = int(node_id_with_prefix.replace('!', ''), 16)
                    # Use appropriate hop limit (7 is common default)
                    hop_limit = 7
                    
                    # Send traceroute directly without built-in timeout to avoid premature timeout
                    from meshtastic.protobuf import mesh_pb2, portnums_pb2
                    r = mesh_pb2.RouteDiscovery()
                    self.interface.sendData(
                        r,
                        destinationId=dest_id,
                        portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                        wantResponse=True,
                        onResponse=self.interface.onResponseTraceRoute,
                        channelIndex=0,
                        hopLimit=hop_limit,
                    )
                    
                    # The traceroute_complete event will be set by our custom handler
                    print("Traceroute request sent, waiting for response...")
                    
                except Exception as e:
                    print(f"Error sending traceroute: {e}")
                    # Don't re-raise, just set the completion event so we can handle it gracefully
                    traceroute_complete.set()
                
                # Wait for response with timeout (the mesh interface has its own timeout too)
                timeout_seconds = 90  # Increased timeout for multi-hop connections
                print(f"Waiting for traceroute response (timeout: {timeout_seconds}s)...")
                if traceroute_complete.wait(timeout=timeout_seconds):
                    # Restore original response handler
                    if original_response_handler:
                        self.interface.onResponseTraceRoute = original_response_handler
                    
                    # Generate report from real data
                    # Check if we got results from our custom handler
                    if traceroute_results:
                        route_info = traceroute_results[0]  # Get the first (should be only) result
                        timestamp = route_info['timestamp']
                        
                        traceroute_report = f"""Traceroute Report
Generated: {timestamp}
Target: {node_name} ({node_id})
Destination: {route_info['destination']}
Origin: {route_info['origin']}

"""
                        
                        # Add forward route information
                        if route_info['hops_forward']:
                            traceroute_report += "Route towards destination:\n"
                            traceroute_report += f"  Start: {route_info['destination']}\n"
                            for hop_data in route_info['hops_forward']:
                                snr_text = f" (SNR: {hop_data['snr']:.1f}dB)" if hop_data['snr'] is not None else " (SNR: ?)"
                                traceroute_report += f"  Hop {hop_data['hop']}: {hop_data['node_id']} ({hop_data['node_name']}){snr_text}\n"
                            traceroute_report += f"  End: {route_info['origin']}\n\n"
                        else:
                            traceroute_report += "Direct connection to destination (no intermediate hops)\n\n"
                        
                        # Add return route information
                        if route_info['hops_back']:
                            traceroute_report += "Route back to us:\n"
                            traceroute_report += f"  Start: {route_info['origin']}\n"
                            for hop_data in route_info['hops_back']:
                                snr_text = f" (SNR: {hop_data['snr']:.1f}dB)" if hop_data['snr'] is not None else " (SNR: ?)"
                                traceroute_report += f"  Hop {hop_data['hop']}: {hop_data['node_id']} ({hop_data['node_name']}){snr_text}\n"
                            traceroute_report += f"  End: {route_info['destination']}\n\n"
                        
                        total_forward_hops = len(route_info['hops_forward'])
                        total_back_hops = len(route_info['hops_back'])
                        
                        traceroute_report += f"Traceroute completed successfully.\n"
                        traceroute_report += f"Forward hops: {total_forward_hops}\n"
                        traceroute_report += f"Return hops: {total_back_hops}\n"
                    else:
                        # No results received - could be timeout from mesh interface or no response
                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                        traceroute_report = f"""Traceroute Report
Generated: {timestamp}
Target: {node_name} ({node_id})

Traceroute completed but no route data was received.

This could indicate:
1. The target node is not reachable via the mesh
2. The target node doesn't support traceroute functionality  
3. The target node is using incompatible firmware (requires 2.1.22+)
4. Network congestion or interference prevented response
5. The target node is currently offline or in deep sleep

Note: The mesh interface may have its own timeout that occurred first.
Try selecting a different target node or check mesh connectivity.
"""
                        
                else:
                    # Timeout - restore handler first
                    if original_response_handler:
                        self.interface.onResponseTraceRoute = original_response_handler
                        
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    traceroute_report = f"""Traceroute Report
Generated: {timestamp}
Target: {node_name} ({node_id})

Traceroute timed out after 30 seconds.
No response received from target node.

This could indicate:
1. The target node is not reachable
2. The target node is offline or sleeping
3. Network congestion or interference
4. The target node doesn't support traceroute functionality
5. Incompatible firmware versions

Try again or check if the node is active in the mesh.
"""
                
                # Close progress window and show results
                self.root.after(0, lambda: self.show_traceroute_results(progress_window, traceroute_report, node_name, node_id))
                
            except Exception as e:
                # Ensure handler is restored on error
                if original_response_handler:
                    self.interface.onResponseTraceRoute = original_response_handler
                error_msg = str(e)  # Capture error message in local variable
                self.root.after(0, lambda: self.show_traceroute_error(progress_window, error_msg))
        
        # Start traceroute in background thread
        threading.Thread(target=run_traceroute, daemon=True).start()
    
    def show_traceroute_results(self, progress_window, report, node_name, node_id):
        """Show traceroute results in popup with export option"""
        progress_window.destroy()
        
        # Create results window
        results_window = tk.Toplevel(self.root)
        results_window.title(f"Traceroute Results - {node_name}")
        results_window.geometry("600x400")
        results_window.transient(self.root)
        
        # Results text area
        text_frame = ttk.Frame(results_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        results_text = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, state=tk.NORMAL)
        results_text.pack(fill=tk.BOTH, expand=True)
        results_text.insert(tk.END, report)
        results_text.config(state=tk.DISABLED)
        
        # Buttons frame
        buttons_frame = ttk.Frame(results_window)
        buttons_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def export_report():
            # Show file type selection dialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")],
                initialfile=f"traceroute_{node_name}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if filename:
                try:
                    if filename.endswith('.json'):
                        # Export as JSON
                        import json
                        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Parse report to extract structured data
                        hops = []
                        status = "completed"
                        if "timed out" in report.lower():
                            status = "timeout"
                        elif "no route data" in report.lower():
                            status = "no_route"
                        else:
                            # Extract hop information from report
                            lines = report.split('\n')
                            for line in lines:
                                if line.startswith('Hop '):
                                    try:
                                        parts = line.split(': ', 1)
                                        if len(parts) == 2:
                                            hop_num = int(parts[0].replace('Hop ', ''))
                                            hop_info = parts[1]
                                            
                                            # Parse hop info
                                            if '(' in hop_info and ')' in hop_info:
                                                node_id_part = hop_info.split(' (')[0]
                                                name_part = hop_info.split(' (')[1].split(')')[0]
                                                
                                                snr = None
                                                if 'SNR:' in hop_info:
                                                    snr_part = hop_info.split('SNR: ')[1].split(')')[0]
                                                    try:
                                                        snr = float(snr_part)
                                                    except:
                                                        pass
                                                
                                                hops.append({
                                                    "hop": hop_num,
                                                    "node_id": node_id_part,
                                                    "node_name": name_part,
                                                    "snr": snr
                                                })
                                    except:
                                        continue
                        
                        json_data = {
                            "traceroute_report": {
                                "timestamp": timestamp,
                                "target_node_id": node_id,
                                "target_node_name": node_name,
                                "hops": hops,
                                "total_hops": len(hops),
                                "status": status
                            }
                        }
                        with open(filename, 'w') as f:
                            json.dump(json_data, f, indent=2)
                    else:
                        # Export as text
                        with open(filename, 'w') as f:
                            f.write(report)
                    
                    messagebox.showinfo("Export Successful", f"Traceroute report saved to {filename}")
                except Exception as e:
                    messagebox.showerror("Export Error", f"Failed to save report: {e}")
        
        ttk.Button(buttons_frame, text="Export Report", command=export_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Close", command=results_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def show_traceroute_error(self, progress_window, error_msg):
        """Show traceroute error"""
        progress_window.destroy()
        messagebox.showerror("Traceroute Error", f"Failed to perform traceroute: {error_msg}")
    
    def message_node(self):
        """Switch to Messages tab with selected node as destination"""
        # Get selected node
        selection = self.nodes_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a node to message")
            return
        
        selected_item = selection[0]
        item = self.nodes_tree.item(selected_item)
        values = item['values']
        
        if not values or len(values) < 2:
            messagebox.showwarning("Warning", "Invalid node selection")
            return
        
        node_id = values[1]  # Node ID is the second value (after column reorder)
        node_name = values[0]  # Short Name is the first value
        
        # Add back the ! prefix that was stripped for display
        node_id_with_prefix = f"!{node_id}"
        
        # Switch to Messages tab
        self.notebook.select(2)  # Messages tab is index 2 (0: Connection, 1: Nodes, 2: Messages, 3: Config)
        
        # Set the selected node as destination (find the formatted entry)
        for dest_option in self.dest_combo['values']:
            if dest_option.startswith(node_id_with_prefix + " - "):
                self.dest_var.set(dest_option)
                break
        else:
            # Fallback to just the node ID if formatted version not found
            self.dest_var.set(node_id_with_prefix)
        
        # Focus on message entry
        self.message_entry.focus_set()
    
    def request_position(self):
        """Request position from selected node"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        # Get selected node
        selection = self.nodes_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a node to request position from")
            return
        
        selected_item = selection[0]
        item = self.nodes_tree.item(selected_item)
        values = item['values']
        
        if not values or len(values) < 2:
            messagebox.showwarning("Warning", "Invalid node selection")
            return
        
        node_id = values[1]  # Node ID is the second value (after column reorder)
        
        # Add back the ! prefix that was stripped for display
        node_id_with_prefix = f"!{node_id}"
        
        try:
            # Convert hex node_id to decimal
            dest_id = int(node_id_with_prefix.replace('!', ''), 16)
            print(f"Sending position request to {node_id} ({dest_id})")
            
            self.interface.sendPosition(
                destinationId=dest_id,
                wantResponse=True,
                channelIndex=0,
            )
            
            messagebox.showinfo("Success", f"Position request sent to {node_id}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send position request: {str(e)}")
    
    def request_telemetry(self):
        """Request telemetry from selected node"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        # Get selected node
        selection = self.nodes_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a node to request telemetry from")
            return
        
        selected_item = selection[0]
        item = self.nodes_tree.item(selected_item)
        values = item['values']
        
        if not values or len(values) < 2:
            messagebox.showwarning("Warning", "Invalid node selection")
            return
        
        node_id = values[1]  # Node ID is the second value (after column reorder)
        
        # Add back the ! prefix that was stripped for display
        node_id_with_prefix = f"!{node_id}"
        
        try:
            # Convert hex node_id to decimal
            dest_id = int(node_id_with_prefix.replace('!', ''), 16)
            print(f"Sending device telemetry request to {node_id} ({dest_id})")
            
            self.interface.sendTelemetry(
                destinationId=dest_id,
                wantResponse=True,
                channelIndex=0,
                telemetryType="device_metrics",
            )
            
            messagebox.showinfo("Success", f"Device telemetry request sent to {node_id}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send telemetry request: {str(e)}")
    
    def remove_node(self):
        """Remove selected node"""
        selected = self.nodes_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a node to remove")
            return
        
        item = self.nodes_tree.item(selected[0])
        node_id = item['values'][0] if item['values'] else None
        node_name = item['text']
        
        if not node_id:
            messagebox.showwarning("Warning", "Invalid node selected")
            return
        
        # Confirm removal
        result = messagebox.askyesno("Confirm Removal", 
                                   f"Remove node '{node_name}' ({node_id}) from the list?\n\n" +
                                   "Note: This only removes it from the GUI display. " +
                                   "The node will reappear if it sends packets.")
        
        if result:
            # Remove from tree view
            self.nodes_tree.delete(selected[0])
            # Remove from nodes dictionary if present
            if node_id in self.nodes:
                del self.nodes[node_id]
            # Remove from favorites if present
            if node_id in self.favorite_nodes:
                self.favorite_nodes.remove(node_id)
            messagebox.showinfo("Success", f"Node '{node_name}' removed from display")

    def favorite_node_node(self):
        """Toggle favorite status for selected node"""
        selected = self.nodes_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a node to favorite")
            return
        
        item = self.nodes_tree.item(selected[0])
        node_id = item['values'][0] if item['values'] else None
        node_name = item['text']
        
        if not node_id:
            messagebox.showwarning("Warning", "Invalid node selected")
            return
        
        # Toggle favorite status
        if node_id in self.favorite_nodes:
            self.favorite_nodes.remove(node_id)
            messagebox.showinfo("Success", f"Removed '{node_name}' from favorites")
        else:
            self.favorite_nodes.add(node_id)
            messagebox.showinfo("Success", f"Added '{node_name}' to favorites")
        
        # Refresh display to update favorite indicators
        self.refresh_nodes()
    
    def on_config_section_select(self, event):
        """Handle configuration section selection"""
        if not self.config_sections.curselection():
            return
        
        selection = self.config_sections.curselection()[0]
        section_name = self.config_sections.get(selection)
        config_type = self.config_section_map[section_name]
        
        self.current_config_section = config_type
        self.load_config_section(config_type)
    
    def load_config_section(self, config_type):
        """Load and display configuration fields for a specific section"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        try:
            # Clear existing widgets
            for widget in self.config_fields_frame.winfo_children():
                widget.destroy()
            self.config_widgets.clear()
            
            # Get configuration object
            node = self.interface.localNode
            if config_type in ['device', 'lora', 'position', 'power', 'network', 'bluetooth', 'display', 'serial']:
                config_obj = getattr(node.localConfig, config_type, None)
            else:
                config_obj = getattr(node.moduleConfig, config_type, None)
            
            if not config_obj:
                ttk.Label(self.config_fields_frame, text=f"Configuration '{config_type}' not available").pack(pady=10)
                return
            
            
            # Create fields for each configuration parameter
            self.create_config_fields(config_obj, config_type)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load config section: {e}")
            import traceback
            traceback.print_exc()
    
    def create_config_fields(self, config_obj, config_type):
        """Create interactive fields for configuration object"""
        descriptor = config_obj.DESCRIPTOR
        
        for field in descriptor.fields:
            if field.name == 'version':  # Skip version field
                continue
                
            frame = ttk.Frame(self.config_fields_frame)
            frame.pack(fill=tk.X, pady=2, padx=10)
            
            # Create label
            label_text = field.name.replace('_', ' ').title()
            label = ttk.Label(frame, text=f"{label_text}:", width=20, anchor='w')
            label.pack(side=tk.LEFT, padx=(0, 10))
            
            # Get current value
            current_value = getattr(config_obj, field.name)
            
            # Skip complex fields that are better left as read-only
            if field.label == field.LABEL_REPEATED:
                # This is a repeated field (list/array) - show as read-only
                display_value = str(list(current_value)) if current_value else "[]"
                info_label = ttk.Label(frame, text=f"(List: {display_value})", 
                                     foreground="gray", font=("TkDefaultFont", 8))
                info_label.pack(side=tk.LEFT)
                continue  # Skip creating editable widget for repeated fields
            
            # Create appropriate widget based on field type
            widget = self.create_config_widget(frame, field, current_value)
            
            if widget:
                self.config_widgets[f"{config_type}.{field.name}"] = {
                    'widget': widget,
                    'field': field,
                    'current_value': current_value
                }
        
        # Add special fields for specific config types
        if config_type == 'device':
            self.add_device_special_fields()
        elif config_type == 'position':
            self.add_position_special_fields()
    
    def create_config_widget(self, parent, field, current_value):
        """Create appropriate widget for configuration field"""
        
        # Handle different field types
        if field.type == field.TYPE_BOOL:
            var = tk.BooleanVar(value=current_value)
            widget = ttk.Checkbutton(parent, variable=var, style='Custom.TCheckbutton')
            widget.var = var
            widget.pack(side=tk.LEFT)
            return widget
            
        elif field.type == field.TYPE_ENUM:
            # Create combobox for enum values
            enum_values = [enum_val.name for enum_val in field.enum_type.values]
            current_name = field.enum_type.values_by_number.get(current_value, enum_values[0]).name
            
            var = tk.StringVar(value=current_name)
            widget = ttk.Combobox(parent, textvariable=var, values=enum_values, state="readonly", width=20)
            widget.var = var
            widget.pack(side=tk.LEFT)
            return widget
            
        elif field.type in [field.TYPE_INT32, field.TYPE_UINT32, field.TYPE_INT64, field.TYPE_UINT64]:
            var = tk.StringVar(value=str(current_value))
            widget = ttk.Entry(parent, textvariable=var, width=15)
            widget.var = var
            widget.pack(side=tk.LEFT)
            
            # Add validation for numeric fields
            def validate_number(value):
                if not value:  # Allow empty
                    return True
                try:
                    int(value)
                    return True
                except ValueError:
                    return False
            
            vcmd = (parent.register(validate_number), '%P')
            widget.config(validate='key', validatecommand=vcmd)
            return widget
            
        elif field.type == field.TYPE_FLOAT:
            var = tk.StringVar(value=str(current_value))
            widget = ttk.Entry(parent, textvariable=var, width=15)
            widget.var = var
            widget.pack(side=tk.LEFT)
            
            # Add validation for float fields
            def validate_float(value):
                if not value:  # Allow empty
                    return True
                try:
                    float(value)
                    return True
                except ValueError:
                    return False
            
            vcmd = (parent.register(validate_float), '%P')
            widget.config(validate='key', validatecommand=vcmd)
            return widget
            
        elif field.type == field.TYPE_STRING:
            var = tk.StringVar(value=str(current_value))
            widget = ttk.Entry(parent, textvariable=var, width=25)
            widget.var = var
            widget.pack(side=tk.LEFT)
            return widget
            
        elif field.type == field.TYPE_BYTES:
            # Handle bytes fields as read-only hex display
            if isinstance(current_value, bytes):
                display_value = current_value.hex() if current_value else ""
            else:
                display_value = str(current_value)
            
            info_label = ttk.Label(parent, text=f"(Bytes: {display_value[:20]}{'...' if len(display_value) > 20 else ''})", 
                                 foreground="gray", font=("TkDefaultFont", 8))
            info_label.pack(side=tk.LEFT)
            return None  # Don't create editable widget for bytes
            
        else:
            # For unknown types, try to determine if it's a simple value
            if isinstance(current_value, (list, dict, bytes)):
                # Complex types - show as read-only
                display_value = str(current_value)[:30] + ("..." if len(str(current_value)) > 30 else "")
                info_label = ttk.Label(parent, text=f"(Complex: {display_value})", 
                                     foreground="gray", font=("TkDefaultFont", 8))
                info_label.pack(side=tk.LEFT)
                return None
            else:
                # Simple unknown type - allow editing as string
                var = tk.StringVar(value=str(current_value))
                widget = ttk.Entry(parent, textvariable=var, width=20)
                widget.var = var
                widget.pack(side=tk.LEFT)
                return widget
    
    def refresh_config(self):
        """Refresh the current configuration section"""
        if self.current_config_section:
            self.load_config_section(self.current_config_section)
        else:
            messagebox.showinfo("Info", "Please select a configuration section first")
    
    def save_config(self):
        """Save current configuration section to device"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        if not self.current_config_section:
            messagebox.showwarning("Warning", "Please select a configuration section first")
            return
        
        try:
            # Get the configuration object
            node = self.interface.localNode
            config_type = self.current_config_section
            
            if config_type in ['device', 'lora', 'position', 'power', 'network', 'bluetooth', 'display', 'serial']:
                config_obj = getattr(node.localConfig, config_type)
            else:
                config_obj = getattr(node.moduleConfig, config_type)
            
            # Update configuration from widgets
            changes_made = False
            special_changes = {}  # Track special field changes
            
            for widget_key, widget_info in self.config_widgets.items():
                if widget_key.startswith(f"{config_type}."):
                    field_name = widget_key.split('.', 1)[1]
                    field = widget_info['field']
                    widget = widget_info['widget']
                    
                    # Handle special fields (owner name, position, etc.)
                    if 'special_type' in widget_info:
                        special_type = widget_info['special_type']
                        if hasattr(widget, 'get'):
                            new_value = widget.get()
                        elif hasattr(widget, 'var'):
                            new_value = widget.var.get()
                        else:
                            continue
                            
                        special_changes[special_type] = new_value
                        continue
                    
                    # Get new value from widget
                    if hasattr(widget, 'var'):
                        new_value = widget.var.get()
                        print(f"Processing field {field_name}: '{new_value}' (type: {type(new_value)})")
                    else:
                        continue
                    
                    # Convert value based on field type
                    try:
                        if field.type == field.TYPE_BOOL:
                            converted_value = bool(new_value)
                        elif field.type == field.TYPE_ENUM:
                            # Convert enum name back to number
                            converted_value = field.enum_type.values_by_name[new_value].number
                        elif field.type in [field.TYPE_INT32, field.TYPE_UINT32, field.TYPE_INT64, field.TYPE_UINT64]:
                            # Handle special cases for numeric fields
                            if isinstance(new_value, str):
                                if new_value.strip() == '' or new_value == '[]' or new_value == 'None':
                                    converted_value = 0
                                else:
                                    converted_value = int(new_value)
                            else:
                                converted_value = int(new_value) if new_value else 0
                        elif field.type == field.TYPE_FLOAT:
                            if isinstance(new_value, str):
                                if new_value.strip() == '' or new_value == '[]' or new_value == 'None':
                                    converted_value = 0.0
                                else:
                                    converted_value = float(new_value)
                            else:
                                converted_value = float(new_value) if new_value else 0.0
                        else:
                            converted_value = str(new_value)
                    except ValueError as ve:
                        print(f"Warning: Could not convert {field_name} value '{new_value}' (type: {type(new_value)}): {ve}")
                        print(f"Field type: {field.type}, Field label: {field.label}")
                        # Skip this field if conversion fails
                        continue
                    
                    # Check if value changed
                    current_value = getattr(config_obj, field_name)
                    if current_value != converted_value:
                        setattr(config_obj, field_name, converted_value)
                        changes_made = True
                        print(f"Updated {field_name}: {current_value} -> {converted_value}")
            
            # Process special field changes
            special_changes_made = self.process_special_field_changes(special_changes, config_type)
            
            if changes_made or special_changes_made:
                # Write configuration to device
                print(f"Writing {config_type} configuration to device...")
                node.writeConfig(config_type)
                messagebox.showinfo("Success", f"Configuration saved to device!\nChanges written to {config_type} section.")
                
                # Refresh the display
                self.load_config_section(config_type)
                
                # If position was configured, also refresh device info display
                if config_type == 'position' and special_changes_made:
                    self.root.after(2000, self.update_device_info)  # Delay to let device process the change
            else:
                messagebox.showinfo("Info", "No changes detected")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")
            import traceback
            traceback.print_exc()
    
    def reset_config_section(self):
        """Reset current configuration section to defaults"""
        if not self.current_config_section:
            messagebox.showwarning("Warning", "Please select a configuration section first")
            return
        
        result = messagebox.askyesno("Confirm Reset", 
                                   f"Reset {self.current_config_section} configuration to defaults?\nThis cannot be undone.")
        if result:
            messagebox.showinfo("Info", "Reset to default feature not yet implemented")
    
    def export_config(self):
        """Export configuration to YAML file"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".yaml",
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                from . import __main__
                config_yaml = __main__.export_config(self.interface)
                
                with open(filename, 'w') as f:
                    f.write(config_yaml)
                
                messagebox.showinfo("Success", f"Configuration exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export config: {e}")
    
    def import_config(self):
        """Import configuration from YAML file"""
        filename = filedialog.askopenfilename(
            filetypes=[("YAML files", "*.yaml"), ("All files", "*.*")]
        )
        
        if filename:
            messagebox.showinfo("Info", "Import config feature not yet implemented")
    
    def update_status(self, message):
        """Update status bar message"""
        self.status_label.config(text=message)
    
    def update_connection_status(self):
        """Update connection status"""
        if self.is_connected:
            self.update_status("Connected")
            self.update_device_stats()
        else:
            self.update_status("Not connected")
            self.stats_label.config(text="")
    
    def update_device_info(self):
        """Update device information display on Connection tab"""
        try:
            if self.interface and hasattr(self, 'device_info_text'):
                # Force refresh of node info
                self.interface.localNode.requestInfo()
                # Schedule device info update after short delay
                self.root.after(1000, self._refresh_device_info_display)
        except Exception as e:
            print(f"Error updating device info: {e}")
    
    def _refresh_device_info_display(self):
        """Internal method to refresh the device info display"""
        try:
            if self.interface and hasattr(self, 'device_info_text'):
                # Get updated device info
                info = self.get_device_info()
                # Update the display
                self.device_info_text.config(state=tk.NORMAL)
                self.device_info_text.delete('1.0', tk.END)
                self.device_info_text.insert('1.0', info)
                self.device_info_text.config(state=tk.DISABLED)
        except Exception as e:
            print(f"Error refreshing device info display: {e}")
    
    def update_device_stats(self):
        """Update device statistics in status bar"""
        if not self.interface:
            self.stats_label.config(text="")
            return
        
        try:
            # Get node count
            node_count = len(self.interface.nodes) if self.interface.nodes else 0
            
            # Get device metrics if available
            my_info = self.interface.getMyNodeInfo()
            stats_text = f"Nodes: {node_count}"
            
            if my_info:
                device_metrics = my_info.get('deviceMetrics', {})
                if 'batteryLevel' in device_metrics:
                    battery = min(100, max(0, round(device_metrics['batteryLevel'])))
                    stats_text += f" | Battery: {battery}%"
                if 'voltage' in device_metrics:
                    voltage = device_metrics['voltage']
                    stats_text += f" | Voltage: {voltage:.1f}V"
                if 'channelUtilization' in device_metrics:
                    util = device_metrics['channelUtilization']
                    stats_text += f" | Channel: {util:.1f}%"
            
            self.stats_label.config(text=stats_text)
            
        except Exception as e:
            logging.error(f"Error updating device stats: {e}")
            self.stats_label.config(text="")
    
    def on_connection_method_changed(self):
        """Handle connection method change - show/hide relevant parameters"""
        method = self.conn_method.get()
        
        # Hide all parameters first
        self.serial_label.grid_remove()
        self.serial_port.grid_remove()
        self.ble_label.grid_remove()
        self.ble_device.grid_remove()
        self.tcp_label.grid_remove()
        self.tcp_host.grid_remove()
        
        # Hide/show scan BLE button based on connection method
        if hasattr(self, 'scan_btn'):
            if method == "ble":
                self.scan_btn.pack(side=tk.LEFT, padx=5)
            else:
                self.scan_btn.pack_forget()
        
        # Show only relevant parameters for selected method
        if method == "serial":
            self.serial_label.grid()
            self.serial_port.grid()
        elif method == "ble":
            self.ble_label.grid()
            self.ble_device.grid()
        elif method == "tcp":
            self.tcp_label.grid()
            self.tcp_host.grid()
    
    def refresh_connection_options(self):
        """Refresh available connection options for dropdowns"""
        try:
            # Serial ports
            import glob
            import os
            serial_ports = []
            
            # Common serial port patterns
            for pattern in ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/ttyS*", "/dev/cu.usbmodem*", "/dev/cu.usbserial*"]:
                serial_ports.extend(glob.glob(pattern))
            
            # Add common Windows COM ports if on Windows
            if os.name == 'nt':
                for i in range(1, 21):
                    serial_ports.append(f"COM{i}")
            
            if not serial_ports:
                serial_ports = ["/dev/ttyACM0", "/dev/ttyUSB0", "COM3", "COM4"]
            
            self.serial_port['values'] = serial_ports
            
            # TCP hosts (common defaults)
            tcp_hosts = ["localhost", "192.168.1.1", "meshtastic.local"]
            self.tcp_host['values'] = tcp_hosts
            
        except Exception as e:
            logging.error(f"Error refreshing connection options: {e}")
    
    def on_search_changed(self, event=None):
        """Handle search text or category change"""
        search_text = self.search_entry.get().lower()
        search_category = self.search_category.get()
        
        # Get all items
        all_items = list(self.nodes_tree.get_children())
        
        if not search_text:
            # Show all items if no search text
            for item_id in all_items:
                self.nodes_tree.reattach(item_id, "", "end")
        else:
            # Filter items based on search criteria
            for item_id in all_items:
                item = self.nodes_tree.item(item_id)
                text = item['text']
                values = item['values']
                
                match = False
                if search_category == "All":
                    # Search in all fields
                    if (search_text in str(text).lower() or 
                        (len(values) > 0 and search_text in str(values[0]).lower()) or  # ID
                        (len(values) > 1 and search_text in str(values[1]).lower()) or  # Name
                        (len(values) > 2 and search_text in str(values[2]).lower()) or  # Distance
                        (len(values) > 3 and search_text in str(values[3]).lower()) or  # SNR
                        (len(values) > 4 and search_text in str(values[4]).lower())):   # Battery
                        match = True
                elif search_category == "Node" and search_text in str(text).lower():
                    match = True
                elif search_category == "ID" and len(values) > 0 and search_text in str(values[0]).lower():
                    match = True
                elif search_category == "Name" and len(values) > 1 and search_text in str(values[1]).lower():
                    match = True
                
                if match:
                    self.nodes_tree.reattach(item_id, "", "end")
                else:
                    self.nodes_tree.detach(item_id)
    
    def clear_search(self):
        """Clear search entry, show all nodes and refresh node list"""
        self.search_entry.delete(0, tk.END)
        
        # Refresh the node list
        self.refresh_nodes()
        
        # Ensure all nodes are visible by reattaching any detached items
        all_items = list(self.nodes_tree.get_children())
        
        # Get any detached items and reattach them
        for item_id in all_items:
            try:
                # Try to reattach in case it was detached
                self.nodes_tree.reattach(item_id, "", "end")
            except tk.TclError:
                # Item might already be attached, ignore error
                pass
        
        # Also trigger the search change to ensure everything is shown
        self.on_search_changed()
    
    def on_chat_selected(self, event=None):
        """Handle chat selection in active chats list"""
        selection = self.active_chats.curselection()
        if not selection:
            return
        
        chat_display = self.active_chats.get(selection[0])
        # Extract node ID from the display format
        if " - " in chat_display:
            node_id = chat_display.split(" - ")[0]
        else:
            node_id = chat_display
        
        # Load chat history for the selected node
        self.load_chat_history(node_id)
        
        # Set the selected node as destination in compose area
        for dest_option in self.dest_combo['values']:
            if dest_option.startswith(node_id + " - "):
                self.dest_var.set(dest_option)
                break
        else:
            self.dest_var.set(node_id)
    
    def load_chat_history(self, node_id):
        """Load chat history for specific node"""
        self.message_history.config(state=tk.NORMAL)
        self.message_history.delete('1.0', tk.END)
        
        if node_id in self.active_chats_data:
            for message in self.active_chats_data[node_id]:
                self.message_history.insert(tk.END, message)
        
        self.message_history.see(tk.END)
        self.message_history.config(state=tk.DISABLED)
    
    def add_to_active_chats(self, node_id, message):
        """Add message to active chats and update display"""
        if node_id not in self.active_chats_data:
            self.active_chats_data[node_id] = []
        
        self.active_chats_data[node_id].append(message)
        
        # Update active chats list display
        self.update_active_chats_display()
    
    def update_active_chats_display(self):
        """Update the active chats list display"""
        current_selection = None
        selection = self.active_chats.curselection()
        if selection:
            current_selection = self.active_chats.get(selection[0])
        
        self.active_chats.delete(0, tk.END)
        
        # Sort by most recent activity
        sorted_chats = sorted(self.active_chats_data.keys(), 
                            key=lambda x: len(self.active_chats_data[x]), 
                            reverse=True)
        
        for node_id in sorted_chats:
            # Get node name for display
            if node_id == '^all':
                node_name = "All Broadcast Messages"
            else:
                node_name = "Unknown"
                try:
                    if self.interface and self.interface.nodes:
                        # Try both with and without ! prefix
                        node_key = None
                        if node_id in self.interface.nodes:
                            node_key = node_id
                        elif f"!{node_id}" in self.interface.nodes:
                            node_key = f"!{node_id}"
                        elif node_id.startswith('!') and node_id[1:] in self.interface.nodes:
                            node_key = node_id[1:]
                        
                        if node_key:
                            node_info = self.interface.nodes[node_key]
                            user = node_info.get('user', {})
                            node_name = user.get('longName', 'Unknown')
                except:
                    pass
            
            chat_display = f"{node_id} - {node_name}"
            self.active_chats.insert(tk.END, chat_display)
            
            # Restore selection if it matches
            if current_selection and current_selection == chat_display:
                self.active_chats.selection_set(tk.END)
    
    def get_node_display_name(self, node_id):
        """Get display name for a node ID"""
        if node_id == BROADCAST_ADDR:
            return "Broadcast"
        
        try:
            if self.interface and self.interface.nodes:
                # Try both with and without ! prefix
                node_key = None
                if node_id in self.interface.nodes:
                    node_key = node_id
                elif f"!{node_id}" in self.interface.nodes:
                    node_key = f"!{node_id}"
                elif node_id.startswith('!') and node_id[1:] in self.interface.nodes:
                    node_key = node_id[1:]
                
                if node_key:
                    node_info = self.interface.nodes[node_key]
                    user = node_info.get('user', {})
                    return user.get('longName', f'Node {node_id}')
        except:
            pass
        
        return f"Node {node_id}"
    
    def load_message_history_from_device(self):
        """Load previous message history from connected device using Store & Forward"""
        if not self.interface:
            return
        
        try:
            # Check if Store & Forward is available and enabled
            local_node = self.interface.localNode
            if not local_node:
                logging.info("Local node not available for message history request")
                return
            
            # Check if store & forward module is configured
            try:
                store_forward_config = local_node.moduleConfig.store_forward
                if not store_forward_config.enabled:
                    logging.info("Store & Forward module not enabled - skipping message history")
                    return
            except:
                logging.info("Store & Forward module not available - checking alternative history sources")
                # Try alternative methods if Store & Forward is not available
                self.load_alternative_message_history()
                return
            
            logging.info("Requesting message history from Store & Forward router...")
            
            # Set up response handler for store & forward messages
            self.setup_store_forward_handler()
            
            # Send a CLIENT_HISTORY request to the Store & Forward router
            self.request_store_forward_history()
            
        except Exception as e:
            logging.error(f"Error loading message history from device: {e}")
            import traceback
            traceback.print_exc()
    
    def setup_store_forward_handler(self):
        """Setup handler for Store & Forward responses"""
        try:
            # Subscribe to Store & Forward messages
            pub.subscribe(self.on_store_forward_message, "meshtastic.receive.data.STORE_FORWARD_APP")
        except:
            pass  # Subscription might already exist or not be available
    
    def request_store_forward_history(self):
        """Request message history from Store & Forward router"""
        try:
            from meshtastic.protobuf import storeforward_pb2, portnums_pb2
            
            # Create a Store & Forward history request
            sf_request = storeforward_pb2.StoreAndForward()
            sf_request.rr = storeforward_pb2.StoreAndForward.RequestResponse.CLIENT_HISTORY
            
            # Set up history parameters (request last 50 messages in a 24-hour window)
            sf_request.history.history_messages = 50  # Number of messages to request
            sf_request.history.window = 24 * 60 * 60  # 24 hours in seconds
            sf_request.history.last_request = int(time.time()) - (24 * 60 * 60)  # Start from 24 hours ago
            
            # Send the request to broadcast (Store & Forward routers will respond)
            self.interface.sendData(
                sf_request,
                destinationId=BROADCAST_ADDR,
                portNum=portnums_pb2.PortNum.STORE_FORWARD_APP,
                wantResponse=False  # We'll get responses via the normal receive path
            )
            
            logging.info("Store & Forward history request sent")
            self.add_monitor_message("Requested message history from Store & Forward router", "SYSTEM")
            
        except Exception as e:
            logging.error(f"Error requesting Store & Forward history: {e}")
            import traceback
            traceback.print_exc()
    
    def on_store_forward_message(self, packet, interface):
        """Handle Store & Forward responses including message history"""
        try:
            from meshtastic.protobuf import storeforward_pb2
            
            decoded = packet.get('decoded', {})
            if decoded.get('portnum') != 'STORE_FORWARD_APP':
                return
            
            payload = decoded.get('payload')
            if not payload:
                return
            
            # Parse Store & Forward message
            sf_message = storeforward_pb2.StoreAndForward()
            sf_message.ParseFromString(payload)
            
            from_id = packet.get('fromId') or packet.get('from')
            
            if sf_message.rr == storeforward_pb2.StoreAndForward.RequestResponse.ROUTER_TEXT_DIRECT:
                # This is a direct message from history
                if sf_message.text:
                    # Decode the stored message
                    try:
                        message_text = sf_message.text.decode('utf-8')
                        sender_name = self.get_node_display_name(from_id)
                        
                        # Add to message history with timestamp
                        timestamp = time.strftime('%H:%M:%S')
                        msg_text = f"[{timestamp}] Historical from {sender_name} ({from_id}): {message_text}\n"
                        
                        self.root.after(0, lambda t=msg_text, f=from_id: self.add_message_to_history(t, f))
                        self.add_monitor_message(f"Historical message from {sender_name}: {message_text}", "HISTORY")
                        
                    except UnicodeDecodeError:
                        logging.warning("Could not decode historical message text")
                        
            elif sf_message.rr == storeforward_pb2.StoreAndForward.RequestResponse.ROUTER_TEXT_BROADCAST:
                # This is a broadcast message from history
                if sf_message.text:
                    try:
                        message_text = sf_message.text.decode('utf-8')
                        sender_name = self.get_node_display_name(from_id)
                        
                        timestamp = time.strftime('%H:%M:%S')
                        msg_text = f"[{timestamp}] Historical broadcast from {sender_name} ({from_id}): {message_text}\n"
                        
                        self.root.after(0, lambda t=msg_text, f=from_id: self.add_message_to_history(t, f, True))  # True for broadcast
                        self.add_monitor_message(f"Historical broadcast from {sender_name}: {message_text}", "HISTORY")
                        
                    except UnicodeDecodeError:
                        logging.warning("Could not decode historical broadcast message text")
                        
            elif sf_message.rr == storeforward_pb2.StoreAndForward.RequestResponse.ROUTER_STATS:
                # Store & Forward router statistics
                if sf_message.stats:
                    stats = sf_message.stats
                    router_name = self.get_node_display_name(from_id)
                    stats_msg = (f"Store & Forward stats from {router_name}: "
                               f"{stats.messages_saved}/{stats.messages_total} messages, "
                               f"uptime: {stats.up_time}s")
                    logging.info(stats_msg)
                    self.add_monitor_message(stats_msg, "STATS")
                    
        except Exception as e:
            logging.error(f"Error processing Store & Forward message: {e}")
            import traceback
            traceback.print_exc()
    
    def load_alternative_message_history(self):
        """Load message history using alternative methods when Store & Forward is not available"""
        try:
            logging.info("Attempting to load message history from alternative sources...")
            
            # Method 1: Check if there are any recent messages in the device logs
            # This would require log access which isn't directly available
            
            # Method 2: Create placeholder entries for known nodes to show they're available for messaging
            if self.interface and self.interface.nodes:
                logging.info("Creating conversation placeholders for known nodes")
                
                for node_id, node_data in self.interface.nodes.items():
                    try:
                        user = node_data.get('user', {})
                        node_name = user.get('longName', 'Unknown')
                        
                        # Create a placeholder message to show the node is available
                        timestamp = time.strftime('%H:%M:%S')
                        placeholder_msg = f"[{timestamp}] Ready to chat with {node_name} ({node_id})\n"
                        
                        # Only add if we don't already have a conversation with this node
                        if node_id not in self.active_chats_data:
                            self.root.after(0, lambda t=placeholder_msg, f=node_id: self.add_message_to_history(t, f))
                            
                    except Exception as e:
                        logging.warning(f"Error creating placeholder for node {node_id}: {e}")
                
                # Add a general informational message
                info_msg = ("Message history loaded from node database. "
                           "Historical messages not available without Store & Forward module.")
                self.add_monitor_message(info_msg, "INFO")
                
            else:
                logging.info("No nodes available for message history placeholders")
                
        except Exception as e:
            logging.error(f"Error loading alternative message history: {e}")
            import traceback
            traceback.print_exc()
    
    def add_monitor_message(self, message, msg_type="INFO"):
        """Add message to monitor console"""
        timestamp = time.strftime('%H:%M:%S')
        formatted_msg = f"[{timestamp}] {msg_type}: {message}\n"
        
        # Add to monitor data for export
        self.monitor_data.append(formatted_msg)
        
        # Add to console display
        self.monitor_console.config(state=tk.NORMAL)
        self.monitor_console.insert(tk.END, formatted_msg)
        self.monitor_console.see(tk.END)
        self.monitor_console.config(state=tk.DISABLED)
    
    def execute_cli_command(self, event=None):
        """Execute a Meshtastic CLI command"""
        command = self.cli_entry.get().strip()
        if not command:
            return
        
        # Clear the input
        self.cli_entry.delete(0, tk.END)
        
        # Log the command
        self.add_monitor_message(f"Executing command: {command}", "CMD")
        
        def run_command():
            try:
                # Import subprocess for running CLI commands
                import subprocess
                
                # Build the full meshtastic command
                full_command = f"meshtastic {command}"
                
                # Execute the command
                result = subprocess.run(
                    full_command.split(),
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Show result
                if result.returncode == 0:
                    output = result.stdout.strip()
                    if output:
                        self.root.after(0, lambda: self.add_monitor_message(f"Output: {output}", "RESULT"))
                    else:
                        self.root.after(0, lambda: self.add_monitor_message("Command executed successfully (no output)", "RESULT"))
                else:
                    error = result.stderr.strip() or f"Command failed with return code {result.returncode}"
                    self.root.after(0, lambda: self.add_monitor_message(f"Error: {error}", "ERROR"))
                    
            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: self.add_monitor_message("Command timed out after 30 seconds", "ERROR"))
            except FileNotFoundError:
                self.root.after(0, lambda: self.add_monitor_message("Meshtastic CLI not found in PATH", "ERROR"))
            except Exception as e:
                self.root.after(0, lambda: self.add_monitor_message(f"Error executing command: {e}", "ERROR"))
        
        # Run command in background thread
        threading.Thread(target=run_command, daemon=True).start()
    
    def export_console_history(self):
        """Export the console history to a file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"monitor_log_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(f"Meshtastic Monitor Log - Exported {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n\n")
                    for entry in self.monitor_data:
                        f.write(entry)
                
                messagebox.showinfo("Export Successful", f"Monitor log saved to {filename}")
                self.add_monitor_message(f"Console history exported to {filename}", "SYSTEM")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save log: {e}")
                self.add_monitor_message(f"Export failed: {e}", "ERROR")
    
    def export_raw_packets(self):
        """Export raw packet data to a file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"), 
                ("CSV files", "*.csv"), 
                ("Text files", "*.txt"), 
                ("All files", "*.*")
            ],
            initialfile=f"raw_packets_{time.strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    # Export as JSON
                    import json
                    export_data = {
                        'export_info': {
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'total_packets': len(self.raw_packet_data),
                            'exporter': 'Meshtastic GUI'
                        },
                        'packets': self.raw_packet_data
                    }
                    
                    with open(filename, 'w') as f:
                        json.dump(export_data, f, indent=2, default=str)
                        
                elif filename.endswith('.csv'):
                    # Export as CSV
                    import csv
                    with open(filename, 'w', newline='') as f:
                        if self.raw_packet_data:
                            # Create CSV headers based on packet structure
                            fieldnames = ['timestamp', 'interface_type', 'packet_id', 'from_id', 'to_id', 'portnum', 'payload_size', 'decoded_data']
                            writer = csv.DictWriter(f, fieldnames=fieldnames)
                            writer.writeheader()
                            
                            for entry in self.raw_packet_data:
                                packet = entry['packet']
                                decoded = packet.get('decoded', {})
                                
                                row = {
                                    'timestamp': entry['timestamp'],
                                    'interface_type': entry['interface_type'],
                                    'packet_id': packet.get('id', ''),
                                    'from_id': packet.get('fromId', packet.get('from', '')),
                                    'to_id': packet.get('toId', packet.get('to', '')),
                                    'portnum': decoded.get('portnum', ''),
                                    'payload_size': len(decoded.get('payload', b'')) if isinstance(decoded.get('payload'), bytes) else '',
                                    'decoded_data': str(decoded) if decoded else 'encrypted'
                                }
                                writer.writerow(row)
                else:
                    # Export as formatted text
                    with open(filename, 'w') as f:
                        f.write(f"Meshtastic Raw Packet Data Export\n")
                        f.write(f"Exported: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Total Packets: {len(self.raw_packet_data)}\n")
                        f.write("=" * 80 + "\n\n")
                        
                        for i, entry in enumerate(self.raw_packet_data, 1):
                            f.write(f"Packet #{i}\n")
                            f.write(f"Timestamp: {entry['timestamp']}\n")
                            f.write(f"Interface: {entry['interface_type']}\n")
                            f.write(f"Raw Data: {entry['packet']}\n")
                            f.write("-" * 80 + "\n\n")
                
                messagebox.showinfo("Export Successful", f"Raw packet data saved to {filename}")
                self.add_monitor_message(f"Raw packet data exported to {filename}", "SYSTEM")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save raw packet data: {e}")
                self.add_monitor_message(f"Raw packet export failed: {e}", "ERROR")
    
    def clear_console(self):
        """Clear the monitor console"""
        self.monitor_console.config(state=tk.NORMAL)
        self.monitor_console.delete('1.0', tk.END)
        self.monitor_console.config(state=tk.DISABLED)
        self.monitor_data.clear()
        self.raw_packet_data.clear()  # Also clear raw packet data
        self.add_monitor_message("Console cleared", "SYSTEM")
    
    def write(self, text):
        """Handle stdout/stderr redirection to console"""
        if text.strip():  # Only log non-empty text
            # Also print to original terminal
            self.original_stdout.write(text)
            self.original_stdout.flush()
            
            # Filter out packet processing - only show other terminal output
            if not any(skip in text.lower() for skip in ['received packet:', 'portnum:', 'non-text message received']):
                self.root.after(0, lambda t=text.strip(): self.add_monitor_message(t, "DEBUG"))
        return len(text)
    
    def flush(self):
        """Required for stdout/stderr redirection"""
        pass
    
    def show_help(self):
        """Show help popup with --help command output"""
        try:
            # Run the meshtastic --help command
            import subprocess
            result = subprocess.run(['meshtastic', '--help'], 
                                  capture_output=True, text=True, timeout=10)
            help_text = result.stdout
            
            if result.stderr:
                help_text += "\n\n" + result.stderr
                
        except Exception as e:
            help_text = f"Error getting help: {e}\n\nPlease run 'meshtastic --help' manually in your terminal."
        
        # Create popup window
        help_window = tk.Toplevel(self.root)
        help_window.title("Meshtastic Help")
        help_window.geometry("800x600")
        
        # Add scrolled text widget
        help_display = scrolledtext.ScrolledText(
            help_window,
            wrap=tk.WORD,
            bg='black',
            fg='green',
            font=('Courier', 9)
        )
        help_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Insert help text
        help_display.insert('1.0', help_text)
        help_display.config(state=tk.DISABLED)
        
        # Add close button
        close_frame = ttk.Frame(help_window)
        close_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Button(close_frame, text="Close", 
                  command=help_window.destroy).pack(side=tk.RIGHT)
    
    def start_message_monitoring(self):
        """Start periodic message monitoring"""
        self.message_monitor_active = True
        self.monitor_messages()
    
    def monitor_messages(self):
        """Monitor for new messages periodically"""
        if not self.message_monitor_active or not self.interface:
            return
        
        try:
            # Check if there are any new messages or packets waiting
            # This is a placeholder - in practice, the PubSub system should handle this
            # But we can add additional checking here if needed
            pass
        except Exception as e:
            logging.error(f"Error in message monitoring: {e}")
        
        # Schedule next check in 1 second
        if self.message_monitor_active:
            self.root.after(1000, self.monitor_messages)
    
    def stop_message_monitoring(self):
        """Stop message monitoring"""
        self.message_monitor_active = False
    
    def add_device_special_fields(self):
        """Add special fields for device configuration (owner name and short name)"""
        # Add separator
        separator = ttk.Separator(self.config_fields_frame, orient='horizontal')
        separator.pack(fill=tk.X, pady=10, padx=10)
        
        # Get current owner info from the interface
        current_owner = ""
        current_owner_short = ""
        
        try:
            if self.interface:
                my_info = self.interface.getMyNodeInfo()
                if my_info:
                    user_info = my_info.get('user', {})
                    current_owner = user_info.get('longName', '')
                    current_owner_short = user_info.get('shortName', '')
        except:
            pass
        
        # Owner name field
        owner_frame = ttk.Frame(self.config_fields_frame)
        owner_frame.pack(fill=tk.X, pady=2, padx=10)
        
        owner_label = ttk.Label(owner_frame, text="Owner Name:", width=20, anchor='w')
        owner_label.pack(side=tk.LEFT, padx=(0, 10))
        
        owner_entry = ttk.Entry(owner_frame)
        owner_entry.insert(0, current_owner)
        owner_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.config_widgets['device.owner_name'] = {
            'widget': owner_entry,
            'field': None,  # Special field
            'current_value': current_owner,
            'special_type': 'owner_name'
        }
        
        # Owner short name field
        owner_short_frame = ttk.Frame(self.config_fields_frame)
        owner_short_frame.pack(fill=tk.X, pady=2, padx=10)
        
        owner_short_label = ttk.Label(owner_short_frame, text="Owner Short Name:", width=20, anchor='w')
        owner_short_label.pack(side=tk.LEFT, padx=(0, 10))
        
        owner_short_entry = ttk.Entry(owner_short_frame)
        owner_short_entry.insert(0, current_owner_short)
        owner_short_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.config_widgets['device.owner_short'] = {
            'widget': owner_short_entry,
            'field': None,  # Special field
            'current_value': current_owner_short,
            'special_type': 'owner_short'
        }
    
    def add_position_special_fields(self):
        """Add special fields for position configuration (lat, lon, alt, remove position)"""
        # Add separator
        separator = ttk.Separator(self.config_fields_frame, orient='horizontal')
        separator.pack(fill=tk.X, pady=10, padx=10)
        
        # Get current position info
        current_lat = ""
        current_lon = ""
        current_alt = ""
        
        try:
            if self.interface:
                my_info = self.interface.getMyNodeInfo()
                if my_info:
                    position = my_info.get('position', {})
                    if 'latitude' in position:
                        current_lat = str(position['latitude'])
                    if 'longitude' in position:
                        current_lon = str(position['longitude'])
                    if 'altitude' in position:
                        current_alt = str(position['altitude'])
                        
                # Also force a device info refresh to get latest position after setting fixed position
                if hasattr(self, 'interface') and self.interface:
                    try:
                        # Request fresh node info which should include updated position
                        self.interface.localNode.requestInfo()
                    except:
                        pass
        except:
            pass
        
        # Latitude field
        lat_frame = ttk.Frame(self.config_fields_frame)
        lat_frame.pack(fill=tk.X, pady=2, padx=10)
        
        lat_label = ttk.Label(lat_frame, text="Latitude:", width=20, anchor='w')
        lat_label.pack(side=tk.LEFT, padx=(0, 10))
        
        lat_entry = ttk.Entry(lat_frame)
        lat_entry.insert(0, current_lat)
        lat_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.config_widgets['position.latitude'] = {
            'widget': lat_entry,
            'field': None,  # Special field
            'current_value': current_lat,
            'special_type': 'latitude'
        }
        
        # Longitude field
        lon_frame = ttk.Frame(self.config_fields_frame)
        lon_frame.pack(fill=tk.X, pady=2, padx=10)
        
        lon_label = ttk.Label(lon_frame, text="Longitude:", width=20, anchor='w')
        lon_label.pack(side=tk.LEFT, padx=(0, 10))
        
        lon_entry = ttk.Entry(lon_frame)
        lon_entry.insert(0, current_lon)
        lon_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.config_widgets['position.longitude'] = {
            'widget': lon_entry,
            'field': None,  # Special field
            'current_value': current_lon,
            'special_type': 'longitude'
        }
        
        # Altitude field
        alt_frame = ttk.Frame(self.config_fields_frame)
        alt_frame.pack(fill=tk.X, pady=2, padx=10)
        
        alt_label = ttk.Label(alt_frame, text="Altitude (meters):", width=20, anchor='w')
        alt_label.pack(side=tk.LEFT, padx=(0, 10))
        
        alt_entry = ttk.Entry(alt_frame)
        alt_entry.insert(0, current_alt)
        alt_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.config_widgets['position.altitude'] = {
            'widget': alt_entry,
            'field': None,  # Special field
            'current_value': current_alt,
            'special_type': 'altitude'
        }
        
        # Remove position button
        remove_frame = ttk.Frame(self.config_fields_frame)
        remove_frame.pack(fill=tk.X, pady=10, padx=10)
        
        remove_button = ttk.Button(remove_frame, text="Remove Fixed Position", 
                                  command=self.remove_fixed_position)
        remove_button.pack(side=tk.LEFT)
        
    def remove_fixed_position(self):
        """Remove fixed position from device"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        try:
            # Clear position fields in the interface
            if hasattr(self.interface, 'clearFixedPosition'):
                self.interface.clearFixedPosition()
            
            messagebox.showinfo("Success", "Fixed position removed from device")
            
            # Reload the position configuration section
            self.load_config_section('position')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove fixed position: {e}")
    
    def process_special_field_changes(self, special_changes, config_type):
        """Process changes to special fields like owner name and position"""
        changes_made = False
        
        try:
            # Handle owner name and short name changes (device config)
            if config_type == 'device':
                if 'owner_name' in special_changes:
                    owner_name = special_changes['owner_name'].strip()
                    if owner_name:
                        # Use setOwner method if available
                        if hasattr(self.interface, 'setOwner'):
                            self.interface.setOwner(owner_name)
                            changes_made = True
                            print(f"Set owner name to: {owner_name}")
                
                if 'owner_short' in special_changes:
                    owner_short = special_changes['owner_short'].strip()
                    if owner_short:
                        # Use setOwnerShort method if available  
                        if hasattr(self.interface, 'setOwnerShort'):
                            self.interface.setOwnerShort(owner_short)
                            changes_made = True
                            print(f"Set owner short name to: {owner_short}")
            
            # Handle position changes (position config)
            elif config_type == 'position':
                lat = special_changes.get('latitude', '').strip()
                lon = special_changes.get('longitude', '').strip()
                alt = special_changes.get('altitude', '').strip()
                
                # Check if we have valid position data
                if lat or lon or alt:
                    try:
                        # Convert to appropriate values, default to 0 if empty
                        lat_val = float(lat) if lat else 0.0
                        lon_val = float(lon) if lon else 0.0  
                        alt_val = int(alt) if alt else 0
                        
                        # Use CLI-style method to set fixed position
                        print(f"Setting fixed position: lat={lat_val}, lon={lon_val}, alt={alt_val}")
                        
                        # Get local node and set fixed position (like CLI does)
                        local_node = self.interface.localNode
                        local_node.setFixedPosition(lat_val, lon_val, alt_val)
                        
                        changes_made = True
                        print(f"Set fixed position: {lat_val}, {lon_val}, {alt_val}m")
                        
                    except ValueError as e:
                        messagebox.showerror("Error", f"Invalid position values: {e}")
        
        except Exception as e:
            print(f"Error processing special field changes: {e}")
            import traceback
            traceback.print_exc()
        
        return changes_made
    
    def run(self):
        """Start the GUI application"""
        try:
            self.root.mainloop()
        finally:
            # Restore original stdout/stderr
            if hasattr(self, 'original_stdout'):
                import sys
                sys.stdout = self.original_stdout
                sys.stderr = self.original_stderr


def main():
    """Main entry point for the GUI"""
    app = MeshtasticGUI()
    app.run()


if __name__ == "__main__":
    main()