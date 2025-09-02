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
        self.root.title("Meshtastic GUI")
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
        
        ttk.Radiobutton(method_frame, text="Serial/USB", variable=self.conn_method, 
                       value="serial", command=self.on_connection_method_changed).grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Radiobutton(method_frame, text="Bluetooth LE", variable=self.conn_method, 
                       value="ble", command=self.on_connection_method_changed).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(method_frame, text="TCP/IP", variable=self.conn_method, 
                       value="tcp", command=self.on_connection_method_changed).grid(row=0, column=2, sticky=tk.W, padx=5)
        
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
        self.scan_btn.pack(side=tk.LEFT, padx=5)
        
        self.connect_btn = ttk.Button(button_frame, text="Connect", 
                                     command=self.connect_device)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.disconnect_btn = ttk.Button(button_frame, text="Disconnect", 
                                        command=self.disconnect_device, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        # Connection status and info
        info_frame = ttk.LabelFrame(conn_frame, text="Device Information")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.device_info = scrolledtext.ScrolledText(info_frame, height=10)
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
        self.nodes_tree = ttk.Treeview(self.list_frame, columns=("id", "name", "distance", "snr", "battery"), 
                                      show="tree headings")
        
        self.nodes_tree.heading("#0", text="Node")
        self.nodes_tree.heading("id", text="ID")
        self.nodes_tree.heading("name", text="Name")
        self.nodes_tree.heading("distance", text="Distance")
        self.nodes_tree.heading("snr", text="SNR")
        self.nodes_tree.heading("battery", text="Battery")
        
        # Configure column widths
        self.nodes_tree.column("#0", width=100)
        self.nodes_tree.column("id", width=100)
        self.nodes_tree.column("name", width=150)
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
        for col in ("#0", "id", "name", "distance", "snr", "battery"):
            self.nodes_tree.heading(col, command=lambda c=col: self.sort_nodes_by_column(c))
        
        # Node actions
        actions_frame = ttk.Frame(nodes_frame)
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(actions_frame, text="Refresh Nodes", 
                  command=self.refresh_nodes).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Ping Node", 
                  command=self.ping_node).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Traceroute", 
                  command=self.traceroute_node).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Message", 
                  command=self.message_node).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Request Position", 
                  command=self.request_position).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Request Telemetry", 
                  command=self.request_telemetry).pack(side=tk.LEFT, padx=5)
        
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
        
        self.message_history = scrolledtext.ScrolledText(history_frame, state=tk.DISABLED)
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
        
        ttk.Label(sections_frame, text="Configuration Sections", 
                 font=("TkDefaultFont", 10, "bold")).pack(pady=5)
        
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
        details_frame = ttk.LabelFrame(main_content_frame, text="Configuration Details")
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
        self.notebook.add(monitor_frame, text="Monitor")
        
        # Activity console
        console_frame = ttk.LabelFrame(monitor_frame, text="TX/RX Activity Console")
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.monitor_console = scrolledtext.ScrolledText(
            console_frame, 
            state=tk.DISABLED, 
            wrap=tk.WORD,
            bg='black',
            fg='green',
            font=('Courier', 9)
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
        
        ttk.Button(input_frame, text="Execute", 
                  command=self.execute_cli_command).pack(side=tk.LEFT, padx=5)
        
        # Export button
        export_frame = ttk.Frame(cli_frame)
        export_frame.pack(fill=tk.X, padx=5, pady=2)
        
        ttk.Button(export_frame, text="Export Console History", 
                  command=self.export_console_history).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Clear Console", 
                  command=self.clear_console).pack(side=tk.LEFT, padx=5)
        
        # Initialize monitor data
        self.monitor_data = []
        
        # Log initial message
        self.add_monitor_message("Monitor console initialized", "SYSTEM")
    
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
        pub.subscribe(self.on_receive, "meshtastic.receive")
        pub.subscribe(self.on_connection, "meshtastic.connection")
        pub.subscribe(self.on_connection, "meshtastic.connection.established") 
        pub.subscribe(self.on_node_updated, "meshtastic.node.updated")
        
        # Subscribe to all packet types for monitor console
        pub.subscribe(self.on_packet_monitor, "meshtastic.receive")
        pub.subscribe(self.on_packet_monitor, "meshtastic.send")
        
        # Also subscribe to specific protocol handlers if needed
        try:
            pub.subscribe(self.on_receive, "meshtastic.receive.text")
            pub.subscribe(self.on_receive, "meshtastic.receive.data.TEXT_MESSAGE_APP")
            pub.subscribe(self.on_packet_monitor, "meshtastic.receive.position")
            pub.subscribe(self.on_packet_monitor, "meshtastic.receive.telemetry")
        except:
            # These might not exist in all versions
            pass
        
        print("PubSub subscriptions set up")  # Debug
        self.add_monitor_message("PubSub subscriptions initialized", "SYSTEM")
    
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
            decoded = packet.get('decoded')
            if decoded:
                portnum = decoded.get('portnum')
                print(f"Portnum: {portnum}")  # Debug print
                
                # Check for text messages using both string and enum comparison
                if (portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP or 
                    portnum == 'TEXT_MESSAGE_APP' or
                    str(portnum) == str(portnums_pb2.PortNum.TEXT_MESSAGE_APP)):
                    
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
                    
                    from_id = packet.get('from')
                    to_id = packet.get('to')
                    
                    if text:
                        print(f"Received text message from {from_id}: {text}")  # Debug print
                        
                        # Get sender name if available
                        sender_name = self.get_node_display_name(from_id)
                        
                        # Add to message history
                        timestamp = time.strftime('%H:%M:%S')
                        msg_text = f"[{timestamp}] From {sender_name} ({from_id}): {text}\n"
                        
                        self.root.after(0, lambda t=msg_text, f=from_id: self.add_message_to_history(t, f))
                        
                        # Add to monitor console
                        self.root.after(0, lambda: self.add_monitor_message(f"RX: {text} from {sender_name} ({from_id})", "RX"))
                        
                        # Also show a notification in status bar
                        self.root.after(0, lambda s=sender_name: self.update_status(f"Message received from {s}"))
                    else:
                        print(f"Text message packet but no text found: {decoded}")
                else:
                    print(f"Non-text message received, portnum: {portnum}")  # Debug print
            else:
                print("Packet has no decoded data")  # Debug print
                
        except Exception as e:
            logging.error(f"Error processing received packet: {e}")
            print(f"Exception in on_receive: {e}")  # Debug print
            import traceback
            traceback.print_exc()
    
    def on_packet_monitor(self, packet, interface):
        """Handle all packets for monitor console"""
        try:
            # Simple direction detection based on packet structure
            direction = "RX"
            
            # Extract basic packet info
            from_id = getattr(packet, 'fromId', getattr(packet, 'from', 'Unknown'))
            to_id = getattr(packet, 'toId', getattr(packet, 'to', 'Unknown'))
            packet_id = getattr(packet, 'id', 'N/A')
            
            # Get packet type/portnum
            decoded = getattr(packet, 'decoded', None)
            if decoded:
                portnum = getattr(decoded, 'portnum', 'Unknown')
                payload_info = f"portnum={portnum}"
                
                # Add payload details if available
                if hasattr(decoded, 'payload'):
                    payload_size = len(decoded.payload) if decoded.payload else 0
                    payload_info += f", size={payload_size}B"
            else:
                payload_info = "encrypted/unknown"
            
            # Format monitor message
            msg = f"Packet ID:{packet_id} {from_id}→{to_id} ({payload_info})"
            self.root.after(0, lambda: self.add_monitor_message(msg, direction))
            
        except Exception as e:
            print(f"Error in packet monitor: {e}")
    
    def on_connection(self, interface, topic):
        """Handle connection events"""
        self.root.after(0, self.update_connection_status)
    
    def on_node_updated(self, node, interface=None):
        """Handle node updates"""
        self.root.after(0, self.refresh_nodes)
    
    def add_message_to_history(self, message, node_id=None):
        """Add message to history display and active chats"""
        # Add to active chats if node_id is provided
        if node_id:
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
                            info += f"Battery Level: {device_metrics['batteryLevel']}%\n"
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
                    if position:
                        info += f"\n=== Position ===\n"
                        if 'latitude' in position:
                            info += f"Latitude: {position['latitude']:.6f}\n"
                        if 'longitude' in position:
                            info += f"Longitude: {position['longitude']:.6f}\n"
                        if 'altitude' in position:
                            info += f"Altitude: {position['altitude']}m\n"
                        if 'satsInView' in position:
                            info += f"Satellites in View: {position['satsInView']}\n"
                    
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
            
            for node_id, node in nodes.items():
                user = node.get('user', {})
                name = user.get('longName', 'Unknown')
                short_name = user.get('shortName', '')
                
                # Format battery level
                battery_level = node.get('deviceMetrics', {}).get('batteryLevel', '')
                if battery_level == '' or battery_level is None:
                    battery_display = 'not available'
                else:
                    battery_display = f"{battery_level}%"
                
                # Add to tree
                self.nodes_tree.insert('', 'end', 
                    text=short_name or name,
                    values=(
                        node_id,
                        name,
                        node.get('position', {}).get('distance', ''),
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
                    return float(val) if val and val != "" else float('inf')
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
            self.add_monitor_message(f"TX: {message} to {dest_name} ({dest})", "TX")
            
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
        
        if not values:
            messagebox.showwarning("Warning", "Invalid node selection")
            return
        
        node_id = values[0]  # ID is the first value
        node_name = values[1] if len(values) > 1 else "Unknown"  # Name is the second value
        
        try:
            # Send ping message
            self.interface.sendText("ping", node_id)
            
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
        
        if not values:
            messagebox.showwarning("Warning", "Invalid node selection")
            return
        
        node_id = values[0]  # ID is the first value
        node_name = values[1] if len(values) > 1 else "Unknown"  # Name is the second value
        
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
                # Store traceroute responses
                traceroute_responses = []
                traceroute_complete = threading.Event()
                
                def on_traceroute_response(packet, interface):
                    """Handle traceroute response packets"""
                    try:
                        decoded = packet.get('decoded')
                        if decoded and decoded.get('portnum') == portnums_pb2.PortNum.TRACEROUTE_APP:
                            route_data = decoded.get('routeDiscovery', {})
                            route = route_data.get('route', [])
                            
                            # Process route information
                            for hop_num, hop_id in enumerate(route, 1):
                                hop_name = self.get_node_display_name(hop_id)
                                traceroute_responses.append({
                                    'hop': hop_num,
                                    'node_id': hop_id,
                                    'node_name': hop_name,
                                    'snr': route_data.get('snr', 0) if hop_num == len(route) else 0
                                })
                            
                            traceroute_complete.set()
                    except Exception as e:
                        print(f"Error processing traceroute response: {e}")
                
                # Subscribe to traceroute responses
                pub.subscribe(on_traceroute_response, "meshtastic.receive")
                
                # Send the actual traceroute request
                try:
                    print(f"Sending traceroute to {node_id}")
                    # Convert hex node_id to decimal
                    dest_id = int(node_id.replace('!', ''), 16)
                    self.interface.sendTraceRoute(dest_id)
                except Exception as e:
                    print(f"Error sending traceroute: {e}")
                    raise e
                
                # Wait for response with timeout
                if traceroute_complete.wait(timeout=30):  # 30 second timeout
                    # Generate report from real data
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    traceroute_report = f"""Traceroute Report
Generated: {timestamp}
Target: {node_name} ({node_id})

"""
                    
                    if traceroute_responses:
                        for hop_data in traceroute_responses:
                            snr_text = f" (SNR: {hop_data['snr']})" if hop_data['snr'] else ""
                            traceroute_report += f"Hop {hop_data['hop']}: {hop_data['node_id']} ({hop_data['node_name']}){snr_text}\n"
                        
                        traceroute_report += f"\nTraceroute completed successfully.\n"
                        traceroute_report += f"Total hops: {len(traceroute_responses)}\n"
                    else:
                        traceroute_report += "No route data received.\n"
                        
                else:
                    # Timeout
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    traceroute_report = f"""Traceroute Report
Generated: {timestamp}
Target: {node_name} ({node_id})

Traceroute timed out after 30 seconds.
No response received from target node.
"""
                
                # Unsubscribe from traceroute responses
                pub.unsubscribe(on_traceroute_response, "meshtastic.receive")
                
                # Close progress window and show results
                self.root.after(0, lambda: self.show_traceroute_results(progress_window, traceroute_report, node_name, node_id))
                
            except Exception as e:
                pub.unsubscribe(on_traceroute_response, "meshtastic.receive")
                self.root.after(0, lambda: self.show_traceroute_error(progress_window, str(e)))
        
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
                initialname=f"traceroute_{node_name}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
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
        
        if not values:
            messagebox.showwarning("Warning", "Invalid node selection")
            return
        
        node_id = values[0]  # ID is the first value
        node_name = values[1] if len(values) > 1 else "Unknown"  # Name is the second value
        
        # Switch to Messages tab
        self.notebook.select(2)  # Messages tab is index 2 (0: Connection, 1: Nodes, 2: Messages, 3: Config)
        
        # Set the selected node as destination (find the formatted entry)
        for dest_option in self.dest_combo['values']:
            if dest_option.startswith(node_id + " - "):
                self.dest_var.set(dest_option)
                break
        else:
            # Fallback to just the node ID if formatted version not found
            self.dest_var.set(node_id)
        
        # Focus on message entry
        self.message_entry.focus_set()
    
    def request_position(self):
        """Request position from selected node"""
        # Implementation would go here
        messagebox.showinfo("Info", "Position request feature not yet implemented")
    
    def request_telemetry(self):
        """Request telemetry from selected node"""
        # Implementation would go here
        messagebox.showinfo("Info", "Telemetry request feature not yet implemented")
    
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
            
            # Create title
            title_label = ttk.Label(self.config_fields_frame, text=f"{config_type.title()} Configuration", 
                                   font=("TkDefaultFont", 12, "bold"))
            title_label.pack(pady=(0, 10))
            
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
            for widget_key, widget_info in self.config_widgets.items():
                if widget_key.startswith(f"{config_type}."):
                    field_name = widget_key.split('.', 1)[1]
                    field = widget_info['field']
                    widget = widget_info['widget']
                    
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
            
            if changes_made:
                # Write configuration to device
                print(f"Writing {config_type} configuration to device...")
                node.writeConfig(config_type)
                messagebox.showinfo("Success", f"Configuration saved to device!\nChanges written to {config_type} section.")
                
                # Refresh the display
                self.load_config_section(config_type)
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
                    battery = device_metrics['batteryLevel']
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
        """Clear search entry and show all nodes"""
        self.search_entry.delete(0, tk.END)
        
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
            node_name = "Unknown"
            try:
                if self.interface and self.interface.nodes and node_id in self.interface.nodes:
                    node_info = self.interface.nodes[node_id]
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
            if self.interface and self.interface.nodes and node_id in self.interface.nodes:
                node_info = self.interface.nodes[node_id]
                user = node_info.get('user', {})
                return user.get('longName', f'Node {node_id}')
        except:
            pass
        
        return f"Node {node_id}"
    
    def load_message_history_from_device(self):
        """Load previous message history from connected device"""
        if not self.interface:
            return
        
        try:
            # This is a placeholder implementation
            # In a real implementation, you would:
            # 1. Query the device for stored messages
            # 2. Parse the message log
            # 3. Populate the active chats with historical messages
            
            # For now, we'll just log that this feature would be implemented
            logging.info("Message history loading from device - feature placeholder")
            
            # Example of how this might work:
            # messages = self.interface.getMessageHistory()  # hypothetical method
            # for msg in messages:
            #     timestamp = msg.get('timestamp', '')
            #     from_id = msg.get('from', '')
            #     text = msg.get('text', '')
            #     formatted_msg = f"[{timestamp}] From {from_id}: {text}\n"
            #     self.add_to_active_chats(from_id, formatted_msg)
            
        except Exception as e:
            logging.error(f"Error loading message history from device: {e}")
    
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
            initialname=f"monitor_log_{time.strftime('%Y%m%d_%H%M%S')}.txt"
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
    
    def clear_console(self):
        """Clear the monitor console"""
        self.monitor_console.config(state=tk.NORMAL)
        self.monitor_console.delete('1.0', tk.END)
        self.monitor_console.config(state=tk.DISABLED)
        self.monitor_data.clear()
        self.add_monitor_message("Console cleared", "SYSTEM")
    
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
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


def main():
    """Main entry point for the GUI"""
    app = MeshtasticGUI()
    app.run()


if __name__ == "__main__":
    main()