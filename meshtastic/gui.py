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
        
        # GUI state
        self.is_connected = False
        self.selected_node = None
        
        # Create main layout
        self.create_widgets()
        self.setup_pubsub()
        
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
        
        # Status bar
        self.create_status_bar()
        
    def create_connection_tab(self):
        """Create the device connection tab"""
        conn_frame = ttk.Frame(self.notebook)
        self.notebook.add(conn_frame, text="Connection")
        
        # Connection method selection
        method_frame = ttk.LabelFrame(conn_frame, text="Connection Method")
        method_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.conn_method = tk.StringVar(value="serial")
        ttk.Radiobutton(method_frame, text="Serial/USB", variable=self.conn_method, 
                       value="serial").grid(row=0, column=0, sticky=tk.W, padx=5)
        ttk.Radiobutton(method_frame, text="Bluetooth LE", variable=self.conn_method, 
                       value="ble").grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Radiobutton(method_frame, text="TCP/IP", variable=self.conn_method, 
                       value="tcp").grid(row=0, column=2, sticky=tk.W, padx=5)
        
        # Connection parameters
        params_frame = ttk.LabelFrame(conn_frame, text="Connection Parameters")
        params_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(params_frame, text="Serial Port:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.serial_port = ttk.Entry(params_frame, width=20)
        self.serial_port.grid(row=0, column=1, padx=5, pady=2)
        self.serial_port.insert(0, "/dev/ttyACM0")
        
        ttk.Label(params_frame, text="BLE Device:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.ble_device = ttk.Entry(params_frame, width=20)
        self.ble_device.grid(row=1, column=1, padx=5, pady=2)
        
        ttk.Label(params_frame, text="TCP Host:").grid(row=2, column=0, sticky=tk.W, padx=5)
        self.tcp_host = ttk.Entry(params_frame, width=20)
        self.tcp_host.grid(row=2, column=1, padx=5, pady=2)
        self.tcp_host.insert(0, "localhost")
        
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
        
        # Nodes list
        list_frame = ttk.LabelFrame(nodes_frame, text="Network Nodes")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Treeview for nodes
        self.nodes_tree = ttk.Treeview(list_frame, columns=("id", "name", "distance", "snr", "battery"), 
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
        
        self.nodes_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.nodes_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.nodes_tree.configure(yscrollcommand=scrollbar.set)
        
        # Node actions
        actions_frame = ttk.Frame(nodes_frame)
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(actions_frame, text="Refresh Nodes", 
                  command=self.refresh_nodes).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Request Position", 
                  command=self.request_position).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Request Telemetry", 
                  command=self.request_telemetry).pack(side=tk.LEFT, padx=5)
        
    def create_messages_tab(self):
        """Create the messaging tab"""
        msg_frame = ttk.Frame(self.notebook)
        self.notebook.add(msg_frame, text="Messages")
        
        # Message history
        history_frame = ttk.LabelFrame(msg_frame, text="Message History")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.message_history = scrolledtext.ScrolledText(history_frame, state=tk.DISABLED)
        self.message_history.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Message composition
        compose_frame = ttk.LabelFrame(msg_frame, text="Send Message")
        compose_frame.pack(fill=tk.X, padx=10, pady=5)
        
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
        
        # Configuration sections
        sections_frame = ttk.Frame(config_frame)
        sections_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=5)
        
        ttk.Label(sections_frame, text="Configuration Sections", 
                 font=("TkDefaultFont", 10, "bold")).pack(pady=5)
        
        self.config_sections = tk.Listbox(sections_frame, width=20)
        self.config_sections.pack(fill=tk.Y, expand=True)
        
        # Add common config sections
        config_items = ["Device", "LoRa", "Position", "Power", "Network", "Bluetooth", "Display"]
        for item in config_items:
            self.config_sections.insert(tk.END, item)
        
        # Configuration details
        details_frame = ttk.LabelFrame(config_frame, text="Configuration Details")
        details_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Configuration display/edit area
        self.config_text = scrolledtext.ScrolledText(details_frame)
        self.config_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configuration buttons
        config_btn_frame = ttk.Frame(details_frame)
        config_btn_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(config_btn_frame, text="Load Config", 
                  command=self.load_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(config_btn_frame, text="Save Config", 
                  command=self.save_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(config_btn_frame, text="Export YAML", 
                  command=self.export_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(config_btn_frame, text="Import YAML", 
                  command=self.import_config).pack(side=tk.LEFT, padx=5)
        
    def create_status_bar(self):
        """Create the status bar"""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(self.status_bar, text="Not connected")
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Connection indicator
        self.conn_indicator = tk.Canvas(self.status_bar, width=20, height=20)
        self.conn_indicator.pack(side=tk.RIGHT, padx=10, pady=5)
        self.conn_indicator.create_oval(5, 5, 15, 15, fill="red", tags="indicator")
        
    def setup_pubsub(self):
        """Setup PubSub event handlers"""
        pub.subscribe(self.on_receive, "meshtastic.receive")
        pub.subscribe(self.on_connection, "meshtastic.connection")
        pub.subscribe(self.on_node_updated, "meshtastic.node.updated")
        
    def on_receive(self, packet, interface):
        """Handle incoming packets"""
        try:
            decoded = packet.get('decoded')
            if decoded:
                portnum = decoded.get('portnum')
                if portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
                    text = decoded.get('text', '')
                    from_id = packet.get('from')
                    to_id = packet.get('to')
                    
                    # Add to message history
                    timestamp = time.strftime('%H:%M:%S')
                    msg_text = f"[{timestamp}] From {from_id}: {text}\n"
                    
                    self.root.after(0, self.add_message_to_history, msg_text)
        except Exception as e:
            logging.error(f"Error processing received packet: {e}")
    
    def on_connection(self, interface, topic):
        """Handle connection events"""
        self.root.after(0, self.update_connection_status)
    
    def on_node_updated(self, node):
        """Handle node updates"""
        self.root.after(0, self.refresh_nodes)
    
    def add_message_to_history(self, message):
        """Add message to history display"""
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
            # Update combo box or show selection dialog
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
                
                # Create interface
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
            info = f"Device: {self.interface.__class__.__name__}\n"
            if hasattr(self.interface, 'devPath') and self.interface.devPath:
                info += f"Path: {self.interface.devPath}\n"
            
            # Get device info
            try:
                my_info = self.interface.getMyNodeInfo()
                if my_info:
                    info += f"Node ID: {my_info.get('num', 'Unknown')}\n"
                    info += f"User: {my_info.get('user', {}).get('longName', 'Unknown')}\n"
            except Exception as e:
                info += f"Error getting device info: {e}\n"
            
            self.device_info.delete('1.0', tk.END)
            self.device_info.insert('1.0', info)
        
        # Refresh nodes and update destination combo
        self.refresh_nodes()
    
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
    
    def refresh_nodes(self):
        """Refresh the nodes list"""
        if not self.interface:
            return
        
        # Clear existing nodes
        for item in self.nodes_tree.get_children():
            self.nodes_tree.delete(item)
        
        # Update destination combo options
        destinations = [BROADCAST_ADDR]
        
        try:
            nodes = self.interface.nodes
            for node_id, node in nodes.items():
                user = node.get('user', {})
                name = user.get('longName', 'Unknown')
                short_name = user.get('shortName', '')
                
                # Add to tree
                self.nodes_tree.insert('', 'end', 
                    text=short_name or name,
                    values=(
                        node_id,
                        name,
                        node.get('position', {}).get('distance', ''),
                        node.get('snr', ''),
                        f"{node.get('deviceMetrics', {}).get('batteryLevel', '')}%"
                    ))
                
                destinations.append(f"{node_id}")
            
            # Update destination combo
            self.dest_combo['values'] = destinations
            if not self.dest_var.get():
                self.dest_var.set(BROADCAST_ADDR)
                
        except Exception as e:
            logging.error(f"Error refreshing nodes: {e}")
    
    def send_message(self, event=None):
        """Send a text message"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        dest = self.dest_var.get()
        channel = int(self.channel_var.get())
        message = self.message_entry.get().strip()
        
        if not message:
            return
        
        try:
            self.interface.sendText(message, dest, channelIndex=channel)
            
            # Add to message history
            timestamp = time.strftime('%H:%M:%S')
            msg_text = f"[{timestamp}] To {dest}: {message}\n"
            self.add_message_to_history(msg_text)
            
            # Clear message entry
            self.message_entry.delete(0, tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send message: {e}")
    
    def request_position(self):
        """Request position from selected node"""
        # Implementation would go here
        messagebox.showinfo("Info", "Position request feature not yet implemented")
    
    def request_telemetry(self):
        """Request telemetry from selected node"""
        # Implementation would go here
        messagebox.showinfo("Info", "Telemetry request feature not yet implemented")
    
    def load_config(self):
        """Load device configuration"""
        if not self.interface:
            messagebox.showwarning("Warning", "Not connected to device")
            return
        
        try:
            # Get local config
            config = {}
            if hasattr(self.interface, 'localNode'):
                local_config = self.interface.localNode.localConfig
                module_config = self.interface.localNode.moduleConfig
                
                # Convert to dict for display
                config['localConfig'] = str(local_config)
                config['moduleConfig'] = str(module_config)
            
            config_text = json.dumps(config, indent=2)
            self.config_text.delete('1.0', tk.END)
            self.config_text.insert('1.0', config_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load config: {e}")
    
    def save_config(self):
        """Save configuration to device"""
        messagebox.showinfo("Info", "Save config feature not yet implemented")
    
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
        else:
            self.update_status("Not connected")
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


def main():
    """Main entry point for the GUI"""
    app = MeshtasticGUI()
    app.run()


if __name__ == "__main__":
    main()