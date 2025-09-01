"""Meshtastic Web GUI Application

A Dash-based web GUI for the Meshtastic Python library that provides
a user-friendly web interface for connecting to devices, viewing mesh nodes,
sending messages, and managing device configuration.
"""

import dash
from dash import dcc, html, Input, Output, State, callback, dash_table
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
import threading
import time
import logging
from typing import Optional, Dict, Any, List
import json
from datetime import datetime

from pubsub import pub

from . import BROADCAST_ADDR
from .ble_interface import BLEInterface
from .serial_interface import SerialInterface
from .tcp_interface import TCPInterface
from .mesh_interface import MeshInterface
from .protobuf import portnums_pb2


class MeshtasticWebGUI:
    """Web-based GUI application for Meshtastic"""
    
    def __init__(self):
        self.app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
        self.interface: Optional[MeshInterface] = None
        self.nodes: Dict[str, Any] = {}
        self.messages: List[Dict] = []
        self.connection_thread: Optional[threading.Thread] = None
        
        # GUI state
        self.is_connected = False
        
        # Setup layout and callbacks
        self.setup_layout()
        self.setup_callbacks()
        self.setup_pubsub()
        
        # Configure logging
        logging.basicConfig(level=logging.INFO)
    
    def setup_layout(self):
        """Create the main web layout"""
        
        self.app.layout = dbc.Container([
            # Header
            dbc.Row([
                dbc.Col([
                    html.H1("Meshtastic Web GUI", className="text-center mb-4"),
                    dbc.Alert(id="status-alert", color="secondary", children="Not connected", className="text-center")
                ])
            ]),
            
            # Main tabs
            dbc.Tabs(id="main-tabs", active_tab="connection", children=[
                dbc.Tab(label="Connection", tab_id="connection"),
                dbc.Tab(label="Mesh Nodes", tab_id="nodes"),  
                dbc.Tab(label="Messages", tab_id="messages"),
                dbc.Tab(label="Configuration", tab_id="config")
            ]),
            
            # Tab content
            html.Div(id="tab-content", className="mt-3"),
            
            # Auto-refresh component
            dcc.Interval(id="interval", interval=2000, n_intervals=0)
            
        ], fluid=True)
    
    def setup_callbacks(self):
        """Setup Dash callbacks"""
        
        @self.app.callback(
            Output("tab-content", "children"),
            [Input("main-tabs", "active_tab")]
        )
        def render_tab_content(active_tab):
            if active_tab == "connection":
                return self.connection_layout()
            elif active_tab == "nodes":
                return self.nodes_layout()
            elif active_tab == "messages":
                return self.messages_layout()
            elif active_tab == "config":
                return self.config_layout()
            return html.Div("Tab content not found")
        
        @self.app.callback(
            [Output("status-alert", "children"),
             Output("status-alert", "color")],
            [Input("interval", "n_intervals")]
        )
        def update_status(n):
            if self.is_connected:
                return "Connected", "success"
            return "Not connected", "secondary"
        
        @self.app.callback(
            Output("connection-result", "children"),
            [Input("connect-btn", "n_clicks")],
            [State("conn-method", "value"),
             State("serial-port", "value"),
             State("ble-device", "value"), 
             State("tcp-host", "value")]
        )
        def handle_connect(n_clicks, method, serial_port, ble_device, tcp_host):
            if n_clicks:
                return self.connect_device(method, serial_port, ble_device, tcp_host)
            return ""
    
    def connection_layout(self):
        """Create connection tab layout"""
        return [
            dbc.Card([
                dbc.CardBody([
                    html.H4("Connection Method"),
                    dcc.RadioItems(
                        id="conn-method",
                        options=[
                            {"label": "Serial/USB", "value": "serial"},
                            {"label": "Bluetooth LE", "value": "ble"},
                            {"label": "TCP/IP", "value": "tcp"}
                        ],
                        value="serial",
                        className="mb-3"
                    ),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Serial Port:"),
                            dbc.Input(id="serial-port", placeholder="/dev/ttyUSB0", value="/dev/ttyUSB0")
                        ], md=4),
                        dbc.Col([
                            dbc.Label("BLE Device:"),
                            dbc.Input(id="ble-device", placeholder="Device name or address")
                        ], md=4),
                        dbc.Col([
                            dbc.Label("TCP Host:"),
                            dbc.Input(id="tcp-host", placeholder="localhost", value="localhost")
                        ], md=4)
                    ], className="mb-3"),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Button("Connect", id="connect-btn", color="primary", className="me-2"),
                            dbc.Button("Disconnect", id="disconnect-btn", color="secondary")
                        ])
                    ]),
                    
                    html.Div(id="connection-result", className="mt-3")
                ])
            ])
        ]
    
    def nodes_layout(self):
        """Create nodes tab layout"""
        nodes_data = []
        if self.interface and hasattr(self.interface, 'nodes'):
            for node_id, node in self.interface.nodes.items():
                user = node.get('user', {})
                nodes_data.append({
                    'ID': node_id,
                    'Name': user.get('longName', 'Unknown'),
                    'Short': user.get('shortName', ''),
                    'SNR': node.get('snr', ''),
                    'Battery': f"{node.get('deviceMetrics', {}).get('batteryLevel', '')}%"
                })
        
        return [
            dbc.Card([
                dbc.CardBody([
                    html.H4("Mesh Network Nodes"),
                    dash_table.DataTable(
                        id="nodes-table",
                        data=nodes_data,
                        columns=[
                            {"name": "ID", "id": "ID"},
                            {"name": "Name", "id": "Name"},  
                            {"name": "Short", "id": "Short"},
                            {"name": "SNR", "id": "SNR"},
                            {"name": "Battery", "id": "Battery"}
                        ],
                        style_cell={'textAlign': 'left'},
                        style_header={'backgroundColor': 'rgb(230, 230, 230)', 'fontWeight': 'bold'}
                    ),
                    
                    html.Div([
                        dbc.Button("Refresh Nodes", id="refresh-nodes", color="info", className="me-2 mt-3"),
                        dbc.Button("Request Position", id="request-pos", color="warning", className="me-2 mt-3"),
                        dbc.Button("Request Telemetry", id="request-telem", color="warning", className="mt-3")
                    ])
                ])
            ])
        ]
    
    def messages_layout(self):
        """Create messages tab layout"""
        return [
            dbc.Card([
                dbc.CardBody([
                    html.H4("Message History"),
                    html.Div(
                        id="message-history",
                        style={
                            'height': '300px',
                            'overflow-y': 'scroll',
                            'border': '1px solid #ddd',
                            'padding': '10px',
                            'backgroundColor': '#f8f9fa'
                        },
                        children=[html.P(msg.get('text', ''), className="mb-1") for msg in self.messages[-20:]]
                    )
                ])
            ], className="mb-3"),
            
            dbc.Card([
                dbc.CardBody([
                    html.H4("Send Message"),
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("To:"),
                            dcc.Dropdown(
                                id="dest-dropdown",
                                options=[{"label": BROADCAST_ADDR, "value": BROADCAST_ADDR}],
                                value=BROADCAST_ADDR
                            )
                        ], md=4),
                        dbc.Col([
                            dbc.Label("Channel:"),
                            dcc.Dropdown(
                                id="channel-dropdown", 
                                options=[{"label": str(i), "value": i} for i in range(8)],
                                value=0
                            )
                        ], md=2)
                    ], className="mb-3"),
                    
                    dbc.Row([
                        dbc.Col([
                            dbc.Label("Message:"),
                            dbc.Input(id="message-input", type="text", placeholder="Enter your message...")
                        ], md=10),
                        dbc.Col([
                            dbc.Button("Send", id="send-btn", color="primary", className="mt-4")
                        ], md=2)
                    ])
                ])
            ])
        ]
    
    def config_layout(self):
        """Create configuration tab layout"""
        return [
            dbc.Card([
                dbc.CardBody([
                    html.H4("Device Configuration"),
                    dbc.Row([
                        dbc.Col([
                            html.H5("Configuration Sections"),
                            dbc.ListGroup([
                                dbc.ListGroupItem("Device", id="config-device"),
                                dbc.ListGroupItem("LoRa", id="config-lora"),
                                dbc.ListGroupItem("Position", id="config-position"),
                                dbc.ListGroupItem("Power", id="config-power"),
                                dbc.ListGroupItem("Network", id="config-network"),
                                dbc.ListGroupItem("Bluetooth", id="config-bluetooth")
                            ])
                        ], md=3),
                        dbc.Col([
                            html.H5("Configuration Details"),
                            dcc.Textarea(
                                id="config-text",
                                style={'width': '100%', 'height': '400px'},
                                placeholder="Configuration will appear here..."
                            ),
                            html.Div([
                                dbc.Button("Load Config", id="load-config", color="info", className="me-2 mt-3"),
                                dbc.Button("Export YAML", id="export-config", color="success", className="me-2 mt-3"),
                                dbc.Button("Import YAML", id="import-config", color="warning", className="mt-3")
                            ])
                        ], md=9)
                    ])
                ])
            ])
        ]
    
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
                    
                    timestamp = datetime.now().strftime('%H:%M:%S')
                    message = {
                        'timestamp': timestamp,
                        'from': from_id,
                        'text': f"[{timestamp}] From {from_id}: {text}"
                    }
                    self.messages.append(message)
                    
        except Exception as e:
            logging.error(f"Error processing received packet: {e}")
    
    def on_connection(self, interface, topic):
        """Handle connection events"""
        pass
    
    def on_node_updated(self, node):
        """Handle node updates"""
        pass
    
    def connect_device(self, method, serial_port, ble_device, tcp_host):
        """Connect to selected device"""
        try:
            if method == "serial":
                port = serial_port or None
                self.interface = SerialInterface(port)
            elif method == "ble":
                device = ble_device or None
                self.interface = BLEInterface(device)
            elif method == "tcp":
                host = tcp_host or "localhost"
                self.interface = TCPInterface(host)
            
            if self.interface:
                self.is_connected = True
                return dbc.Alert("Connected successfully!", color="success")
                
        except Exception as e:
            return dbc.Alert(f"Connection failed: {str(e)}", color="danger")
        
        return dbc.Alert("Connection failed", color="danger")
    
    def run(self, host="127.0.0.1", port=8050, debug=False):
        """Start the web GUI application"""
        print(f"Starting Meshtastic Web GUI at http://{host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)


def main():
    """Main entry point for the web GUI"""
    gui = MeshtasticWebGUI()
    gui.run(debug=True)


if __name__ == "__main__":
    main()