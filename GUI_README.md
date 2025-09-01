# Meshtastic GUI

A graphical user interface for the Meshtastic Python library, providing an easy-to-use interface for connecting to Meshtastic devices, viewing mesh networks, sending messages, and managing device configuration.

## Features

### Device Connection
- **Multiple connection methods**: Serial/USB, Bluetooth LE, and TCP/IP
- **Device discovery**: Scan for BLE devices
- **Connection management**: Easy connect/disconnect with status indicators
- **Device information**: View connected device details

### Mesh Network Management
- **Node visualization**: View all nodes in the mesh network in a tree view
- **Node details**: Display node ID, name, distance, SNR, and battery level
- **Network monitoring**: Real-time updates of node information
- **Node actions**: Request position and telemetry from specific nodes

### Messaging
- **Send messages**: Send text messages to specific nodes or broadcast to all
- **Message history**: View sent and received messages with timestamps
- **Channel selection**: Choose which channel to send messages on
- **Real-time updates**: See incoming messages as they arrive

### Configuration Management
- **Device configuration**: View and modify device settings
- **YAML export/import**: Export device configuration to YAML files
- **Configuration sections**: Organized view of different configuration areas
- **Backup and restore**: Save and load device configurations

## Installation

### Prerequisites
- Python 3.9 or higher
- Poetry (for development) or pip (for regular installation)

### Using Poetry (Recommended for Development)
```bash
# Install dependencies
poetry install

# Run the GUI
poetry run meshtastic-gui
```

### Using Pip
```bash
# Install the package
pip install -e .

# Run the GUI
meshtastic-gui
```

### Manual Launch
You can also run the GUI directly:
```bash
# From the project root directory
python -m meshtastic.gui

# Or using the launcher script
./meshtastic-gui
```

## Usage

### Connecting to a Device

1. **Launch the GUI**: Run `meshtastic-gui` from your terminal
2. **Choose connection method**: Select from Serial/USB, Bluetooth LE, or TCP/IP
3. **Configure connection**: 
   - **Serial**: Enter device path (e.g., `/dev/ttyUSB0`) or leave blank for auto-detection
   - **BLE**: Click "Scan BLE Devices" to find nearby devices, then enter device name/address
   - **TCP**: Enter hostname or IP address (default: `localhost`)
4. **Connect**: Click the "Connect" button

### Viewing Mesh Nodes

1. Go to the **"Mesh Nodes"** tab
2. Once connected, the GUI will automatically populate the node list
3. Click **"Refresh Nodes"** to update the list
4. Select a node to view its details
5. Use **"Request Position"** or **"Request Telemetry"** for specific node information

### Sending Messages

1. Go to the **"Messages"** tab
2. Select the destination:
   - Choose a specific node from the dropdown
   - Use `^all` for broadcast to all nodes
3. Select the channel (0-7, where 0 is the primary channel)
4. Type your message and press Enter or click **"Send"**
5. View message history in the scrollable area above

### Managing Configuration

1. Go to the **"Configuration"** tab
2. Select a configuration section from the left panel
3. View current configuration in the main area
4. Use the buttons to:
   - **Load Config**: Retrieve current device configuration
   - **Save Config**: Apply changes to the device
   - **Export YAML**: Save configuration to a file
   - **Import YAML**: Load configuration from a file

## GUI Components

### Connection Tab
- Connection method selection (Serial/BLE/TCP)
- Connection parameters input
- Device scanning and connection controls
- Device information display

### Mesh Nodes Tab
- Tree view of all mesh nodes
- Node details (ID, name, distance, SNR, battery)
- Node action buttons
- Real-time node updates

### Messages Tab
- Message history display
- Message composition area
- Destination and channel selection
- Send controls

### Configuration Tab
- Configuration sections list
- Configuration details view
- Export/import controls
- Configuration management tools

### Status Bar
- Connection status text
- Visual connection indicator (red/green)
- Current operation status

## Technical Details

### Architecture
- Built with Python's tkinter for cross-platform compatibility
- Uses the existing Meshtastic library interfaces
- Implements PubSub pattern for real-time updates
- Threaded connection management to prevent GUI blocking

### Supported Connection Types
- **SerialInterface**: USB/serial connections
- **BLEInterface**: Bluetooth Low Energy connections
- **TCPInterface**: Network connections via TCP/IP

### Event Handling
The GUI subscribes to Meshtastic library events:
- `meshtastic.receive`: Incoming message packets
- `meshtastic.connection`: Connection state changes
- `meshtastic.node.updated`: Node information updates

## Troubleshooting

### Connection Issues
- **Serial not found**: Check device path and permissions (Linux: add user to `dialout` group)
- **BLE scan fails**: Ensure Bluetooth is enabled and device is in pairing mode
- **TCP connection fails**: Verify the target device is running and accessible

### GUI Performance
- Large mesh networks may cause slower updates
- Message history is kept in memory - restart if it becomes too large
- Configuration loading may take time for complex setups

### Platform-Specific Notes
- **Linux**: May require additional permissions for serial and BLE access
- **macOS**: BLE functionality requires proper Bluetooth permissions
- **Windows**: Serial port names are typically `COM1`, `COM2`, etc.

## Development

### Code Structure
- `meshtastic/gui.py`: Main GUI application
- `meshtastic-gui`: Command-line launcher script
- Integration with existing Meshtastic library interfaces

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes to `meshtastic/gui.py`
4. Test with various connection types
5. Submit a pull request

### Future Enhancements
- Network topology visualization
- Advanced message filtering
- Plugin system for custom functionality
- Enhanced configuration editing
- Message encryption status indicators
- GPS coordinate mapping
- Firmware update management

## License

This GUI follows the same GPL-3.0 license as the main Meshtastic Python library.