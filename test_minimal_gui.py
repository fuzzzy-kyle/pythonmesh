#!/usr/bin/env python3
"""Minimal GUI test to debug connection issues"""

import sys
import tkinter as tk
from tkinter import ttk
import threading
import time
sys.path.insert(0, '.')

from meshtastic.serial_interface import SerialInterface

class MinimalGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Minimal Connection Test")
        self.root.geometry("400x200")
        
        self.interface = None
        self.is_connected = False
        
        # Create UI
        self.status_label = tk.Label(self.root, text="Not connected")
        self.status_label.pack(pady=10)
        
        self.connect_btn = tk.Button(self.root, text="Connect", command=self.connect)
        self.connect_btn.pack(pady=5)
        
        self.disconnect_btn = tk.Button(self.root, text="Disconnect", command=self.disconnect, state=tk.DISABLED)
        self.disconnect_btn.pack(pady=5)
        
        # Progress indicator
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(pady=10, fill=tk.X, padx=20)
    
    def update_status(self, text):
        """Update status label"""
        self.status_label.config(text=text)
        print(f"Status: {text}")
    
    def connect(self):
        """Connect to device"""
        print("Connect button clicked")
        
        def connect_worker():
            print("Worker: Starting connection...")
            try:
                self.root.after(0, lambda: self.update_status("Creating interface..."))
                interface = SerialInterface('/dev/ttyACM0')
                print("Worker: Interface created")
                
                self.root.after(0, lambda: self.update_status("Waiting for connection..."))
                time.sleep(2)
                print("Worker: Wait completed")
                
                # Success callback
                self.root.after(0, lambda: self.on_connected(interface))
                
            except Exception as e:
                print(f"Worker: Error - {e}")
                self.root.after(0, lambda: self.on_error(str(e)))
        
        # Disable button and start progress
        self.connect_btn.config(state=tk.DISABLED)
        self.progress.start()
        self.update_status("Connecting...")
        
        # Start worker thread
        thread = threading.Thread(target=connect_worker, daemon=True)
        thread.start()
        print("Thread started")
    
    def on_connected(self, interface):
        """Handle successful connection"""
        print("on_connected called")
        self.interface = interface
        self.is_connected = True
        
        # Update UI
        self.progress.stop()
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)
        self.update_status("Connected!")
        
        print("Connection successful!")
    
    def on_error(self, error):
        """Handle connection error"""
        print(f"on_error called: {error}")
        
        # Update UI
        self.progress.stop()
        self.connect_btn.config(state=tk.NORMAL)
        self.update_status(f"Error: {error}")
    
    def disconnect(self):
        """Disconnect from device"""
        if self.interface:
            self.interface.close()
            self.interface = None
        
        self.is_connected = False
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.update_status("Disconnected")
    
    def run(self):
        """Start the GUI"""
        print("Starting minimal GUI...")
        self.root.mainloop()

if __name__ == "__main__":
    gui = MinimalGUI()
    gui.run()