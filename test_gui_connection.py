#!/usr/bin/env python3
"""Test script to debug GUI connection issues"""

import sys
import time
import threading
sys.path.insert(0, '.')

from meshtastic.serial_interface import SerialInterface

def test_threaded_connection():
    """Test connection in a thread like the GUI does"""
    
    result = {"interface": None, "error": None, "completed": False}
    
    def connect_worker():
        try:
            print("Worker thread: Starting connection...")
            interface = SerialInterface('/dev/ttyACM0')
            print("Worker thread: Interface created")
            time.sleep(2)
            print("Worker thread: Sleep completed")
            
            result["interface"] = interface
            result["completed"] = True
            print("Worker thread: Connection successful")
            
        except Exception as e:
            result["error"] = str(e)
            result["completed"] = True
            print(f"Worker thread: Connection failed: {e}")
    
    print("Main thread: Starting worker thread...")
    thread = threading.Thread(target=connect_worker, daemon=True)
    thread.start()
    
    # Wait for completion with timeout
    timeout = 10
    start_time = time.time()
    
    while not result["completed"] and (time.time() - start_time) < timeout:
        print(f"Main thread: Waiting... ({time.time() - start_time:.1f}s)")
        time.sleep(0.5)
    
    if result["completed"]:
        if result["interface"]:
            print("SUCCESS: Connection established in thread")
            result["interface"].close()
        else:
            print(f"FAILED: {result['error']}")
    else:
        print("TIMEOUT: Connection did not complete")
    
    return result["completed"] and result["interface"] is not None

if __name__ == "__main__":
    print("Testing threaded connection like GUI does...")
    success = test_threaded_connection()
    print(f"Test result: {'PASS' if success else 'FAIL'}")