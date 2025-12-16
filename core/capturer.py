"""
Core packet capture engine using Scapy
SRS Compliance: Implements FU-01, FU-02, FU-03
"""

import threading
import time
from typing import List, Dict, Optional, Callable, Tuple
from datetime import datetime

import scapy.all as scapy
from scapy.all import get_if_list, get_if_addr, AsyncSniffer, conf

from models.packet_session import Packet
from core.filter_engine import FilterEngine

class CaptureEngine:
    """Main capture engine that interfaces with Scapy"""
    
    def __init__(self):
        self.sniffer: Optional[AsyncSniffer] = None
        self.capturing = False
        self.current_interface = None
        self.packet_callback = None
        self.capture_thread = None
        self.filter_engine = FilterEngine()
        
        # Configure Scapy
        conf.verb = 0  # Disable Scapy verbose mode
        conf.use_pcap = True  # Force libpcap usage
        
    # ===== SRS FU-01: Interface Enumeration =====
    def list_interfaces(self) -> List[Dict]:
        """Get list of all available network interfaces"""
        interfaces = []
        
        try:
            # Get interfaces using Scapy
            iface_list = get_if_list()
            
            for iface in iface_list:
                try:
                    ip_addr = get_if_addr(iface)
                    status = "ACTIVE" if ip_addr and ip_addr != "0.0.0.0" else "INACTIVE"
                    
                    interfaces.append({
                        'name': iface,
                        'ip': ip_addr if ip_addr and ip_addr != "0.0.0.0" else "No IP",
                        'status': status
                    })
                except Exception as e:
                    # If we can't get IP, still add the interface
                    interfaces.append({
                        'name': iface,
                        'ip': "Unknown",
                        'status': "UNKNOWN"
                    })
        except Exception as e:
            print(f"Error listing interfaces: {e}")
            # Fallback to common interface names
            fallback_ifaces = ['eth0', 'wlan0', 'lo', 'enp0s3']
            for iface in fallback_ifaces:
                interfaces.append({
                    'name': iface,
                    'ip': '127.0.0.1' if iface == 'lo' else 'Unknown',
                    'status': 'ACTIVE' if iface == 'lo' else 'UNKNOWN'
                })
        
        return interfaces
    
    # ===== SRS FU-02: Interface Selection =====
    def select_interface(self, interface_name: str) -> bool:
        """Select network interface for capture"""
        interfaces = self.list_interfaces()
        interface_names = [iface['name'] for iface in interfaces]
        
        if interface_name in interface_names:
            self.current_interface = interface_name
            return True
        return False
    
    # ===== SRS FU-03: Capture Control =====
    def start_capture(self, packet_callback: Callable, filter_str: str = "", 
                     count: int = 0) -> bool:
        """Start packet capture"""
        if not self.current_interface:
            print("No interface selected")
            return False
            
        if self.capturing:
            print("Already capturing")
            return False
            
        self.capturing = True
        self.packet_callback = packet_callback
        
        # Start capture in background thread
        self.capture_thread = threading.Thread(
            target=self._capture_worker,
            args=(filter_str, count),
            daemon=True
        )
        self.capture_thread.start()
        
        # Wait a bit for the thread to start
        time.sleep(0.1)
        
        return True
    
    def stop_capture(self):
        """Stop packet capture"""
        if self.sniffer and self.capturing:
            try:
                self.sniffer.stop()
                self.sniffer = None
            except:
                pass
            self.capturing = False
            time.sleep(0.1)  # Give time for cleanup
            
    def _capture_worker(self, filter_str: str, count: int):
        """Background worker for packet capture"""
        try:
            # Start the sniffer
            self.sniffer = AsyncSniffer(
                iface=self.current_interface,
                prn=self._packet_handler,
                count=count if count > 0 else 0,
                filter=filter_str if filter_str else None,
                store=False,
                quiet=True
            )
            self.sniffer.start()
            
            # Keep thread alive while capturing
            while self.capturing and self.sniffer:
                time.sleep(0.1)
                
        except Exception as e:
            print(f"Capture error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.capturing = False
    
    def _packet_handler(self, packet):
        """Handle each captured packet"""
        if self.packet_callback and packet:
            try:
                self.packet_callback(packet)
            except Exception as e:
                print(f"Error in packet handler: {e}")
    
    def is_capturing(self) -> bool:
        """Check if capture is active"""
        return self.capturing
    
    # Add a new method for filter parsing
    def parse_and_validate_filter(self, user_filter: str) -> Tuple[str, Optional[str]]:
        """
        Parse user filter and validate it
        Returns: (bpf_filter, error_message)
        """
        return self.filter_engine.parse_filter(user_filter)