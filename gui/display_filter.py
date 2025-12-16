"""
Display filter system for filtering already captured packets
"""

from typing import List, Callable
from models.packet_session import Packet

class DisplayFilter:
    """Filters packets for display (post-capture filtering)"""
    
    def __init__(self):
        self.current_filter = ""
        self.filter_func = None
    
    def set_filter(self, filter_str: str) -> bool:
        """
        Set display filter
        Returns: True if filter is valid, False otherwise
        """
        self.current_filter = filter_str.strip().lower()
        
        if not self.current_filter:
            self.filter_func = None
            return True
        
        try:
            self.filter_func = self._create_filter_func(self.current_filter)
            return True
        except Exception as e:
            print(f"Invalid display filter: {e}")
            self.filter_func = None
            return False
    
    def filter_packets(self, packets: List[Packet]) -> List[Packet]:
        """Filter packets using current filter"""
        if not self.filter_func or not packets:
            return packets
        
        return [packet for packet in packets if self.filter_func(packet)]
    
    def _create_filter_func(self, filter_str: str) -> Callable[[Packet], bool]:
        """Create a filter function from filter string"""
        # Simple keyword-based filtering for now
        # Can be enhanced to support more complex expressions
        
        def filter_func(packet: Packet) -> bool:
            # Check if filter string is in any of the packet fields
            fields_to_check = [
                packet.src_ip.lower(),
                packet.dst_ip.lower(),
                packet.protocol.lower(),
                packet.src_port.lower(),
                packet.dst_port.lower(),
                str(packet.length).lower(),
            ]
            
            # Also check layers
            for layer_name, layer_data in packet.layers.items():
                fields_to_check.append(layer_name.lower())
                for key, value in layer_data.items():
                    fields_to_check.append(str(value).lower())
            
            # Check if any field contains the filter string
            for field in fields_to_check:
                if filter_str in field:
                    return True
            
            return False
        
        return filter_func
    
    def get_filter_examples(self) -> List[tuple]:
        """Get display filter examples"""
        return [
            ("192.168.1.1", "Filter by IP address"),
            ("tcp", "Filter by protocol"),
            ("80", "Filter by port"),
            ("http", "Filter HTTP traffic"),
            ("443", "Filter HTTPS traffic"),
            ("syn", "Filter TCP SYN packets"),
            (">100", "Packets larger than 100 bytes"),
            ("<100", "Packets smaller than 100 bytes"),
        ]