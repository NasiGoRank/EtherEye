"""
Packet data models for EtherEye - Enhanced for database storage
SRS Compliance: FU-08, FU-09
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any
import json
import base64

@dataclass
class Packet:
    """Represents a single captured packet"""
    packet_number: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: str
    dst_port: str
    length: int
    raw_data: bytes
    layers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    def to_dict(self):
        """Convert packet to JSON-serializable dictionary"""
        serializable_layers = {}
        
        for layer_name, layer_data in self.layers.items():
            serializable_layer = {}
            for key, value in layer_data.items():
                # Convert any non-serializable objects
                if isinstance(value, (datetime, bytes)):
                    serializable_layer[key] = str(value)
                elif hasattr(value, '__dict__'):  # Complex object
                    serializable_layer[key] = str(value)
                else:
                    serializable_layer[key] = value
            serializable_layers[layer_name] = serializable_layer
        
        return {
            'packet_number': self.packet_number,
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'length': self.length,
            'raw_data': base64.b64encode(self.raw_data).decode('ascii') if self.raw_data else None,
            'layers': serializable_layers
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Packet':
        """Create Packet from dictionary"""
        raw_data_encoded = data.get('raw_data')
        raw_data = base64.b64decode(raw_data_encoded) if raw_data_encoded else b''
        
        return cls(
            packet_number=data['packet_number'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            src_ip=data['src_ip'],
            dst_ip=data['dst_ip'],
            protocol=data['protocol'],
            src_port=data['src_port'],
            dst_port=data['dst_port'],
            length=data['length'],
            raw_data=raw_data,
            layers=data['layers']
        )

@dataclass
class CaptureSession:
    """Represents a complete capture session (SRS FU-08)"""
    session_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    interface: str = ""
    filter_string: str = ""
    packet_count: int = 0
    total_bytes: int = 0
    packets: List[Packet] = field(default_factory=list)
    
    def add_packet(self, packet: Packet):
        """Add packet to session"""
        self.packets.append(packet)
        self.packet_count = len(self.packets)
        self.total_bytes += packet.length
    
    def get_stats(self) -> Dict[str, int]:
        """Get statistics for this session"""
        stats = {}
        for packet in self.packets:
            stats[packet.protocol] = stats.get(packet.protocol, 0) + 1
        return stats
    
    def to_dict(self) -> Dict:
        """Convert session to dictionary for storage"""
        return {
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "interface": self.interface,
            "filter": self.filter_string,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "packets": [packet.to_dict() for packet in self.packets],
            "protocol_stats": self.get_stats()
        }
    
    def to_json(self) -> str:
        """Convert session to JSON string"""
        return json.dumps(self.to_dict(), indent=2, default=str)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'CaptureSession':
        """Create CaptureSession from dictionary"""
        session = cls(
            session_id=data['session_id'],
            start_time=datetime.fromisoformat(data['start_time']),
            end_time=datetime.fromisoformat(data['end_time']) if data['end_time'] else None,
            interface=data['interface'],
            filter_string=data['filter'],
            packet_count=data['packet_count'],
            total_bytes=data.get('total_bytes', 0)
        )
        
        # Reconstruct packets
        for packet_data in data.get('packets', []):
            session.packets.append(Packet.from_dict(packet_data))
        
        return session
    
    @classmethod
    def from_json(cls, json_str: str) -> 'CaptureSession':
        """Create CaptureSession from JSON string"""
        return cls.from_dict(json.loads(json_str))