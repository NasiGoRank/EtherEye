"""
Exporter for EtherEye
SRS Compliance: Implements FU-09 - Export Capture Results
Exports sessions to PCAP and CSV formats
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import struct

from models.packet_session import CaptureSession, Packet

class SessionExporter:
    """Handles export of capture sessions to various formats"""
    
    # PCAP file header constants
    PCAP_MAGIC_NUMBER = 0xA1B2C3D4
    PCAP_MAJOR_VERSION = 2
    PCAP_MINOR_VERSION = 4
    PCAP_SNAPLEN = 65535
    PCAP_NETWORK = 1  # LINKTYPE_ETHERNET
    
    def __init__(self):
        self.supported_formats = {
            'pcap': {
                'name': 'PCAP',
                'description': 'Wireshark/tcpdump compatible format',
                'extension': '.pcap'
            },
            'csv': {
                'name': 'CSV',
                'description': 'Comma-separated values for spreadsheet analysis',
                'extension': '.csv'
            },
            'json': {
                'name': 'JSON',
                'description': 'Structured JSON data',
                'extension': '.json'
            },
            'txt': {
                'name': 'Text',
                'description': 'Human-readable text format',
                'extension': '.txt'
            }
        }
    
    def export_session(self, session: CaptureSession, file_path: str, 
                      format: str = 'pcap', 
                      include_payload: bool = True) -> bool:
        """
        Export a session to specified format
        Returns: True if successful, False otherwise
        """
        format = format.lower()
        
        if format not in self.supported_formats:
            raise ValueError(f"Unsupported format: {format}. "
                           f"Supported: {list(self.supported_formats.keys())}")
        
        # Ensure file has correct extension
        if not file_path.endswith(self.supported_formats[format]['extension']):
            file_path += self.supported_formats[format]['extension']
        
        try:
            if format == 'pcap':
                return self._export_to_pcap(session, file_path)
            elif format == 'csv':
                return self._export_to_csv(session, file_path, include_payload)
            elif format == 'json':
                return self._export_to_json(session, file_path, include_payload)
            elif format == 'txt':
                return self._export_to_txt(session, file_path, include_payload)
            else:
                return False
                
        except Exception as e:
            print(f"Error exporting to {format}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _export_to_pcap(self, session: CaptureSession, file_path: str) -> bool:
        """
        Export session to PCAP format (SRS FU-09-01)
        Implements the PCAP file format specification
        """
        try:
            with open(file_path, 'wb') as f:
                # Write PCAP global header
                header = struct.pack(
                    '<I H H i I I I',
                    self.PCAP_MAGIC_NUMBER,
                    self.PCAP_MAJOR_VERSION,
                    self.PCAP_MINOR_VERSION,
                    0,  # timezone correction (always 0)
                    0,  # accuracy of timestamps (always 0)
                    self.PCAP_SNAPLEN,
                    self.PCAP_NETWORK
                )
                f.write(header)
                
                # Write each packet
                for packet in session.packets:
                    # Calculate timestamp in seconds and microseconds
                    timestamp = packet.timestamp.timestamp()
                    ts_sec = int(timestamp)
                    ts_usec = int((timestamp - ts_sec) * 1_000_000)
                    
                    # Packet header: ts_sec, ts_usec, incl_len, orig_len
                    packet_header = struct.pack(
                        '<I I I I',
                        ts_sec,
                        ts_usec,
                        len(packet.raw_data),
                        len(packet.raw_data)
                    )
                    f.write(packet_header)
                    
                    # Packet data
                    f.write(packet.raw_data)
            
            # Verify file was created and has content
            return Path(file_path).exists() and Path(file_path).stat().st_size > 0
            
        except Exception as e:
            print(f"PCAP export error: {e}")
            return False
    
    def _export_to_csv(self, session: CaptureSession, file_path: str, 
                      include_payload: bool = True) -> bool:
        """
        Export session to CSV format (SRS FU-09-02)
        Creates a spreadsheet-friendly format
        """
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                # Define CSV columns
                fieldnames = [
                    'No.', 'Timestamp', 'Source IP', 'Destination IP',
                    'Protocol', 'Source Port', 'Destination Port',
                    'Length (bytes)', 'TTL', 'Flags', 'Checksum', 'Info'
                ]
                
                if include_payload:
                    fieldnames.append('Payload Preview')
                    fieldnames.append('Payload Hex')
                
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for packet in session.packets:
                    row = {
                        'No.': packet.packet_number,
                        'Timestamp': packet.timestamp.isoformat(),
                        'Source IP': packet.src_ip,
                        'Destination IP': packet.dst_ip,
                        'Protocol': packet.protocol,
                        'Source Port': packet.src_port,
                        'Destination Port': packet.dst_port,
                        'Length (bytes)': packet.length,
                        'TTL': '',
                        'Flags': '',
                        'Checksum': '',
                        'Info': self._get_packet_info(packet)
                    }
                    
                    # Extract additional fields from layers
                    if 'IP' in packet.layers:
                        row['TTL'] = packet.layers['IP'].get('ttl', '')
                        row['Checksum'] = packet.layers['IP'].get('chksum', '')
                    
                    if 'TCP' in packet.layers:
                        row['Flags'] = packet.layers['TCP'].get('flags', '')
                        row['Checksum'] = packet.layers['TCP'].get('chksum', '')
                    elif 'UDP' in packet.layers:
                        row['Checksum'] = packet.layers['UDP'].get('chksum', '')
                    
                    if include_payload:
                        # Add payload preview (first 50 bytes as ASCII)
                        payload_preview = ''
                        if len(packet.raw_data) > 54:  # Ethernet + IP headers
                            try:
                                payload = packet.raw_data[54:]  # Skip headers
                                # Take printable ASCII characters only
                                payload_preview = ''.join(
                                    chr(b) if 32 <= b <= 126 else '.'
                                    for b in payload[:50]
                                )
                            except:
                                payload_preview = 'Binary data'
                        
                        row['Payload Preview'] = payload_preview
                        
                        # Add hex representation of payload
                        if len(packet.raw_data) > 54:
                            hex_data = packet.raw_data[54:74].hex()  # First 20 bytes
                            if len(packet.raw_data) > 74:
                                hex_data += '...'
                            row['Payload Hex'] = hex_data
                        else:
                            row['Payload Hex'] = ''
                    
                    writer.writerow(row)
            
            return True
            
        except Exception as e:
            print(f"CSV export error: {e}")
            return False
    
    def _export_to_json(self, session: CaptureSession, file_path: str,
                       include_payload: bool = True) -> bool:
        """Export session to JSON format"""
        try:
            # Use session's to_dict method which should handle serialization
            export_data = session.to_dict()
            
            # Optionally exclude raw payload data to reduce file size
            if not include_payload:
                for packet in export_data['packets']:
                    packet['raw_data'] = 'EXCLUDED'  # Replace with placeholder
            
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(export_data, jsonfile, indent=2, default=str, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"JSON export error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _export_to_txt(self, session: CaptureSession, file_path: str,
                      include_payload: bool = True) -> bool:
        """Export session to human-readable text format"""
        try:
            with open(file_path, 'w', encoding='utf-8') as txtfile:
                # Write session header
                txtfile.write(f"EtherEye Capture Session Export\n")
                txtfile.write(f"{'='*60}\n\n")
                
                txtfile.write(f"Session ID: {session.session_id}\n")
                txtfile.write(f"Start Time: {session.start_time}\n")
                txtfile.write(f"End Time: {session.end_time or 'N/A'}\n")
                txtfile.write(f"Interface: {session.interface}\n")
                txtfile.write(f"Filter: {session.filter_string or 'None'}\n")
                txtfile.write(f"Total Packets: {session.packet_count}\n")
                txtfile.write(f"Total Bytes: {session.total_bytes:,}\n\n")
                
                # Write protocol statistics
                txtfile.write("Protocol Statistics:\n")
                stats = session.get_stats()
                for protocol, count in stats.items():
                    percentage = (count / session.packet_count) * 100 if session.packet_count > 0 else 0
                    txtfile.write(f"  {protocol:<6}: {count:>6} packets ({percentage:>5.1f}%)\n")
                
                txtfile.write(f"\n{'='*60}\n")
                txtfile.write("Packet Details:\n")
                txtfile.write(f"{'='*60}\n\n")
                
                # Write packet details
                for i, packet in enumerate(session.packets, 1):
                    txtfile.write(f"Packet #{i}:\n")
                    txtfile.write(f"  Time:      {packet.timestamp}\n")
                    txtfile.write(f"  Source:    {packet.src_ip}:{packet.src_port}\n")
                    txtfile.write(f"  Dest:      {packet.dst_ip}:{packet.dst_port}\n")
                    txtfile.write(f"  Protocol:  {packet.protocol}\n")
                    txtfile.write(f"  Length:    {packet.length} bytes\n")
                    
                    # Add layer information
                    for layer_name, layer_data in packet.layers.items():
                        txtfile.write(f"  {layer_name}:\n")
                        for key, value in layer_data.items():
                            txtfile.write(f"    {key:<15}: {value}\n")
                    
                    if include_payload and len(packet.raw_data) > 0:
                        txtfile.write(f"  Payload ({len(packet.raw_data)} bytes):\n")
                        
                        # Hex dump
                        for j in range(0, min(len(packet.raw_data), 128), 16):
                            hex_part = ' '.join(
                                f"{b:02x}" for b in packet.raw_data[j:j+16]
                            )
                            
                            # ASCII part
                            ascii_part = ''.join(
                                chr(b) if 32 <= b <= 126 else '.'
                                for b in packet.raw_data[j:j+16]
                            )
                            
                            txtfile.write(f"    {j:04x}: {hex_part:<48}  {ascii_part}\n")
                        
                        if len(packet.raw_data) > 128:
                            txtfile.write(f"    ... {len(packet.raw_data) - 128} more bytes\n")
                    
                    txtfile.write(f"\n{'-'*40}\n\n")
            
            return True
            
        except Exception as e:
            print(f"Text export error: {e}")
            return False
    
    def _get_packet_info(self, packet: Packet) -> str:
        """Get human-readable info about packet"""
        info_parts = []
        
        if packet.protocol == "TCP" and packet.layers.get('TCP'):
            tcp_info = packet.layers['TCP']
            flags = tcp_info.get('flags', '')
            
            # Decode TCP flags
            if 'SYN' in flags:
                if 'ACK' in flags:
                    info_parts.append("SYN-ACK")
                else:
                    info_parts.append("SYN")
            elif 'ACK' in flags and 'SYN' not in flags:
                info_parts.append("ACK")
            elif 'FIN' in flags:
                info_parts.append("FIN")
            elif 'RST' in flags:
                info_parts.append("RST")
            elif 'PSH' in flags:
                info_parts.append("PSH")
            elif 'URG' in flags:
                info_parts.append("URG")
            
            # Window size
            window = tcp_info.get('window', '')
            if window:
                info_parts.append(f"Win={window}")
            
            # Sequence info
            seq = tcp_info.get('seq', '')
            ack = tcp_info.get('ack', '')
            if seq and ack:
                info_parts.append(f"Seq={seq}")
                info_parts.append(f"Ack={ack}")
        
        elif packet.protocol == "ICMP" and packet.layers.get('ICMP'):
            icmp_type = packet.layers['ICMP'].get('type', '')
            if icmp_type == 8:
                info_parts.append("Echo Request")
            elif icmp_type == 0:
                info_parts.append("Echo Reply")
            elif icmp_type == 3:
                info_parts.append("Destination Unreachable")
            elif icmp_type == 11:
                info_parts.append("Time Exceeded")
        
        elif packet.protocol == "ARP" and packet.layers.get('ARP'):
            op = packet.layers['ARP'].get('op', '')
            if op == 1:
                info_parts.append("Request")
            elif op == 2:
                info_parts.append("Reply")
        
        # Add TTL for IP packets
        if packet.layers.get('IP'):
            ttl = packet.layers['IP'].get('ttl', '')
            if ttl:
                info_parts.append(f"TTL={ttl}")
        
        # Special port-based info
        if packet.dst_port == '80' or packet.src_port == '80':
            info_parts.append("HTTP")
        elif packet.dst_port == '443' or packet.src_port == '443':
            info_parts.append("HTTPS")
        elif packet.dst_port == '53' or packet.src_port == '53':
            info_parts.append("DNS")
        elif packet.dst_port == '22' or packet.src_port == '22':
            info_parts.append("SSH")
        elif packet.dst_port == '25' or packet.src_port == '25':
            info_parts.append("SMTP")
        
        return "; ".join(info_parts) if info_parts else "Data"
    
    def get_supported_formats(self) -> Dict[str, Dict[str, str]]:
        """Get dictionary of supported export formats"""
        return self.supported_formats.copy()
    
    def get_format_description(self, format: str) -> str:
        """Get description of export format"""
        fmt_info = self.supported_formats.get(format.lower())
        return fmt_info['description'] if fmt_info else "Unknown format"
    
    def get_file_extension(self, format: str) -> str:
        """Get file extension for format"""
        fmt_info = self.supported_formats.get(format.lower())
        return fmt_info['extension'] if fmt_info else '.bin'
    
    def validate_export_path(self, file_path: str, format: str) -> tuple[bool, str]:
        """
        Validate export path and format
        Returns: (is_valid, error_message)
        """
        if format.lower() not in self.supported_formats:
            return False, f"Unsupported format: {format}"
        
        path = Path(file_path)
        
        # Check if directory exists and is writable
        if not path.parent.exists():
            return False, f"Directory does not exist: {path.parent}"
        
        if not path.parent.is_dir():
            return False, f"Not a directory: {path.parent}"
        
        # Check if we can write to directory
        try:
            test_file = path.parent / '.ethereye_test'
            test_file.touch()
            test_file.unlink()
        except PermissionError:
            return False, f"No write permission in directory: {path.parent}"
        except Exception as e:
            return False, f"Cannot write to directory: {e}"
        
        # Check file extension
        expected_ext = self.supported_formats[format.lower()]['extension']
        if not file_path.endswith(expected_ext):
            return True, f"Note: File will be saved as {path.stem}{expected_ext}"
        
        return True, "Path is valid"