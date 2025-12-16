"""
Filter Engine for EtherEye
SRS Compliance: Implements FU-07 - Simple Packet Filtering
Translates user-friendly filters to BPF syntax
"""

import re
from typing import Optional, Tuple  # IMPORTANT: Add this import

class FilterEngine:
    """Converts user-friendly filters to BPF syntax"""
    
    def __init__(self):
        # Protocol mapping
        self.protocol_map = {
            'tcp': 'tcp',
            'udp': 'udp', 
            'icmp': 'icmp',
            'arp': 'arp',
            'http': 'tcp port 80',
            'https': 'tcp port 443',
            'dns': 'udp port 53 or tcp port 53'
        }
        
        # Common port mappings
        self.port_map = {
            'ftp': 21,
            'ssh': 22,
            'telnet': 23,
            'smtp': 25,
            'dns': 53,
            'http': 80,
            'pop3': 110,
            'https': 443,
            'mysql': 3306,
            'rdp': 3389
        }
    
    def parse_filter(self, user_input: str) -> Tuple[str, Optional[str]]:
        """
        Parse user input and convert to BPF syntax
        Returns: (bpf_filter, error_message)
        """
        if not user_input or user_input.strip() == "":
            return "", None
        
        input_str = user_input.strip().lower()
        
        # Check for complex filters (already in BPF format)
        if self._is_bpf_format(input_str):
            return input_str, None
        
        try:
            # Try different parsing strategies
            bpf_filter = self._parse_simple_filter(input_str)
            if bpf_filter:
                return bpf_filter, None
            else:
                return "", f"Could not parse filter: {user_input}"
                
        except Exception as e:
            return "", f"Filter error: {str(e)}"
    
    def _is_bpf_format(self, filter_str: str) -> bool:
        """Check if filter is already in BPF format"""
        bpf_keywords = [
            'host', 'net', 'port', 'src', 'dst', 'proto',
            'and', 'or', 'not', 'greater', 'less', 
            'tcp', 'udp', 'icmp', 'arp', 'ip', 'ip6'
        ]
        
        # Check for BPF keywords
        words = filter_str.split()
        for word in words:
            if word in bpf_keywords:
                return True
        
        # Check for common BPF patterns
        bpf_patterns = [
            r'port\s+\d+',
            r'host\s+\d+\.\d+\.\d+\.\d+',
            r'net\s+\d+\.\d+\.\d+\.\d+/\d+',
            r'proto\s+\w+'
        ]
        
        for pattern in bpf_patterns:
            if re.search(pattern, filter_str, re.IGNORECASE):
                return True
        
        return False
    
    def _parse_simple_filter(self, filter_str: str) -> Optional[str]:
        """Parse simple user-friendly filters"""
        # Remove extra whitespace
        filter_str = ' '.join(filter_str.split())
        
        # Check for IP address (IPv4)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_matches = re.findall(ip_pattern, filter_str)
        
        # Check for protocol names
        words = filter_str.split()
        protocols = []
        other_words = []
        
        for word in words:
            if word in self.protocol_map:
                protocols.append(word)
            elif word in self.port_map:
                protocols.append(word)
            elif not re.match(ip_pattern, word):
                other_words.append(word)
        
        # Build BPF filter
        bpf_parts = []
        
        # Add IP filters
        for ip in ip_matches:
            if self._is_valid_ip(ip):
                bpf_parts.append(f"host {ip}")
        
        # Add protocol filters
        for proto in protocols:
            if proto in self.protocol_map:
                bpf_parts.append(self.protocol_map[proto])
            elif proto in self.port_map:
                port = self.port_map[proto]
                bpf_parts.append(f"port {port}")
        
        # Try to parse port numbers
        for word in other_words:
            # Check for port numbers
            if word.isdigit():
                port = int(word)
                if 1 <= port <= 65535:
                    bpf_parts.append(f"port {port}")
            
            # Check for source/destination keywords
            elif word in ['from', 'src', 'source']:
                # Next word might be an IP
                idx = words.index(word)
                if idx + 1 < len(words):
                    next_word = words[idx + 1]
                    if re.match(ip_pattern, next_word) and self._is_valid_ip(next_word):
                        bpf_parts.append(f"src host {next_word}")
            
            elif word in ['to', 'dst', 'dest', 'destination']:
                # Next word might be an IP
                idx = words.index(word)
                if idx + 1 < len(words):
                    next_word = words[idx + 1]
                    if re.match(ip_pattern, next_word) and self._is_valid_ip(next_word):
                        bpf_parts.append(f"dst host {next_word}")
        
        # Combine all parts with 'and'
        if bpf_parts:
            if len(bpf_parts) == 1:
                return bpf_parts[0]
            else:
                return ' and '.join(bpf_parts)
        
        return None
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Validate IPv4 address"""
        parts = ip_str.split('.')
        if len(parts) != 4:
            return False
        
        for part in parts:
            try:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            except ValueError:
                return False
        
        return True
    
    def get_filter_examples(self) -> list:
        """Get examples of supported filters"""
        return [
            ("192.168.1.1", "Filter traffic to/from specific IP"),
            ("tcp", "Filter TCP packets only"),
            ("udp port 53", "Filter DNS traffic"),
            ("http", "Filter HTTP traffic (port 80)"),
            ("src 192.168.1.10", "Filter packets from source IP"),
            ("port 443", "Filter HTTPS traffic"),
            ("icmp", "Filter ping packets"),
            ("tcp and port 80", "Filter HTTP traffic using BPF"),
            ("host 8.8.8.8 and udp", "Filter UDP traffic to/from Google DNS"),
        ]
    
    def validate_bpf(self, bpf_filter: str) -> Tuple[bool, str]:
        """
        Validate BPF filter syntax (basic validation)
        Returns: (is_valid, error_message)
        """
        if not bpf_filter:
            return True, ""
        
        # Check for potentially dangerous filters
        dangerous_keywords = ['broadcast', 'multicast', 'ip broadcast']
        for keyword in dangerous_keywords:
            if keyword in bpf_filter.lower():
                return False, f"Filter contains potentially dangerous keyword: {keyword}"
        
        # Check for reasonable length
        if len(bpf_filter) > 200:
            return False, "Filter too long (max 200 characters)"
        
        return True, ""