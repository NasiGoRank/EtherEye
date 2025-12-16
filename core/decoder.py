"""
Packet decoder using Scapy
SRS Compliance: Implements protocol decoding for FU-05, FU-06, and Section 4.4
"""

from datetime import datetime
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR, DNSRR
from models.packet_session import Packet

class PacketDecoder:
    """Decodes raw packets into structured data"""
    
    def __init__(self):
        self.packet_count = 0
    
    def decode_packet(self, raw_packet) -> Packet:
        """Decode a raw packet into structured Packet object"""
        self.packet_count += 1
        print(f"Decoding packet #{self.packet_count}")
        print(f"Raw packet layers: {raw_packet.summary()}")
        
        # Initialize protocol information
        src_ip = dst_ip = "N/A"
        protocol = "Other"
        src_port = dst_port = ""
        layers = {}
        app_layer_info = {}
        
        # ===== Layer 2: Ethernet =====
        if Ether in raw_packet:
            eth = raw_packet[Ether]
            layers['Ethernet'] = {
                'src': str(eth.src),
                'dst': str(eth.dst),
                'type': f"0x{eth.type:04x}"
            }
        
        # ===== Layer 3: Network =====
        if IP in raw_packet:
            ip = raw_packet[IP]
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
            
            layers['IP'] = {
                'version': int(ip.version),
                'ihl': int(ip.ihl),
                'tos': int(ip.tos),
                'len': int(ip.len),
                'id': int(ip.id),
                'flags': str(ip.flags) if hasattr(ip, 'flags') else '',
                'frag': int(ip.frag),
                'ttl': int(ip.ttl),
                'proto': int(ip.proto),
                'chksum': int(ip.chksum) if ip.chksum else 0,
                'src': str(ip.src),
                'dst': str(ip.dst)
            }
            
            # ===== Layer 4: Transport =====
            if TCP in raw_packet:
                tcp = raw_packet[TCP]
                protocol = "TCP"
                src_port = str(tcp.sport)
                dst_port = str(tcp.dport)
                
                layers['TCP'] = {
                    'sport': int(tcp.sport),
                    'dport': int(tcp.dport),
                    'seq': int(tcp.seq),
                    'ack': int(tcp.ack),
                    'dataofs': int(tcp.dataofs),
                    'reserved': int(tcp.reserved),
                    'flags': self._decode_tcp_flags(tcp.flags),
                    'window': int(tcp.window),
                    'chksum': int(tcp.chksum) if tcp.chksum else 0,
                    'urgptr': int(tcp.urgptr)
                }
                
                # Try to identify application layer by port and content
                app_layer_info = self._identify_application(tcp, raw_packet)
                if app_layer_info and 'protocol' in app_layer_info:
                    protocol = app_layer_info['protocol']
                
            elif UDP in raw_packet:
                udp = raw_packet[UDP]
                protocol = "UDP"
                src_port = str(udp.sport)
                dst_port = str(udp.dport)
                
                layers['UDP'] = {
                    'sport': int(udp.sport),
                    'dport': int(udp.dport),
                    'len': int(udp.len),
                    'chksum': int(udp.chksum) if udp.chksum else 0
                }
                
                # Check for DNS
                if udp.sport == 53 or udp.dport == 53:
                    protocol = "DNS"
                    app_layer_info = self._parse_dns(raw_packet)
                
            elif ICMP in raw_packet:
                icmp = raw_packet[ICMP]
                protocol = "ICMP"
                
                layers['ICMP'] = {
                    'type': int(icmp.type),
                    'code': int(icmp.code),
                    'chksum': int(icmp.chksum) if icmp.chksum else 0,
                    'id': int(getattr(icmp, 'id', 0)),
                    'seq': int(getattr(icmp, 'seq', 0))
                }
                
        elif IPv6 in raw_packet:
            ipv6 = raw_packet[IPv6]
            src_ip = str(ipv6.src)
            dst_ip = str(ipv6.dst)
            protocol = "IPv6"
            
            layers['IPv6'] = {
                'version': int(ipv6.version),
                'tc': int(ipv6.tc),
                'fl': int(ipv6.fl),
                'plen': int(ipv6.plen),
                'nh': int(ipv6.nh),
                'hlim': int(ipv6.hlim),
                'src': str(ipv6.src),
                'dst': str(ipv6.dst)
            }
            
        elif ARP in raw_packet:
            arp = raw_packet[ARP]
            src_ip = str(arp.psrc)
            dst_ip = str(arp.pdst)
            protocol = "ARP"
            
            layers['ARP'] = {
                'hwtype': int(arp.hwtype),
                'ptype': int(arp.ptype),
                'hwlen': int(arp.hwlen),
                'plen': int(arp.plen),
                'op': int(arp.op),
                'hwsrc': str(arp.hwsrc),
                'psrc': str(arp.psrc),
                'hwdst': str(arp.hwdst),
                'pdst': str(arp.pdst)
            }
        
        # Add application layer info to layers if present
        if app_layer_info:
            layers['Application'] = app_layer_info
        
        # Create Packet object
        packet = Packet(
            packet_number=self.packet_count,
            timestamp=datetime.now(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=str(src_port) if src_port else "",
            dst_port=str(dst_port) if dst_port else "",
            length=len(raw_packet),
            raw_data=bytes(raw_packet),
            layers=layers
        )
        
        return packet
    
    def _decode_tcp_flags(self, flags):
        """Decode TCP flags to human-readable format"""
        flag_names = []
        if flags & 0x01: flag_names.append("FIN")
        if flags & 0x02: flag_names.append("SYN")
        if flags & 0x04: flag_names.append("RST")
        if flags & 0x08: flag_names.append("PSH")
        if flags & 0x10: flag_names.append("ACK")
        if flags & 0x20: flag_names.append("URG")
        if flags & 0x40: flag_names.append("ECE")
        if flags & 0x80: flag_names.append("CWR")
        return "|".join(flag_names) if flag_names else "None"
    
    def _identify_application(self, tcp, raw_packet):
        """Identify application layer protocol"""
        app_info = {}
        
        try:
            # Get payload if available
            payload = None
            if Raw in raw_packet:
                payload = raw_packet[Raw].load
            
            # Identify by port
            if tcp.sport == 80 or tcp.dport == 80:
                app_info['protocol'] = 'HTTP'
                if payload:
                    app_info.update(self._parse_http(payload))
            elif tcp.sport == 443 or tcp.dport == 443:
                app_info['protocol'] = 'HTTPS'
                app_info['encrypted'] = True
            elif tcp.sport == 22 or tcp.dport == 22:
                app_info['protocol'] = 'SSH'
                app_info['service'] = 'SSH'
            elif tcp.sport == 21 or tcp.dport == 21:
                app_info['protocol'] = 'FTP'
                if payload:
                    app_info.update(self._parse_ftp(payload))
            elif tcp.sport == 25 or tcp.dport == 25:
                app_info['protocol'] = 'SMTP'
                if payload:
                    app_info.update(self._parse_smtp(payload))
            elif tcp.sport == 110 or tcp.dport == 110:
                app_info['protocol'] = 'POP3'
                app_info['service'] = 'POP3'
            elif tcp.sport == 143 or tcp.dport == 143:
                app_info['protocol'] = 'IMAP'
                app_info['service'] = 'IMAP'
            elif tcp.sport == 53 or tcp.dport == 53:
                app_info['protocol'] = 'DNS'
                if payload:
                    app_info.update(self._parse_dns_tcp(payload))
            elif tcp.sport == 3306 or tcp.dport == 3306:
                app_info['protocol'] = 'MySQL'
            elif tcp.sport == 5432 or tcp.dport == 5432:
                app_info['protocol'] = 'PostgreSQL'
            elif tcp.sport == 3389 or tcp.dport == 3389:
                app_info['protocol'] = 'RDP'
            
            # Try to identify by content if not identified by port
            elif payload:
                payload_str = payload.decode('utf-8', errors='ignore')
                if 'HTTP/' in payload_str or 'GET ' in payload_str or 'POST ' in payload_str:
                    app_info['protocol'] = 'HTTP'
                    app_info.update(self._parse_http(payload))
        
        except Exception as e:
            print(f"Error identifying application: {e}")
        
        return app_info
    
    def _parse_http(self, payload):
        """Parse HTTP packets"""
        http_info = {}
        
        try:
            if not payload:
                return http_info
            
            # Decode payload
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # Look for HTTP signature
            lines = payload_str.split('\n')
            for line in lines[:5]:  # Check first 5 lines
                line = line.strip()
                if line.startswith('GET ') or line.startswith('POST ') or line.startswith('PUT ') or \
                   line.startswith('DELETE ') or line.startswith('HEAD ') or line.startswith('OPTIONS '):
                    parts = line.split()
                    if len(parts) >= 3:
                        http_info['method'] = parts[0]
                        http_info['path'] = parts[1]
                        http_info['version'] = parts[2]
                        http_info['type'] = 'Request'
                        break
                elif line.startswith('HTTP/'):
                    parts = line.split()
                    if len(parts) >= 3:
                        http_info['version'] = parts[0]
                        http_info['status_code'] = parts[1]
                        http_info['status_message'] = ' '.join(parts[2:])
                        http_info['type'] = 'Response'
                        break
            
            # Extract headers
            in_headers = False
            headers = {}
            for line in lines:
                if ': ' in line:
                    in_headers = True
                    key, value = line.split(': ', 1)
                    headers[key.strip()] = value.strip()
                elif in_headers and line.strip() == '':
                    break
            
            # Add important headers
            for key in ['Host', 'User-Agent', 'Content-Type', 'Content-Length', 'Server']:
                if key in headers:
                    http_info[key.lower()] = headers[key]
        
        except Exception as e:
            print(f"Error parsing HTTP: {e}")
        
        return http_info
    
    def _parse_dns(self, packet):
        """Parse DNS packets"""
        dns_info = {}
        
        try:
            if DNS in packet:
                dns = packet[DNS]
                
                dns_info['id'] = int(dns.id)
                dns_info['qr'] = 'Response' if dns.qr else 'Query'
                
                # Questions
                if hasattr(dns, 'qd') and dns.qd:
                    questions = []
                    for q in dns.qd:
                        if hasattr(q, 'qname'):
                            questions.append(str(q.qname))
                    if questions:
                        dns_info['questions'] = questions
                
                # Answers
                if hasattr(dns, 'an') and dns.an:
                    answers = []
                    for a in dns.an:
                        if hasattr(a, 'rrname'):
                            answers.append(str(a.rrname))
                    if answers:
                        dns_info['answers'] = answers
        
        except Exception as e:
            print(f"Error parsing DNS: {e}")
        
        return dns_info
    
    def _parse_dns_tcp(self, payload):
        """Parse DNS over TCP"""
        dns_info = {'transport': 'TCP'}
        return dns_info
    
    def _parse_ftp(self, payload):
        """Parse FTP packets"""
        ftp_info = {}
        
        try:
            if payload:
                payload_str = payload.decode('utf-8', errors='ignore').strip()
                if payload_str:
                    ftp_info['command'] = payload_str.split()[0] if ' ' in payload_str else payload_str
        except:
            pass
        
        return ftp_info
    
    def _parse_smtp(self, payload):
        """Parse SMTP packets"""
        smtp_info = {}
        
        try:
            if payload:
                payload_str = payload.decode('utf-8', errors='ignore').strip()
                if payload_str:
                    smtp_info['command'] = payload_str.split()[0] if ' ' in payload_str else payload_str
        except:
            pass
        
        return smtp_info
    
    def get_packet_hex(self, packet: Packet) -> str:
        """Get hexadecimal representation of packet (for FU-06 hex view)"""
        hex_str = ""
        ascii_str = ""
        
        for i, byte in enumerate(packet.raw_data):
            if i % 16 == 0:
                if i > 0:
                    hex_str += f"  {ascii_str}\n"
                    ascii_str = ""
                hex_str += f"{i:04x}: "
            
            hex_str += f"{byte:02x} "
            
            # ASCII representation (show printable characters only)
            if 32 <= byte <= 126:
                ascii_str += chr(byte)
            else:
                ascii_str += "."
        
        # Pad last line if needed
        if len(packet.raw_data) % 16 != 0:
            remaining = 16 - (len(packet.raw_data) % 16)
            hex_str += "   " * remaining
        
        hex_str += f"  {ascii_str}"
        return hex_str