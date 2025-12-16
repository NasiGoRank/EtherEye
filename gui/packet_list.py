"""
Packet list widget (Top Panel) - Dark Theme Version
SRS Compliance: Implements FU-04, FU-05 - Real-time packet display
"""

from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor, QBrush

from models.packet_session import Packet

class PacketListWidget(QTableWidget):
    """Widget to display packets in a table format - Dark Theme"""
    
    def __init__(self):
        super().__init__()
        self.setObjectName("packetTable")  # For CSS styling
        self.init_ui()
        self.packets = []
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(100)  # Update every 100ms for real-time feel
        
        # Text colors for protocols (optimized for dark theme)
        self.protocol_colors = {
            'TCP': QColor(100, 150, 255),      # Soft blue
            'UDP': QColor(100, 220, 150),      # Soft green
            'ICMP': QColor(255, 120, 200),     # Soft pink
            'ARP': QColor(220, 180, 100),      # Soft gold
            'IPv6': QColor(180, 120, 255),     # Soft purple
            'HTTP': QColor(255, 180, 80),      # Soft orange
            'HTTPS': QColor(80, 220, 220),     # Soft cyan
            'DNS': QColor(255, 120, 120),      # Soft red
            'SSH': QColor(220, 220, 100),      # Soft yellow
            'Other': QColor(180, 180, 180)     # Light gray
        }
    
    def init_ui(self):
        """Initialize the table widget with dark theme"""
        # Set column headers (SRS FU-05)
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length"
        ])
        
        # Set table properties
        self.setFont(QFont("Segoe UI", 10))  # Modern readable font
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(False)  # Disable sorting for real-time updates
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        
        # Configure header for dark theme
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)  # No.
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)  # Time
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)           # Source
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)           # Destination
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)  # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)  # Length
        
        # Style the header (will be overridden by CSS)
        header_font = QFont("Segoe UI", 10, QFont.Weight.Bold)
        header.setFont(header_font)
        
        # Enable horizontal scrolling
        self.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        
        # Set column widths
        self.setColumnWidth(0, 60)   # No.
        self.setColumnWidth(1, 140)  # Time
        self.setColumnWidth(4, 90)   # Protocol
        self.setColumnWidth(5, 80)   # Length
        self.setColumnWidth(6, 200)  # Info
    
    def add_packet(self, packet: Packet):
        """Add packet to the list (SRS FU-04)"""
        self.packets.append(packet)
    
    def update_display(self):
        """Update the display with new packets (batched for performance)"""
        if not self.packets:
            return
        
        # Get current row count
        current_rows = self.rowCount()
        
        # Add new rows
        self.setRowCount(current_rows + len(self.packets))
        
        for i, packet in enumerate(self.packets):
            row = current_rows + i
            
            # Packet number
            item_no = QTableWidgetItem(str(packet.packet_number))
            item_no.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_no.setForeground(QBrush(QColor(180, 180, 180)))  # Light gray
            self.setItem(row, 0, item_no)
            
            # Timestamp (millisecond precision)
            timestamp_str = packet.timestamp.strftime("%H:%M:%S.%f")[:-3]
            item_time = QTableWidgetItem(timestamp_str)
            item_time.setForeground(QBrush(QColor(200, 200, 200)))  # Very light gray
            self.setItem(row, 1, item_time)
            
            # Source (IP:Port)
            if packet.src_port:
                source_str = f"{packet.src_ip}:{packet.src_port}"
            else:
                source_str = packet.src_ip
            source_item = QTableWidgetItem(source_str)
            source_item.setForeground(QBrush(QColor(220, 220, 220)))  # Almost white
            self.setItem(row, 2, source_item)
            
            # Destination (IP:Port)
            if packet.dst_port:
                dest_str = f"{packet.dst_ip}:{packet.dst_port}"
            else:
                dest_str = packet.dst_ip
            dest_item = QTableWidgetItem(dest_str)
            dest_item.setForeground(QBrush(QColor(220, 220, 220)))  # Almost white
            self.setItem(row, 3, dest_item)
            
            # Protocol - with colored text
            protocol = packet.protocol
            item_protocol = QTableWidgetItem(protocol)
            item_protocol.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            
            # Info column (column 6)
            info_text = self._get_packet_info(packet)
            info_item = QTableWidgetItem(info_text)
            info_item.setForeground(QBrush(QColor(180, 180, 180)))  # Light gray
            info_item.setToolTip(info_text)  # Show full info on hover
            self.setItem(row, 6, info_item)
            
            # Set text color based on protocol
            text_color = self.protocol_colors.get(protocol, self.protocol_colors['Other'])
            item_protocol.setForeground(QBrush(text_color))
            
            # Make protocol text bold for better visibility
            font = QFont("Segoe UI", 10, QFont.Weight.Bold)
            item_protocol.setFont(font)
            self.setItem(row, 4, item_protocol)
            
            # Length
            item_length = QTableWidgetItem(str(packet.length))
            item_length.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            item_length.setForeground(QBrush(QColor(180, 180, 180)))  # Light gray
            self.setItem(row, 5, item_length)
            
            # Ensure text is visible against selection
            for col in range(6):
                item = self.item(row, col)
                if item:
                    item.setSelected(False)
        
        # Clear the packets list
        self.packets.clear()
        
        # Auto-scroll to bottom
        if self.rowCount() > 0:
            self.scrollToItem(self.item(self.rowCount() - 1, 0))
            
            # Highlight the newest packet briefly (with dark theme color)
            self.selectRow(self.rowCount() - 1)
            QTimer.singleShot(500, lambda: self.clearSelection() if self.rowCount() > 0 else None)
    
    def _get_packet_info(self, packet):
        """Get human-readable info about packet"""
        info_parts = []
        
        # TCP flags
        if packet.protocol == "TCP" and packet.layers.get('TCP'):
            tcp_info = packet.layers['TCP']
            flags = tcp_info.get('flags', '')
            
            if flags:
                flag_list = flags.split('|')
                if flag_list:
                    info_parts.append(f"Flags: {', '.join(flag_list)}")
        
        # ICMP type
        elif packet.protocol == "ICMP" and packet.layers.get('ICMP'):
            icmp_type = packet.layers['ICMP'].get('type', '')
            if icmp_type == 8:
                info_parts.append("Echo Request")
            elif icmp_type == 0:
                info_parts.append("Echo Reply")
        
        # ARP operation
        elif packet.protocol == "ARP" and packet.layers.get('ARP'):
            op = packet.layers['ARP'].get('op', '')
            if op == 1:
                info_parts.append("Request")
            elif op == 2:
                info_parts.append("Reply")
        
        # Application layer info
        if 'Application' in packet.layers:
            app_info = packet.layers['Application']
            
            # HTTP info
            if 'type' in app_info:
                if app_info['type'] == 'Request':
                    if 'method' in app_info and 'uri' in app_info:
                        info_parts.append(f"{app_info['method']} {app_info['uri']}")
                elif app_info['type'] == 'Response':
                    if 'status_code' in app_info:
                        info_parts.append(f"HTTP {app_info['status_code']}")
            
            # DNS info
            elif 'qr' in app_info:
                if app_info['qr'] == 'Query':
                    if 'questions' in app_info and app_info['questions']:
                        info_parts.append(f"DNS Query: {app_info['questions'][0]}")
                elif app_info['qr'] == 'Response':
                    if 'answers' in app_info and app_info['answers']:
                        info_parts.append(f"DNS Response: {len(app_info['answers'])} answers")
        
        # Common ports
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
        elif packet.dst_port == '21' or packet.src_port == '21':
            info_parts.append("FTP")
        
        # Packet size indicator
        if packet.length > 1000:
            info_parts.append(f"Large ({packet.length} bytes)")
        
        return " | ".join(info_parts) if info_parts else "Data"
    
    def clear(self):
        """Clear all packets from display"""
        super().clear()
        self.setRowCount(0)
        self.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Length"
        ])
        self.packets.clear()