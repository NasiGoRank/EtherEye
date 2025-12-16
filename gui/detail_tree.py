"""
Packet detail tree widget (Middle Panel) - Dark Theme Version
SRS Compliance: Implements FU-06 packet inspection
"""

from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QColor, QBrush

from models.packet_session import Packet

class DetailTreeWidget(QTreeWidget):
    """Widget to display packet details in a tree structure - Dark Theme"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the tree widget with dark theme"""
        self.setHeaderLabel("Packet Details")
        self.setFont(QFont("Segoe UI", 9))  # Modern readable font
        
        # Tree properties
        self.setAlternatingRowColors(True)
        self.setAnimated(True)
        self.setColumnCount(2)
        self.setHeaderLabels(["Field", "Value"])
        
        header = self.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
    
    def display_packet(self, packet: Packet):
        """Display packet details in tree format (SRS FU-06) with dark theme colors"""
        self.clear()
        
        # Root item
        root = QTreeWidgetItem(self)
        root.setText(0, f"Frame {packet.packet_number}")
        root.setText(1, f"{packet.length} bytes on wire")
        root.setForeground(0, QBrush(QColor(120, 170, 255)))  # Light blue
        root.setFont(0, QFont("Segoe UI", 10, QFont.Weight.Bold))
        
        # Add all layers
        for layer_name, layer_data in packet.layers.items():
            layer_item = QTreeWidgetItem(root)
            layer_item.setText(0, layer_name)
            
            # Set layer name color
            text_color = self.get_layer_color(layer_name)
            layer_item.setForeground(0, QBrush(text_color))
            layer_item.setFont(0, QFont("Segoe UI", 9, QFont.Weight.Bold))
            
            # Add fields for this layer
            for field_name, field_value in layer_data.items():
                field_item = QTreeWidgetItem(layer_item)
                field_item.setText(0, field_name)
                field_item.setText(1, str(field_value))
                
                # Differentiate field name and value
                field_item.setForeground(0, QBrush(QColor(180, 180, 180)))  # Light gray
                field_item.setForeground(1, QBrush(QColor(220, 220, 220)))  # Almost white
            
            # Expand important layers by default
            if layer_name in ['Application', 'TCP', 'UDP', 'IP', 'Ethernet']:
                layer_item.setExpanded(True)
        
        # Expand root
        root.setExpanded(True)
        
        # Resize columns to content
        self.resizeColumnToContents(0)
        
    def get_layer_color(self, layer_name: str):
        """Get color for a layer name"""
        colors = {
            'Ethernet': QColor(100, 150, 255),      # Soft blue
            'IP': QColor(100, 220, 150),           # Soft green
            'TCP': QColor(255, 120, 200),          # Soft pink/magenta
            'UDP': QColor(220, 180, 100),          # Soft gold
            'ICMP': QColor(180, 120, 255),         # Soft purple
            'ARP': QColor(255, 180, 80),           # Soft orange
            'IPv6': QColor(80, 220, 220),          # Soft cyan
            'Application': QColor(255, 200, 100),  # Soft yellow
            'DNS': QColor(255, 120, 120),          # Soft red
            'HTTP': QColor(100, 200, 255),         # Light blue
            'HTTPS': QColor(100, 255, 200),        # Light green
        }
        
        return colors.get(layer_name, QColor(180, 180, 180))