"""
Hex/ASCII view widget (Bottom Panel) - Dark Theme Version
SRS Compliance: Implements FU-06 hex view requirement
"""

from PyQt6.QtWidgets import QTextEdit, QVBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

class HexViewWidget(QWidget):
    """Widget to display packet data in hex and ASCII format - Dark Theme"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        """Initialize the hex view widget with dark theme"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Header label
        header_label = QLabel("Hex Dump")
        header_label.setStyleSheet("""
            QLabel {
                background-color: #3d3d3d;
                padding: 5px;
                border: 1px solid #555555;
                border-bottom: none;
                font-weight: bold;
                color: #cccccc;
            }
        """)
        layout.addWidget(header_label)
        
        # Hex display
        self.hex_display = QTextEdit()
        self.hex_display.setObjectName("hexView")  # For CSS styling
        self.hex_display.setReadOnly(True)
        self.hex_display.setFont(QFont("Consolas", 10))
        self.hex_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #e0e0e0;
                border: 1px solid #555555;
                border-top: none;
                padding: 5px;
                font-family: Consolas, Monaco, 'Courier New', monospace;
            }
        """)
        
        layout.addWidget(self.hex_display)
    
    def display_hex(self, hex_data: str):
        """Display hexadecimal data (SRS FU-06) with dark theme syntax highlighting"""
        self.hex_display.clear()
        
        if not hex_data:
            return
        
        # Create a formatted display with colors optimized for dark theme
        lines = hex_data.split('\n')
        formatted_text = ""
        
        for line in lines:
            if not line.strip():
                continue
                
            # Parse the line
            parts = line.split('  ')
            if len(parts) >= 2:
                # Address part in light gray
                address_part = parts[0]
                hex_part = '  '.join(parts[1:-1]) if len(parts) > 2 else parts[1]
                ascii_part = parts[-1] if len(parts) > 1 else ""
                
                # Color coding for dark theme
                formatted_text += f'<span style="color:#999;">{address_part}</span> '
                formatted_text += f'<span style="color:#66ccff;">{hex_part}</span>'
                
                # ASCII part with printable chars in light colors
                colored_ascii = ""
                for char in ascii_part:
                    if 32 <= ord(char) <= 126:  # Printable ASCII
                        if char.isalnum() or char in ' .,;:!?':
                            colored_ascii += f'<span style="color:#ffffff;">{char}</span>'
                        else:
                            colored_ascii += f'<span style="color:#cccccc;">{char}</span>'
                    else:
                        colored_ascii += f'<span style="color:#666;">{char}</span>'
                
                formatted_text += f'  <span style="color:#666;">|</span> {colored_ascii}<br>'
            else:
                formatted_text += f'<span style="color:#999;">{line}</span><br>'
        
        self.hex_display.setHtml(formatted_text)
    
    def clear(self):
        """Clear the hex view"""
        self.hex_display.clear()