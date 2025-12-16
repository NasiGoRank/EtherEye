"""
Main window for EtherEye - Implements all SRS requirements
SRS Compliance: FU-01 through FU-09
"""

import sys
import os
from datetime import datetime
from typing import Optional
import uuid
import threading

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QLabel, QComboBox, QLineEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QMessageBox, QStatusBar,
    QToolBar, QMenu, QMenuBar, QFileDialog, QProgressDialog,
    QDialog, QInputDialog, QApplication
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QFont, QAction, QKeySequence, QIcon, QColor  # ADDED: QColor

# Core components
from core.capturer import CaptureEngine
from core.decoder import PacketDecoder
from core.filter_engine import FilterEngine

# GUI components
from gui.packet_list import PacketListWidget
from gui.detail_tree import DetailTreeWidget
from gui.hex_view import HexViewWidget
from gui.advanced_filter import AdvancedFilterDialog
from gui.display_filter import DisplayFilter
from gui.export_dialog import ExportDialog
from gui.history_dialog import HistoryDialog
from gui.styles import ALL_STYLES
from gui.display_filter import DisplayFilter

# Utils
from utils.history_manager import HistoryManager
from utils.exporter import SessionExporter


# Models
from models.packet_session import Packet, CaptureSession

class CaptureWorker(QThread):
    """Worker thread for packet capture"""
    packet_received = pyqtSignal(object)
    status_update = pyqtSignal(str)
    
    def __init__(self, capturer, decoder, filter_str=""):
        super().__init__()
        self.capturer = capturer
        self.decoder = decoder
        self.filter_str = filter_str
        self.running = False
    
    def run(self):
        """Main worker loop"""
        self.running = True
        
        def packet_callback(packet):
            if self.running:
                decoded_packet = self.decoder.decode_packet(packet)
                self.packet_received.emit(decoded_packet)
        
        # Start capture
        self.capturer.start_capture(packet_callback, self.filter_str)
        
        # Keep thread alive while capturing
        while self.running and self.capturer.is_capturing():
            self.msleep(100)
    
    def stop(self):
        """Stop the worker"""
        self.running = False
        self.capturer.stop_capture()
        self.wait()

class MainWindow(QMainWindow):
    """Main application window for EtherEye"""
    
    def __init__(self):
        super().__init__()
        self.current_session: Optional[CaptureSession] = None
        self.capturing = False
        self.capture_worker: Optional[CaptureWorker] = None
        self.display_filter = DisplayFilter()
        self.display_filter_active = False
        
        # Apply dark theme
        self.apply_dark_theme()
        
        # Initialize components
        self.capturer = CaptureEngine()
        self.decoder = PacketDecoder()
        self.filter_engine = FilterEngine()
        self.history_manager = HistoryManager()
        self.exporter = SessionExporter()
        
        self.init_ui()
        self.load_interfaces()
        self.update_status("Ready")
    
    def init_ui(self):
        """Initialize the main window UI"""
        self.setWindowTitle("EtherEye - Network Packet Analyzer")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # ===== Top toolbar =====
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        # Interface selection
        toolbar.addWidget(QLabel(" Interface: "))
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        toolbar.addWidget(self.interface_combo)
        
        toolbar.addSeparator()
        
        # Start/Stop button
        self.capture_button = QPushButton("Start Capture")
        self.capture_button.clicked.connect(self.toggle_capture)
        toolbar.addWidget(self.capture_button)
        
        toolbar.addSeparator()
        
        # Capture Filter input
        toolbar.addWidget(QLabel(" Capture Filter: "))
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("e.g., tcp, 192.168.1.1, port 80")
        self.filter_input.setMinimumWidth(200)
        self.filter_input.returnPressed.connect(self.apply_capture_filter)
        self.filter_input.setToolTip(
            "Filter packets during capture (BPF syntax)"
        )
        toolbar.addWidget(self.filter_input)
        
        self.apply_filter_button = QPushButton("Apply")
        self.apply_filter_button.clicked.connect(self.apply_capture_filter)
        toolbar.addWidget(self.apply_filter_button)
        
        self.clear_filter_button = QPushButton("Clear")
        self.clear_filter_button.clicked.connect(self.clear_capture_filter)
        toolbar.addWidget(self.clear_filter_button)
        
        toolbar.addSeparator()
        
        # Advanced Filter button
        self.advanced_filter_button = QPushButton("Advanced Filter...")
        self.advanced_filter_button.clicked.connect(self.show_advanced_filter)
        toolbar.addWidget(self.advanced_filter_button)
        
        toolbar.addSeparator()
        
        # Display Filter input
        toolbar.addWidget(QLabel(" Display Filter: "))
        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText("Filter displayed packets...")
        self.display_filter_input.setMinimumWidth(200)
        self.display_filter_input.returnPressed.connect(self.apply_display_filter)
        self.display_filter_input.setToolTip(
            "Filter already captured packets"
        )
        toolbar.addWidget(self.display_filter_input)
        
        self.apply_display_filter_button = QPushButton("Apply")
        self.apply_display_filter_button.clicked.connect(self.apply_display_filter)
        toolbar.addWidget(self.apply_display_filter_button)
        
        self.clear_display_filter_button = QPushButton("Clear")
        self.clear_display_filter_button.clicked.connect(self.clear_display_filter)
        toolbar.addWidget(self.clear_display_filter_button)
        
        toolbar.addSeparator()
        
        
        
        # Export button
        export_action = QAction("Export", self)
        export_action.triggered.connect(self.export_current_session)
        toolbar.addAction(export_action)
        
        # History button
        history_action = QAction("History", self)
        history_action.triggered.connect(self.show_history)
        toolbar.addAction(history_action)
        
        main_layout.addWidget(toolbar)
        
        # ===== Main content area (3-panel layout) =====
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Panel 1: Packet list (Top)
        self.packet_list = PacketListWidget()
        self.packet_list.itemSelectionChanged.connect(self.on_packet_selected)
        
        # Panel 2: Packet details (Middle)
        self.detail_tree = DetailTreeWidget()
        
        # Panel 3: Hex view (Bottom)
        self.hex_view = HexViewWidget()
        
        # Add panels to splitter
        splitter.addWidget(self.packet_list)
        splitter.addWidget(self.detail_tree)
        splitter.addWidget(self.hex_view)
        
        # Set initial sizes
        splitter.setSizes([400, 200, 200])
        
        main_layout.addWidget(splitter)
        
        # ===== Status bar =====
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)
        
        self.packet_count_label = QLabel("Packets: 0")
        self.status_bar.addWidget(self.packet_count_label)
        
        # ===== Menu bar =====
        self.create_menus()
    
    def apply_dark_theme(self):
        """Apply dark theme styles to the application"""
        # Apply the dark theme stylesheet
        self.setStyleSheet(ALL_STYLES)
        
        # Additional theme-specific settings
        palette = self.palette()
        palette.setColor(palette.ColorRole.Window, QColor(45, 45, 45))
        palette.setColor(palette.ColorRole.WindowText, QColor(224, 224, 224))
        palette.setColor(palette.ColorRole.Base, QColor(30, 30, 30))
        palette.setColor(palette.ColorRole.AlternateBase, QColor(45, 45, 45))
        palette.setColor(palette.ColorRole.ToolTipBase, QColor(45, 45, 45))
        palette.setColor(palette.ColorRole.ToolTipText, QColor(224, 224, 224))
        palette.setColor(palette.ColorRole.Text, QColor(224, 224, 224))
        palette.setColor(palette.ColorRole.Button, QColor(61, 61, 61))
        palette.setColor(palette.ColorRole.ButtonText, QColor(224, 224, 224))
        palette.setColor(palette.ColorRole.BrightText, QColor(255, 255, 255))
        palette.setColor(palette.ColorRole.Link, QColor(100, 150, 255))
        palette.setColor(palette.ColorRole.Highlight, QColor(74, 74, 74))
        palette.setColor(palette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        self.setPalette(palette)
    
    def create_menus(self):
        """Create application menus"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_session_action = QAction("New Session", self)
        new_session_action.triggered.connect(self.new_session)
        file_menu.addAction(new_session_action)
        
        file_menu.addSeparator()
        
        export_action = QAction("Export Session...", self)
        export_action.triggered.connect(self.export_current_session)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Capture menu
        capture_menu = menubar.addMenu("Capture")
        
        start_action = QAction("Start Capture", self)
        start_action.triggered.connect(self.start_capture)
        capture_menu.addAction(start_action)
        
        stop_action = QAction("Stop Capture", self)
        stop_action.triggered.connect(self.stop_capture)
        capture_menu.addAction(stop_action)
        
        capture_menu.addSeparator()
        
        interface_action = QAction("Refresh Interfaces", self)
        interface_action.triggered.connect(self.load_interfaces)
        capture_menu.addAction(interface_action)
        
        # View menu
        view_menu = menubar.addMenu("View")
        
        clear_action = QAction("Clear Display", self)
        clear_action.triggered.connect(self.clear_display)
        view_menu.addAction(clear_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        history_action = QAction("Capture History", self)
        history_action.triggered.connect(self.show_history)
        tools_menu.addAction(history_action)
        
        filter_examples_action = QAction("Filter Examples", self)
        filter_examples_action.triggered.connect(self.show_filter_examples)
        tools_menu.addAction(filter_examples_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About EtherEye", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def load_interfaces(self):
        """Load available network interfaces (SRS FU-01)"""
        self.interface_combo.clear()
        
        try:
            interfaces = self.capturer.list_interfaces()
            
            if not interfaces:
                self.update_status("No network interfaces found")
                return
            
            for iface in interfaces:
                display_text = f"{iface['name']} - {iface['ip']} ({iface['status']})"
                self.interface_combo.addItem(display_text, iface['name'])
            
            self.update_status(f"Found {len(interfaces)} interface(s)")
            
        except Exception as e:
            self.update_status(f"Error loading interfaces: {str(e)}")
            QMessageBox.critical(self, "Interface Error", 
                               f"Failed to load network interfaces:\n{str(e)}")
    
    def toggle_capture(self):
        """Toggle capture state (SRS FU-03)"""
        if self.capturing:
            self.stop_capture()
        else:
            self.start_capture()
    
    def start_capture(self):
        """Start packet capture (SRS FU-03)"""
        if self.capturing:
            return
        
        # Get selected interface
        if self.interface_combo.count() == 0:
            QMessageBox.warning(self, "No Interface", 
                              "No network interface selected.")
            return
        
        interface_index = self.interface_combo.currentIndex()
        interface_name = self.interface_combo.itemData(interface_index)
        
        if not interface_name:
            QMessageBox.warning(self, "Invalid Interface", 
                              "Please select a valid network interface.")
            return
        
        # Select interface
        if not self.capturer.select_interface(interface_name):
            QMessageBox.critical(self, "Interface Error", 
                               f"Failed to select interface: {interface_name}")
            return
        
        # Parse filter if any
        filter_str = self.filter_input.text().strip()
        bpf_filter = ""
        
        if filter_str:
            bpf_filter, error = self.filter_engine.parse_filter(filter_str)
            if error:
                QMessageBox.warning(self, "Filter Error", 
                                  f"Invalid filter: {error}")
                return
        
        # Create new session
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        self.current_session = CaptureSession(
            session_id=session_id,
            start_time=datetime.now(),
            interface=interface_name,
            filter_string=filter_str
        )
        
        # Clear display
        self.clear_display()
        self.decoder.packet_count = 0
        
        # Start capture worker
        self.capture_worker = CaptureWorker(self.capturer, self.decoder, bpf_filter)
        self.capture_worker.packet_received.connect(self.add_packet)
        self.capture_worker.status_update.connect(self.update_status)
        
        self.capturing = True
        self.capture_button.setText("Stop Capture")
        self.capture_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        self.update_status(f"Capturing on {interface_name}...")
        
        self.capture_worker.start()
    
    def stop_capture(self):
        """Stop packet capture (SRS FU-03, FU-08)"""
        if not self.capturing:
            return
        
        self.capturing = False
        self.capture_button.setText("Start Capture")
        self.capture_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        
        # Stop worker
        if self.capture_worker:
            self.capture_worker.stop()
            self.capture_worker = None
        
        # Update session end time
        if self.current_session:
            self.current_session.end_time = datetime.now()
            
            # Save to history (SRS FU-08)
            if self.current_session.packet_count > 0:
                self.save_session_to_history()
        
        self.update_status("Capture stopped")
    
    def add_packet(self, packet: Packet):
        """Add packet to display (SRS FU-04)"""
        if not self.current_session:
            return
        
        # Add to session
        self.current_session.add_packet(packet)
        
        # Add to packet list
        self.packet_list.add_packet(packet)
        
        # Update status
        self.packet_count_label.setText(f"Packets: {self.current_session.packet_count}")
        
        # Auto-select first packet
        if self.current_session.packet_count == 1:
            self.packet_list.selectRow(0)
            self.on_packet_selected()
    
    def on_packet_selected(self):
        """Handle packet selection (SRS FU-06)"""
        selected_items = self.packet_list.selectedItems()
        if not selected_items:
            print("DEBUG: No items selected")
            return
    
        row = selected_items[0].row()
        packet_number = int(self.packet_list.item(row, 0).text())
    
        print(f"DEBUG: Selected packet #{packet_number} from row {row}")
    
        # Find packet in current session
        if self.current_session:
            print(f"DEBUG: Current session has {len(self.current_session.packets)} packets")
        
            found = False
            for packet in self.current_session.packets:
                if packet.packet_number == packet_number:
                    print(f"DEBUG: Found packet! Protocol: {packet.protocol}")
                    print(f"DEBUG: Packet layers: {list(packet.layers.keys())}")
                    print(f"DEBUG: Raw data length: {len(packet.raw_data)}")
                
                    # Update detail tree
                    self.detail_tree.display_packet(packet)
                
                    # Update hex view
                    hex_data = self.decoder.get_packet_hex(packet)
                    print(f"DEBUG: Hex data generated: {len(hex_data)} chars")
                    self.hex_view.display_hex(hex_data)
                
                    found = True
                    break
        
            if not found:
                print(f"DEBUG: Packet #{packet_number} not found!")
        else:
            print("DEBUG: No current session!")
    
    def apply_filter(self):
        """Apply packet filter (SRS FU-07)"""
        filter_str = self.filter_input.text().strip()
        
        if not filter_str:
            self.clear_filter()
            return
        
        # Parse filter
        bpf_filter, error = self.filter_engine.parse_filter(filter_str)
        
        if error:
            QMessageBox.warning(self, "Filter Error", 
                              f"Invalid filter: {error}")
            return
        
        # If capturing, we need to restart with new filter
        if self.capturing:
            reply = QMessageBox.question(
                self, "Restart Capture",
                "Changing filter requires restarting capture. Stop and restart?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_capture()
                # Filter will be applied when starting new capture
                self.update_status(f"Filter applied: {filter_str}")
            return
        
        self.update_status(f"Filter set: {filter_str}")
    
    def clear_filter(self):
        """Clear current filter (SRS FU-07)"""
        self.filter_input.clear()
        
        if self.capturing:
            self.update_status("Note: Filter cleared but capture continues. Stop and restart to remove filter.")
        else:
            self.update_status("Filter cleared")
    
    def apply_capture_filter(self):
        """Apply capture filter (SRS FU-07)"""
        filter_str = self.filter_input.text().strip()
        
        if not filter_str:
            self.clear_capture_filter()
            return
        
        # Parse filter
        bpf_filter, error = self.filter_engine.parse_filter(filter_str)
        
        if error:
            QMessageBox.warning(self, "Filter Error", 
                              f"Invalid filter: {error}")
            return
        
        # If capturing, we need to restart with new filter
        if self.capturing:
            reply = QMessageBox.question(
                self, "Restart Capture",
                "Changing filter requires restarting capture. Stop and restart?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_capture()
                # Filter will be applied when starting new capture
                self.update_status(f"Capture filter applied: {filter_str}")
            return
        
        self.update_status(f"Capture filter set: {filter_str}")

    def clear_capture_filter(self):
        """Clear current capture filter"""
        self.filter_input.clear()
        
        if self.capturing:
            self.update_status("Note: Capture filter cleared but capture continues. Stop and restart to remove filter.")
        else:
            self.update_status("Capture filter cleared")

    def apply_display_filter(self):
        """Apply display filter to already captured packets"""
        filter_str = self.display_filter_input.text().strip()
    
        if not filter_str:
            self.clear_display_filter()
            return
    
        # Set display filter
        if self.display_filter.set_filter(filter_str):
            self.display_filter_active = True
            self.update_display_filtered_packets()
            self.update_status(f"Display filter applied: {filter_str}")
        else:
            QMessageBox.warning(self, "Filter Error", 
                          "Invalid display filter syntax")


    def clear_display_filter(self):
        """Clear display filter"""
        self.display_filter_input.clear()
        self.display_filter_active = False
        
        if self.current_session:
            # Reload all packets
            self.packet_list.clear()
            for packet in self.current_session.packets:
                self.packet_list.add_packet(packet)
        
        self.update_status("Display filter cleared")

    def update_display_filtered_packets(self):
        """Update displayed packets based on current display filter"""
        if not self.current_session or not self.display_filter_active:
            return
    
        # Get filtered packets
        filtered_packets = self.display_filter.filter_packets(self.current_session.packets)
    
        # Update packet list
        self.packet_list.clear()
        for packet in filtered_packets:
            self.packet_list.add_packet(packet)
    
        # Update packet count
        self.packet_count_label.setText(f"Packets: {len(filtered_packets)} (filtered from {self.current_session.packet_count})")

    def show_advanced_filter(self):
        """Show advanced filter dialog"""
        # Get current filter string
        current_filter = self.filter_input.text()
        
        dialog = AdvancedFilterDialog(self, current_filter)
        dialog.filter_applied.connect(self.apply_advanced_filter)
        dialog.exec()

    def apply_advanced_filter(self, filter_str: str):
        """Apply filter from advanced filter dialog"""
        if filter_str:
            self.filter_input.setText(filter_str)
            self.apply_capture_filter()
        else:
            self.clear_capture_filter()
    
    def save_session_to_history(self):
        """Save current session to history (SRS FU-08)"""
        if not self.current_session or self.current_session.packet_count == 0:
            return
        
        try:
            # Generate session name
            interface_name = self.current_session.interface
            packet_count = self.current_session.packet_count
            duration = (self.current_session.end_time - self.current_session.start_time).seconds
            
            session_name = f"Capture on {interface_name} - {packet_count} packets ({duration}s)"
            
            # Save to history
            success = self.history_manager.save_session(
                self.current_session,
                name=session_name,
                description=f"Captured {packet_count} packets on {interface_name}",
                tags=[interface_name]
            )
            
            if success:
                self.update_status(f"Session saved to history: {session_name}")
            else:
                self.update_status("Failed to save session to history")
                
        except Exception as e:
            print(f"Error saving session: {e}")
    
    def export_current_session(self):
        """Export current session (SRS FU-09)"""
        if not self.current_session or self.current_session.packet_count == 0:
            QMessageBox.warning(self, "No Session", 
                              "No capture session to export.")
            return
        
        # Open export dialog
        dialog = ExportDialog(self, self.current_session, self.exporter)
        dialog.exec()
    
    def show_history(self):
        """Show capture history dialog (SRS FU-08)"""
        dialog = HistoryDialog(self, self.history_manager, self.exporter)
        dialog.session_selected.connect(self.load_session_from_history)
        dialog.exec()
    
    def load_session_from_history(self, session: CaptureSession):
        """Load session from history"""
        # Clear current display
        self.clear_display()
        
        # Stop any active capture
        if self.capturing:
            self.stop_capture()
        
        # Load session
        self.current_session = session
        self.decoder.packet_count = 0
        
        # Add all packets to display
        for packet in session.packets:
            self.packet_list.add_packet(packet)
            self.decoder.packet_count += 1
        
        # Update status
        self.packet_count_label.setText(f"Packets: {session.packet_count}")
        self.update_status(f"Loaded session: {session.session_id[:8]}")
        
        # Select first packet
        if session.packet_count > 0:
            self.packet_list.selectRow(0)
            self.on_packet_selected()
    
    def clear_display(self):
        """Clear all displays"""
        self.packet_list.clear()
        self.detail_tree.clear()
        self.hex_view.clear()
        self.packet_count_label.setText("Packets: 0")
    
    def new_session(self):
        """Start a new capture session"""
        if self.capturing:
            reply = QMessageBox.question(
                self, "Stop Capture",
                "A capture is in progress. Stop and start new session?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_capture()
                self.clear_display()
                self.current_session = None
                self.update_status("New session ready")
        else:
            self.clear_display()
            self.current_session = None
            self.update_status("New session ready")
    
    def show_filter_examples(self):
        """Show filter examples"""
        examples = self.filter_engine.get_filter_examples()
        
        examples_text = "Filter Examples:\n\n"
        for example, description in examples:
            examples_text += f"• {example:30} - {description}\n"
        
        QMessageBox.information(self, "Filter Examples", examples_text)

    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        EtherEye - Network Packet Analyzer
        Version 1.0
    
        Features:
        • Network interface enumeration and selection
        • Real-time packet capture and display
        • Protocol decoding (Ethernet, IP, TCP, UDP, ICMP, ARP)
        • Packet filtering with BPF syntax
        • Capture session history with SQLite storage
        • Export to PCAP, CSV, JSON, and TXT formats
        
        Developed by:
        Aris Nur Rochman (2407421063)
        Dimas Ryan Yusuf (2407421073)
        Farel Fachrianza Hidayat (2407421083)
        
        Politeknik Negeri Jakarta
        2025
        """
        
        QMessageBox.about(self, "About EtherEye", about_text)
    
    def update_status(self, message: str):
        """Update status bar"""
        self.status_label.setText(message)
        print(f"Status: {message}")
    
    def closeEvent(self, event):
        """Handle application close"""
        if self.capturing:
            reply = QMessageBox.question(
                self, "Capture in Progress",
                "A capture is in progress. Stop and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.stop_capture()
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()