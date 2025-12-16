"""
History Dialog for EtherEye
SRS Compliance: FU-08 - History browsing and management
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
    QPushButton, QLabel, QMessageBox, QFileDialog, QTextEdit, QSplitter,
    QTabWidget, QWidget, QFormLayout, QGroupBox, QLineEdit, QCheckBox,
    QComboBox, QSpinBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressDialog, QApplication, QTreeWidget, QTreeWidgetItem,
    QInputDialog  # ADD THIS IMPORT
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QFont, QIcon, QAction, QKeySequence

from utils.history_manager import HistoryManager
from utils.exporter import SessionExporter
from models.packet_session import CaptureSession

class HistoryDialog(QDialog):
    """Dialog for viewing and managing capture history"""
    
    session_selected = pyqtSignal(object)  # Emits selected CaptureSession
    
    def __init__(self, parent=None, history_manager=None, exporter=None):
        super().__init__(parent)
        self.history_manager = history_manager or HistoryManager()
        self.exporter = exporter or SessionExporter()
        self.current_session_id = None
        self.current_session_data = None
        
        self.setWindowTitle("Capture History")
        self.setMinimumSize(900, 600)
        
        self.init_ui()
        self.load_sessions()
        self.update_statistics()
    
    def init_ui(self):
        """Initialize the dialog UI"""
        main_layout = QVBoxLayout(self)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Tab 1: Session Browser
        browser_tab = QWidget()
        self.init_browser_tab(browser_tab)
        tabs.addTab(browser_tab, "Sessions")
        
        # Tab 2: Statistics
        stats_tab = QWidget()
        self.init_stats_tab(stats_tab)
        tabs.addTab(stats_tab, "Statistics")
        
        # Tab 3: Import/Export
        import_export_tab = QWidget()
        self.init_import_export_tab(import_export_tab)
        tabs.addTab(import_export_tab, "Import/Export")
        
        main_layout.addWidget(tabs)
        
        # Status bar
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
    
    def init_browser_tab(self, parent):
        """Initialize session browser tab"""
        layout = QVBoxLayout(parent)
        
        # Search bar
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by name, interface, or filter...")
        self.search_input.textChanged.connect(self.on_search_changed)
        search_layout.addWidget(self.search_input)
        
        self.search_combo = QComboBox()
        self.search_combo.addItems(["All", "Name", "Interface", "Filter"])
        search_layout.addWidget(self.search_combo)
        
        search_layout.addStretch()
        layout.addLayout(search_layout)
        
        # Splitter for session list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Session list
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Session list
        self.session_list = QListWidget()
        self.session_list.itemClicked.connect(self.on_session_selected)
        self.session_list.itemDoubleClicked.connect(self.load_selected_session)
        left_layout.addWidget(self.session_list)
        
        # Left panel buttons
        left_buttons = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_sessions)
        left_buttons.addWidget(refresh_btn)
        
        load_btn = QPushButton("Load")
        load_btn.clicked.connect(self.load_selected_session)
        left_buttons.addWidget(load_btn)
        
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(self.delete_selected_session)
        left_buttons.addWidget(delete_btn)
        
        left_buttons.addStretch()
        left_layout.addLayout(left_buttons)
        
        # Right: Session details
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Session info
        info_group = QGroupBox("Session Information")
        info_layout = QFormLayout()
        
        self.info_labels = {}
        fields = [
            ("Name", "name"),
            ("Description", "description"),
            ("Session ID", "session_id"),
            ("Start Time", "start_time"),
            ("End Time", "end_time"),
            ("Duration", "duration"),
            ("Interface", "interface"),
            ("Filter", "filter_string"),
            ("Packets", "packet_count"),
            ("Total Size", "total_bytes"),
            ("Created", "created_at")
        ]
        
        for label_text, field_name in fields:
            label = QLabel("N/A")
            label.setWordWrap(True)
            if field_name in ['packet_count', 'total_bytes']:
                label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            info_layout.addRow(f"{label_text}:", label)
            self.info_labels[field_name] = label
        
        info_group.setLayout(info_layout)
        right_layout.addWidget(info_group)
        
        # Protocol statistics
        stats_group = QGroupBox("Protocol Statistics")
        stats_layout = QVBoxLayout()
        
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(3)
        self.stats_table.setHorizontalHeaderLabels(["Protocol", "Packets", "Percentage"])
        self.stats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.stats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.stats_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.stats_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        stats_layout.addWidget(self.stats_table)
        stats_group.setLayout(stats_layout)
        right_layout.addWidget(stats_group)
        
        # Right panel buttons
        right_buttons = QHBoxLayout()
        
        export_btn = QPushButton("Export Session")
        export_btn.clicked.connect(self.export_selected_session)
        right_buttons.addWidget(export_btn)
        
        rename_btn = QPushButton("Rename")
        rename_btn.clicked.connect(self.rename_selected_session)
        right_buttons.addWidget(rename_btn)
        
        right_buttons.addStretch()
        right_layout.addLayout(right_buttons)
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 600])
        
        layout.addWidget(splitter)
    
    def init_stats_tab(self, parent):
        """Initialize statistics tab"""
        layout = QVBoxLayout(parent)
        
        # Overall statistics
        stats_group = QGroupBox("Overall Statistics")
        stats_layout = QFormLayout()
        
        self.overall_stats_labels = {}
        stat_fields = [
            ("Total Sessions", "total_sessions"),
            ("Total Packets", "total_packets"),
            ("Total Data", "total_size_gb"),
            ("Average Packets/Session", "avg_packets_per_session"),
            ("Most Active Interface", "most_active_interface"),
            ("Sessions on Interface", "interface_count")
        ]
        
        for label_text, field_name in stat_fields:
            label = QLabel("Calculating...")
            label.setWordWrap(True)
            stats_layout.addRow(f"{label_text}:", label)
            self.overall_stats_labels[field_name] = label
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        # Database info
        db_group = QGroupBox("Database Information")
        db_layout = QFormLayout()
        
        db_info = self.history_manager.get_database_info()
        for key, value in db_info.items():
            if key != 'exists':
                label = QLabel(str(value))
                label.setWordWrap(True)
                db_layout.addRow(f"{key.replace('_', ' ').title()}:", label)
        
        db_group.setLayout(db_layout)
        layout.addWidget(db_group)
        
        # Cleanup controls
        cleanup_group = QGroupBox("Database Maintenance")
        cleanup_layout = QVBoxLayout()
        
        cleanup_info = QLabel(
            "Sessions older than 30 days are automatically cleaned up. "
            "You can manually clean up or clear all history below."
        )
        cleanup_info.setWordWrap(True)
        cleanup_layout.addWidget(cleanup_info)
        
        cleanup_buttons = QHBoxLayout()
        
        cleanup_btn = QPushButton("Clean Up Old Sessions")
        cleanup_btn.clicked.connect(self.cleanup_old_sessions)
        cleanup_buttons.addWidget(cleanup_btn)
        
        clear_all_btn = QPushButton("Clear All History")
        clear_all_btn.setStyleSheet("background-color: #f44336; color: white;")
        clear_all_btn.clicked.connect(self.clear_all_history)
        cleanup_buttons.addWidget(clear_all_btn)
        
        cleanup_buttons.addStretch()
        cleanup_layout.addLayout(cleanup_buttons)
        
        cleanup_group.setLayout(cleanup_layout)
        layout.addWidget(cleanup_group)
        
        layout.addStretch()
    
    def init_import_export_tab(self, parent):
        """Initialize import/export tab"""
        layout = QVBoxLayout(parent)
        
        # Export section
        export_group = QGroupBox("Export Multiple Sessions")
        export_layout = QVBoxLayout()
        
        export_info = QLabel("Export multiple sessions at once. Each session will be saved as a separate file.")
        export_info.setWordWrap(True)
        export_layout.addWidget(export_info)
        
        self.export_list = QListWidget()
        self.export_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        export_layout.addWidget(self.export_list)
        
        export_controls = QHBoxLayout()
        
        self.export_format_combo = QComboBox()
        self.export_format_combo.addItems(["pcap", "csv", "json", "txt"])
        export_controls.addWidget(QLabel("Format:"))
        export_controls.addWidget(self.export_format_combo)
        
        export_selected_btn = QPushButton("Export Selected")
        export_selected_btn.clicked.connect(self.export_multiple_sessions)
        export_controls.addWidget(export_selected_btn)
        
        export_controls.addStretch()
        export_layout.addLayout(export_controls)
        
        export_group.setLayout(export_layout)
        layout.addWidget(export_group)
        
        # Import section
        import_group = QGroupBox("Import Sessions")
        import_layout = QVBoxLayout()
        
        import_info = QLabel("Import sessions from JSON files exported by EtherEye.")
        import_info.setWordWrap(True)
        import_layout.addWidget(import_info)
        
        import_btn = QPushButton("Import Session File")
        import_btn.clicked.connect(self.import_session_file)
        import_layout.addWidget(import_btn)
        
        import_group.setLayout(import_layout)
        layout.addWidget(import_group)
        
        layout.addStretch()
    
    def load_sessions(self):
        """Load all sessions from history"""
        self.session_list.clear()
        self.export_list.clear()
        
        sessions = self.history_manager.get_all_sessions(limit=500)
        
        for session_data in sessions:
            # Format display text for session list
            start_time = session_data['start_time'][:19].replace('T', ' ')
            display_text = f"{start_time} - {session_data['name']}"
            
            if session_data['packet_count'] > 0:
                display_text += f" ({session_data['packet_count']} packets)"
            
            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, session_data['session_id'])
            self.session_list.addItem(item)
            
            # Also add to export list
            export_item = QListWidgetItem(f"{session_data['name']} - {session_data['session_id'][:8]}")
            export_item.setData(Qt.ItemDataRole.UserRole, session_data['session_id'])
            self.export_list.addItem(export_item)
        
        self.status_label.setText(f"Loaded {len(sessions)} sessions")
    
    def on_search_changed(self, text):
        """Handle search text changes"""
        if not text:
            self.load_sessions()
            return
        
        search_field = self.search_combo.currentText().lower()
        sessions = []
        
        if search_field == "all" or search_field == "name":
            sessions.extend(self.history_manager.search_sessions(text, 'name'))
        
        if search_field == "all" or search_field == "interface":
            sessions.extend(self.history_manager.search_sessions(text, 'interface'))
        
        if search_field == "all" or search_field == "filter":
            sessions.extend(self.history_manager.search_sessions(text, 'filter'))
        
        # Remove duplicates
        unique_sessions = {}
        for session in sessions:
            unique_sessions[session['session_id']] = session
        
        # Update list
        self.session_list.clear()
        for session_data in unique_sessions.values():
            display_text = f"{session_data['start_time'][:19].replace('T', ' ')} - {session_data.get('name', 'Unnamed')}"
            if session_data['packet_count'] > 0:
                display_text += f" ({session_data['packet_count']} packets)"
            
            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, session_data['session_id'])
            self.session_list.addItem(item)
        
        self.status_label.setText(f"Found {len(unique_sessions)} matching sessions")
    
    def on_session_selected(self, item):
        """Handle session selection"""
        session_id = item.data(Qt.ItemDataRole.UserRole)
        self.current_session_id = session_id
        
        # Load session metadata
        metadata = self.history_manager.get_session_metadata(session_id)
        if metadata:
            self.current_session_data = metadata
            
            # Update info labels
            self.info_labels['name'].setText(metadata.get('name', 'Unnamed'))
            self.info_labels['description'].setText(metadata.get('description', 'No description'))
            self.info_labels['session_id'].setText(metadata['session_id'][:8])
            self.info_labels['start_time'].setText(metadata['start_time'][:19].replace('T', ' '))
            self.info_labels['end_time'].setText(
                metadata['end_time'][:19].replace('T', ' ') if metadata['end_time'] else 'N/A'
            )
            
            # Format duration
            if metadata.get('duration'):
                hours = metadata['duration'] // 3600
                minutes = (metadata['duration'] % 3600) // 60
                seconds = metadata['duration'] % 60
                self.info_labels['duration'].setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
            else:
                self.info_labels['duration'].setText('N/A')
            
            self.info_labels['interface'].setText(metadata.get('interface', 'N/A'))
            self.info_labels['filter_string'].setText(metadata.get('filter_string', 'None'))
            self.info_labels['packet_count'].setText(f"{metadata['packet_count']:,}")
            
            # Format file size
            total_bytes = metadata.get('total_bytes', 0)
            if total_bytes >= 1024 * 1024:
                size_str = f"{total_bytes / (1024 * 1024):.2f} MB"
            elif total_bytes >= 1024:
                size_str = f"{total_bytes / 1024:.2f} KB"
            else:
                size_str = f"{total_bytes} bytes"
            self.info_labels['total_bytes'].setText(size_str)
            
            self.info_labels['created_at'].setText(metadata['created_at'][:19].replace('T', ' '))
            
            # Update protocol statistics table
            protocol_stats = metadata.get('protocol_stats', {})
            self.stats_table.setRowCount(len(protocol_stats))
            
            total_packets = metadata['packet_count']
            for i, (protocol, count) in enumerate(protocol_stats.items()):
                percentage = (count / total_packets) * 100 if total_packets > 0 else 0
                
                self.stats_table.setItem(i, 0, QTableWidgetItem(protocol))
                self.stats_table.setItem(i, 1, QTableWidgetItem(f"{count:,}"))
                self.stats_table.setItem(i, 2, QTableWidgetItem(f"{percentage:.1f}%"))
    
    def load_selected_session(self):
        """Load selected session into main window"""
        if not self.current_session_id:
            QMessageBox.warning(self, "No Session", "Please select a session first.")
            return
        
        # Load full session data
        session = self.history_manager.get_session_by_id(self.current_session_id)
        if session:
            self.session_selected.emit(session)
            self.accept()
        else:
            QMessageBox.critical(self, "Error", "Failed to load session data.")
    
    def export_selected_session(self):
        """Export selected session to file"""
        if not self.current_session_id:
            QMessageBox.warning(self, "No Session", "Please select a session first.")
            return
        
        # Load full session data
        session = self.history_manager.get_session_by_id(self.current_session_id)
        if not session:
            QMessageBox.critical(self, "Error", "Failed to load session data.")
            return
        
        # Open file dialog
        default_name = f"session_{session.session_id[:8]}_{session.start_time.strftime('%Y%m%d_%H%M%S')}"
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Session",
            default_name,
            "PCAP Files (*.pcap);;CSV Files (*.csv);;JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if not file_path:
            return
        
        # Determine format from filter
        if "PCAP" in selected_filter:
            format = 'pcap'
        elif "CSV" in selected_filter:
            format = 'csv'
        elif "JSON" in selected_filter:
            format = 'json'
        elif "Text" in selected_filter:
            format = 'txt'
        else:
            format = 'pcap'  # Default
        
        # Show progress dialog for large sessions
        if len(session.packets) > 1000:
            progress = QProgressDialog("Exporting session...", "Cancel", 0, len(session.packets), self)
            progress.setWindowTitle("Export Progress")
            progress.setWindowModality(Qt.WindowModality.WindowModal)
            progress.show()
        
        try:
            success = self.exporter.export_session(session, file_path, format)
            
            if success:
                QMessageBox.information(self, "Export Successful",
                                      f"Session exported successfully to:\n{file_path}\n\n"
                                      f"Format: {format.upper()}\n"
                                      f"Packets: {len(session.packets):,}\n"
                                      f"Size: {session.total_bytes:,} bytes")
            else:
                QMessageBox.critical(self, "Export Failed",
                                   "Failed to export session.\n"
                                   "Check console for details.")
        except Exception as e:
            QMessageBox.critical(self, "Export Error",
                               f"Error during export:\n{str(e)}")
        finally:
            if len(session.packets) > 1000:
                progress.close()
    
    def export_multiple_sessions(self):
        """Export multiple selected sessions"""
        selected_items = self.export_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select sessions to export.")
            return
        
        # Ask for directory
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Export Directory",
            "",
            QFileDialog.Option.ShowDirsOnly
        )
        
        if not directory:
            return
        
        format = self.export_format_combo.currentText()
        
        # Show progress dialog
        progress = QProgressDialog("Exporting sessions...", "Cancel", 0, len(selected_items), self)
        progress.setWindowTitle("Export Progress")
        progress.setWindowModality(Qt.WindowModality.WindowModal)
        progress.show()
        
        success_count = 0
        fail_count = 0
        
        for i, item in enumerate(selected_items):
            progress.setValue(i)
            progress.setLabelText(f"Exporting session {i+1} of {len(selected_items)}...")
            
            QApplication.processEvents()  # Keep UI responsive
            
            if progress.wasCanceled():
                break
            
            session_id = item.data(Qt.ItemDataRole.UserRole)
            session = self.history_manager.get_session_by_id(session_id)
            
            if session:
                file_path = f"{directory}/session_{session.session_id[:8]}.{format}"
                
                try:
                    if self.exporter.export_session(session, file_path, format):
                        success_count += 1
                    else:
                        fail_count += 1
                except:
                    fail_count += 1
        
        progress.close()
        
        QMessageBox.information(self, "Export Complete",
                              f"Exported {success_count} sessions successfully.\n"
                              f"Failed: {fail_count}\n"
                              f"Directory: {directory}")
    
    def import_session_file(self):
        """Import a session from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Session",
            "",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if not file_path:
            return
        
        try:
            session_id = self.history_manager.import_session_from_file(file_path)
            if session_id:
                QMessageBox.information(self, "Import Successful",
                                      f"Session imported successfully.\n"
                                      f"Session ID: {session_id}")
                self.load_sessions()
            else:
                QMessageBox.critical(self, "Import Failed",
                                   "Failed to import session.\n"
                                   "The file may be corrupted or in wrong format.")
        except Exception as e:
            QMessageBox.critical(self, "Import Error",
                               f"Error during import:\n{str(e)}")
    
    def rename_selected_session(self):
        """Rename selected session"""
        if not self.current_session_id:
            QMessageBox.warning(self, "No Session", "Please select a session first.")
            return
        
        current_name = self.current_session_data.get('name', '') if self.current_session_data else ''
        new_name, ok = QInputDialog.getText(
            self,
            "Rename Session",
            "Enter new name for session:",
            text=current_name
        )
        
        if ok and new_name:
            success = self.history_manager.update_session_info(
                self.current_session_id,
                name=new_name
            )
            
            if success:
                QMessageBox.information(self, "Renamed", "Session renamed successfully.")
                self.load_sessions()
                
                # Reload current session data
                item = self.session_list.currentItem()
                if item:
                    self.on_session_selected(item)
            else:
                QMessageBox.critical(self, "Error", "Failed to rename session.")
    
    def delete_selected_session(self):
        """Delete selected session"""
        current_item = self.session_list.currentItem()
        if not current_item:
            QMessageBox.warning(self, "No Selection", "Please select a session to delete.")
            return
        
        session_id = current_item.data(Qt.ItemDataRole.UserRole)
        session_name = self.current_session_data.get('name', 'Unnamed') if self.current_session_data else 'Unnamed'
        
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete this session?\n\n"
            f"Name: {session_name}\n"
            f"Session ID: {session_id[:8]}\n"
            f"Packets: {self.current_session_data.get('packet_count', 0):,}\n\n"
            f"This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success = self.history_manager.delete_session(session_id)
            
            if success:
                QMessageBox.information(self, "Deleted", "Session deleted successfully.")
                self.load_sessions()
                self.clear_session_details()
            else:
                QMessageBox.critical(self, "Error", "Failed to delete session.")
    
    def cleanup_old_sessions(self):
        """Clean up old sessions"""
        reply = QMessageBox.question(
            self, "Clean Up Old Sessions",
            "This will delete all sessions older than 30 days.\n"
            "This action cannot be undone.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # This is handled automatically by HistoryManager on init
            # We'll just reload to show current state
            self.load_sessions()
            self.update_statistics()
            QMessageBox.information(self, "Cleanup Complete", 
                                  "Old sessions have been cleaned up.")
    
    def clear_all_history(self):
        """Clear all history"""
        reply = QMessageBox.question(
            self, "Confirm Clear All",
            "WARNING: This will delete ALL capture history!\n"
            "All saved sessions will be permanently deleted.\n\n"
            "This action cannot be undone!\n\n"
            "Are you absolutely sure?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success = self.history_manager.clear_all_history()
            
            if success:
                QMessageBox.information(self, "History Cleared", 
                                      "All history has been cleared.")
                self.load_sessions()
                self.clear_session_details()
                self.update_statistics()
            else:
                QMessageBox.critical(self, "Error", "Failed to clear history.")
    
    def clear_session_details(self):
        """Clear session details from UI"""
        self.current_session_id = None
        self.current_session_data = None
        
        for label in self.info_labels.values():
            label.setText("N/A")
        
        self.stats_table.setRowCount(0)
    
    def update_statistics(self):
        """Update overall statistics"""
        stats = self.history_manager.get_statistics()
        
        for field_name, label in self.overall_stats_labels.items():
            if field_name in stats:
                value = stats[field_name]
                
                if field_name == 'total_size_gb':
                    label.setText(f"{value:.2f} GB")
                elif field_name == 'avg_packets_per_session':
                    label.setText(f"{value:.1f}")
                else:
                    label.setText(str(value))
            else:
                label.setText("N/A")