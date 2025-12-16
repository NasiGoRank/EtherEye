"""
Export Dialog for EtherEye
SRS Compliance: FU-09 - Export functionality
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QMessageBox,
    QFileDialog, QGroupBox, QFormLayout, QComboBox, QCheckBox, QLineEdit,
    QSpinBox, QProgressDialog, QApplication
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from utils.exporter import SessionExporter
from models.packet_session import CaptureSession

class ExportWorker(QThread):
    """Worker thread for export operations"""
    
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)
    
    def __init__(self, session, file_path, format, include_payload=True):
        super().__init__()
        self.session = session
        self.file_path = file_path
        self.format = format
        self.include_payload = include_payload
        self.exporter = SessionExporter()
    
    def run(self):
        try:
            success = self.exporter.export_session(
                self.session, 
                self.file_path, 
                self.format,
                self.include_payload
            )
            
            if success:
                self.finished.emit(True, f"Session exported successfully to:\n{self.file_path}")
            else:
                self.finished.emit(False, "Failed to export session.")
                
        except Exception as e:
            self.finished.emit(False, f"Error during export:\n{str(e)}")

class ExportDialog(QDialog):
    """Dialog for exporting capture sessions"""
    
    def __init__(self, parent=None, session=None, exporter=None):
        super().__init__(parent)
        self.session = session
        self.exporter = exporter or SessionExporter()
        self.worker = None
        
        self.setWindowTitle("Export Capture Session")
        self.setMinimumWidth(500)
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the dialog UI"""
        layout = QVBoxLayout(self)
        
        # Session info
        info_group = QGroupBox("Session Information")
        info_layout = QFormLayout()
        
        if self.session:
            info_layout.addRow("Session ID:", QLabel(self.session.session_id[:8]))
            info_layout.addRow("Start Time:", QLabel(self.session.start_time.strftime('%Y-%m-%d %H:%M:%S')))
            info_layout.addRow("Interface:", QLabel(self.session.interface))
            info_layout.addRow("Filter:", QLabel(self.session.filter_string or "None"))
            info_layout.addRow("Packets:", QLabel(f"{len(self.session.packets):,}"))
            info_layout.addRow("Total Size:", QLabel(f"{self.session.total_bytes:,} bytes"))
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Export settings
        settings_group = QGroupBox("Export Settings")
        settings_layout = QFormLayout()
        
        # Format selection
        self.format_combo = QComboBox()
        for fmt_key, fmt_info in self.exporter.get_supported_formats().items():
            self.format_combo.addItem(f"{fmt_info['name']} ({fmt_info['description']})", fmt_key)
        settings_layout.addRow("Format:", self.format_combo)
        
        # File path
        path_layout = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setReadOnly(True)
        path_layout.addWidget(self.path_input)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_file)
        path_layout.addWidget(browse_btn)
        settings_layout.addRow("File:", path_layout)
        
        # Options
        self.include_payload_check = QCheckBox("Include packet payload data")
        self.include_payload_check.setChecked(True)
        settings_layout.addRow("Options:", self.include_payload_check)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        export_btn = QPushButton("Export")
        export_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        export_btn.clicked.connect(self.start_export)
        button_layout.addWidget(export_btn)
        
        layout.addLayout(button_layout)
        
        # Set default file path
        self.update_default_path()
    
    def browse_file(self):
        """Open file dialog to choose export location"""
        format_key = self.format_combo.currentData()
        format_info = self.exporter.get_supported_formats()[format_key]
        
        default_name = f"capture_{self.session.start_time.strftime('%Y%m%d_%H%M%S')}{format_info['extension']}"
        
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            f"Export as {format_info['name']}",
            default_name,
            f"{format_info['name']} Files (*{format_info['extension']});;All Files (*)"
        )
        
        if file_path:
            self.path_input.setText(file_path)
    
    def update_default_path(self):
        """Update default file path based on selected format"""
        format_key = self.format_combo.currentData()
        format_info = self.exporter.get_supported_formats()[format_key]
        
        default_name = f"capture_{self.session.start_time.strftime('%Y%m%d_%H%M%S')}{format_info['extension']}"
        self.path_input.setText(default_name)
    
    def start_export(self):
        """Start the export process"""
        file_path = self.path_input.text().strip()
        if not file_path:
            QMessageBox.warning(self, "No File", "Please select a file path.")
            return
        
        format_key = self.format_combo.currentData()
        include_payload = self.include_payload_check.isChecked()
        
        # Validate path
        is_valid, message = self.exporter.validate_export_path(file_path, format_key)
        if not is_valid:
            QMessageBox.warning(self, "Invalid Path", message)
            return
        
        # Show progress dialog for large sessions
        if len(self.session.packets) > 1000:
            self.progress_dialog = QProgressDialog(
                "Exporting session...", 
                "Cancel", 
                0, 
                len(self.session.packets), 
                self
            )
            self.progress_dialog.setWindowTitle("Export Progress")
            self.progress_dialog.setWindowModality(Qt.WindowModality.WindowModal)
            self.progress_dialog.show()
        
        # Create and start worker thread
        self.worker = ExportWorker(self.session, file_path, format_key, include_payload)
        self.worker.finished.connect(self.export_finished)
        self.worker.start()
    
    def export_finished(self, success, message):
        """Handle export completion"""
        # Close progress dialog if it exists
        if hasattr(self, 'progress_dialog'):
            self.progress_dialog.close()
        
        if success:
            QMessageBox.information(self, "Export Successful", message)
            self.accept()
        else:
            QMessageBox.critical(self, "Export Failed", message)