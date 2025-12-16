"""
Advanced Filter Dialog for EtherEye
Allows complex filtering of packets
"""

from PyQt6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QGroupBox,
    QFormLayout,
    QLineEdit,
    QComboBox,
    QCheckBox,
    QSpinBox,
    QTabWidget,
    QWidget,
    QMessageBox,
    QListWidget,
    QListWidgetItem,
    QApplication,
    QTextEdit,  # ADDED
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont  # ADDED
from PyQt6.QtWidgets import QSizePolicy  # ADDED


class AdvancedFilterDialog(QDialog):
    """Dialog for advanced packet filtering"""

    filter_applied = pyqtSignal(str)  # Emits filter string

    def __init__(self, parent=None, current_filter=""):
        super().__init__(parent)
        self.setWindowTitle("Advanced Filter")
        self.setMinimumWidth(600)
        self.setMinimumHeight(500)

        self.current_filter = current_filter
        self.init_ui()
        self.load_current_filter()

    def init_ui(self):
        """Initialize the dialog UI"""
        layout = QVBoxLayout(self)

        # Create tab widget
        tabs = QTabWidget()

        # Tab 1: Basic Filters
        basic_tab = QWidget()
        self.init_basic_tab(basic_tab)
        tabs.addTab(basic_tab, "Basic")

        # Tab 2: Protocol Filters
        protocol_tab = QWidget()
        self.init_protocol_tab(protocol_tab)
        tabs.addTab(protocol_tab, "Protocols")

        # Tab 3: Port Filters
        port_tab = QWidget()
        self.init_port_tab(port_tab)
        tabs.addTab(port_tab, "Ports")

        # Tab 4: Advanced Syntax
        syntax_tab = QWidget()
        self.init_syntax_tab(syntax_tab)
        tabs.addTab(syntax_tab, "BPF Syntax")

        layout.addWidget(tabs)

        # Filter preview
        preview_group = QGroupBox("Filter Preview")
        preview_layout = QVBoxLayout()

        self.preview_label = QLabel("No filter")
        self.preview_label.setWordWrap(True)
        self.preview_label.setStyleSheet(
            """
            QLabel {
                background-color: #2d2d2d;
                padding: 10px;
                border: 1px solid #555555;
                border-radius: 3px;
                font-family: monospace;
            }
        """
        )
        preview_layout.addWidget(self.preview_label)

        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(clear_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        apply_btn = QPushButton("Apply Filter")
        apply_btn.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold;"
        )
        apply_btn.clicked.connect(self.apply_filter)
        button_layout.addWidget(apply_btn)

        layout.addLayout(button_layout)

    def init_basic_tab(self, parent):
        """Initialize basic filter tab"""
        layout = QVBoxLayout(parent)

        # IP Filters
        ip_group = QGroupBox("IP Address Filters")
        ip_layout = QFormLayout()

        self.src_ip_input = QLineEdit()
        self.src_ip_input.setPlaceholderText("e.g., 192.168.1.1")
        self.src_ip_input.textChanged.connect(self.update_preview)
        ip_layout.addRow("Source IP:", self.src_ip_input)

        self.dst_ip_input = QLineEdit()
        self.dst_ip_input.setPlaceholderText("e.g., 192.168.1.100")
        self.dst_ip_input.textChanged.connect(self.update_preview)
        ip_layout.addRow("Destination IP:", self.dst_ip_input)

        self.host_ip_input = QLineEdit()
        self.host_ip_input.setPlaceholderText("e.g., 192.168.1.1")
        self.host_ip_input.textChanged.connect(self.update_preview)
        ip_layout.addRow("Host (Src or Dst):", self.host_ip_input)

        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group)

        # Network Range
        net_group = QGroupBox("Network Range")
        net_layout = QFormLayout()

        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("e.g., 192.168.1.0/24")
        self.network_input.textChanged.connect(self.update_preview)
        net_layout.addRow("Network:", self.network_input)

        net_group.setLayout(net_layout)
        layout.addWidget(net_group)

        layout.addStretch()

    def init_protocol_tab(self, parent):
        """Initialize protocol filter tab"""
        layout = QVBoxLayout(parent)

        # Protocol checkboxes
        proto_group = QGroupBox("Protocols")
        proto_layout = QFormLayout()

        self.tcp_check = QCheckBox("TCP")
        self.tcp_check.stateChanged.connect(self.update_preview)
        proto_layout.addRow("TCP:", self.tcp_check)

        self.udp_check = QCheckBox("UDP")
        self.udp_check.stateChanged.connect(self.update_preview)
        proto_layout.addRow("UDP:", self.udp_check)

        self.icmp_check = QCheckBox("ICMP")
        self.icmp_check.stateChanged.connect(self.update_preview)
        proto_layout.addRow("ICMP:", self.icmp_check)

        self.arp_check = QCheckBox("ARP")
        self.arp_check.stateChanged.connect(self.update_preview)
        proto_layout.addRow("ARP:", self.arp_check)

        self.http_check = QCheckBox("HTTP (port 80)")
        self.http_check.stateChanged.connect(self.update_preview)
        proto_layout.addRow("HTTP:", self.http_check)

        self.https_check = QCheckBox("HTTPS (port 443)")
        self.https_check.stateChanged.connect(self.update_preview)
        proto_layout.addRow("HTTPS:", self.https_check)

        self.dns_check = QCheckBox("DNS (port 53)")
        self.dns_check.stateChanged.connect(self.update_preview)
        proto_layout.addRow("DNS:", self.dns_check)

        self.ssh_check = QCheckBox("SSH (port 22)")
        self.ssh_check.stateChanged.connect(self.update_preview)
        proto_layout.addRow("SSH:", self.ssh_check)

        proto_group.setLayout(proto_layout)
        layout.addWidget(proto_group)

        # Custom protocol
        custom_group = QGroupBox("Custom Protocol")
        custom_layout = QFormLayout()

        self.custom_proto_input = QLineEdit()
        self.custom_proto_input.setPlaceholderText("e.g., tcp, udp, icmp")
        self.custom_proto_input.textChanged.connect(self.update_preview)
        custom_layout.addRow("Protocol:", self.custom_proto_input)

        custom_group.setLayout(custom_layout)
        layout.addWidget(custom_group)

        layout.addStretch()

    def init_port_tab(self, parent):
        """Initialize port filter tab"""
        layout = QVBoxLayout(parent)

        # Port Filters
        port_group = QGroupBox("Port Filters")
        port_layout = QFormLayout()

        self.src_port_input = QLineEdit()
        self.src_port_input.setPlaceholderText("e.g., 80, 443, 22")
        self.src_port_input.textChanged.connect(self.update_preview)
        port_layout.addRow("Source Port:", self.src_port_input)

        self.dst_port_input = QLineEdit()
        self.dst_port_input.setPlaceholderText("e.g., 80, 443, 22")
        self.dst_port_input.textChanged.connect(self.update_preview)
        port_layout.addRow("Destination Port:", self.dst_port_input)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("e.g., 80 (src or dst)")
        self.port_input.textChanged.connect(self.update_preview)
        port_layout.addRow("Port (Src or Dst):", self.port_input)

        port_group.setLayout(port_layout)
        layout.addWidget(port_group)

        # Port Range
        range_group = QGroupBox("Port Range")
        range_layout = QFormLayout()

        self.port_range_min = QSpinBox()
        self.port_range_min.setRange(1, 65535)
        self.port_range_min.setValue(1)
        self.port_range_min.valueChanged.connect(self.update_preview)
        range_layout.addRow("From Port:", self.port_range_min)

        self.port_range_max = QSpinBox()
        self.port_range_max.setRange(1, 65535)
        self.port_range_max.setValue(1024)
        self.port_range_max.valueChanged.connect(self.update_preview)
        range_layout.addRow("To Port:", self.port_range_max)

        range_group.setLayout(range_layout)
        layout.addWidget(range_group)

        layout.addStretch()

    def init_syntax_tab(self, parent):
        """Initialize BPF syntax tab"""
        layout = QVBoxLayout(parent)

        # BPF examples
        examples_group = QGroupBox("BPF Filter Examples")
        examples_layout = QVBoxLayout()

        # Use a plain text widget for better text handling
        examples_text = QTextEdit()
        examples_text.setReadOnly(True)
        examples_text.setMaximumHeight(300)
        examples_text.setStyleSheet(
            """
            QTextEdit {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #555555;
                font-family: Consolas, Monaco, monospace;
                font-size: 11px;
                padding: 10px;
            }
        """
        )

        # Build examples text
        examples_content = "Common BPF Filter Examples:\n\n"
        examples_list = [
            ("tcp and port 80", "HTTP traffic"),
            ("udp and port 53", "DNS traffic"),
            ("icmp", "Ping packets"),
            ("arp", "ARP packets"),
            ("host 192.168.1.1", "Traffic to/from specific host"),
            ("net 192.168.1.0/24", "Traffic within network"),
            ("src host 192.168.1.1", "Traffic from source"),
            ("dst host 192.168.1.100", "Traffic to destination"),
            ("port 443", "HTTPS traffic"),
            ("tcp[13] & 2 != 0", "TCP SYN packets"),
            ("tcp[13] & 4 != 0", "TCP RST packets"),
            ("tcp[13] & 16 != 0", "TCP ACK packets"),
            ("greater 100", "Packets larger than 100 bytes"),
            ("less 100", "Packets smaller than 100 bytes"),
            ("ip broadcast", "Broadcast packets"),
            ("ether proto 0x0806", "ARP packets (Ethernet protocol)"),
            ("ip proto 1", "ICMP packets (IP protocol)"),
        ]

        for filter_str, description in examples_list:
            examples_content += f"• {filter_str:40} - {description}\n"

        examples_text.setPlainText(examples_content)
        examples_layout.addWidget(examples_text)

        examples_group.setLayout(examples_layout)
        layout.addWidget(examples_group)

        # Custom BPF input
        custom_group = QGroupBox("Custom BPF Filter")
        custom_layout = QVBoxLayout()

        self.custom_bpf_input = QLineEdit()
        self.custom_bpf_input.setPlaceholderText("Enter custom BPF filter...")
        self.custom_bpf_input.textChanged.connect(self.update_preview)

        # Set monospace font for better BPF readability
        font = QFont("Monospace")
        font.setPointSize(10)
        self.custom_bpf_input.setFont(font)

        custom_layout.addWidget(self.custom_bpf_input)
        custom_group.setLayout(custom_layout)
        layout.addWidget(custom_group)

        layout.addStretch()

    def load_current_filter(self):
        """Load current filter into the dialog"""
        if self.current_filter:
            self.custom_bpf_input.setText(self.current_filter)
            self.update_preview()

    def update_preview(self):
        """Update filter preview based on current selections"""
        filter_parts = []

        # Check custom BPF first
        custom_bpf = self.custom_bpf_input.text().strip()
        if custom_bpf:
            filter_parts.append(custom_bpf)
        else:
            # Build filter from UI elements
            filter_parts.extend(self.get_ip_filters())
            filter_parts.extend(self.get_protocol_filters())
            filter_parts.extend(self.get_port_filters())

        # Combine all parts with 'and'
        if filter_parts:
            filter_str = " and ".join(filter_parts)
            self.preview_label.setText(filter_str)
        else:
            self.preview_label.setText("No filter")

    def get_ip_filters(self):
        """Get IP address filters"""
        filters = []

        # Source IP
        src_ip = self.src_ip_input.text().strip()
        if src_ip:
            filters.append(f"src host {src_ip}")

        # Destination IP
        dst_ip = self.dst_ip_input.text().strip()
        if dst_ip:
            filters.append(f"dst host {dst_ip}")

        # Host (src or dst)
        host_ip = self.host_ip_input.text().strip()
        if host_ip:
            filters.append(f"host {host_ip}")

        # Network
        network = self.network_input.text().strip()
        if network:
            filters.append(f"net {network}")

        return filters

    def get_protocol_filters(self):
        """Get protocol filters"""
        filters = []

        # Protocol checkboxes
        if self.tcp_check.isChecked():
            filters.append("tcp")
        if self.udp_check.isChecked():
            filters.append("udp")
        if self.icmp_check.isChecked():
            filters.append("icmp")
        if self.arp_check.isChecked():
            filters.append("arp")
        if self.http_check.isChecked():
            filters.append("tcp port 80")
        if self.https_check.isChecked():
            filters.append("tcp port 443")
        if self.dns_check.isChecked():
            filters.append("udp port 53 or tcp port 53")
        if self.ssh_check.isChecked():
            filters.append("tcp port 22")

        # Custom protocol
        custom_proto = self.custom_proto_input.text().strip()
        if custom_proto:
            filters.append(custom_proto)

        return filters

    def get_port_filters(self):
        """Get port filters"""
        filters = []

        # Source port
        src_port = self.src_port_input.text().strip()
        if src_port:
            filters.append(f"src port {src_port}")

        # Destination port
        dst_port = self.dst_port_input.text().strip()
        if dst_port:
            filters.append(f"dst port {dst_port}")

        # Port (src or dst)
        port = self.port_input.text().strip()
        if port:
            filters.append(f"port {port}")

        # Port range
        port_min = self.port_range_min.value()
        port_max = self.port_range_max.value()
        if port_min > 1 or port_max < 65535:
            filters.append(f"portrange {port_min}-{port_max}")

        return filters

    def clear_all(self):
        """Clear all filter inputs"""
        # Clear all inputs
        for widget in self.findChildren(QLineEdit):
            widget.clear()

        for widget in self.findChildren(QCheckBox):
            widget.setChecked(False)

        for widget in self.findChildren(QSpinBox):
            widget.setValue(widget.minimum())

        self.custom_bpf_input.clear()
        self.update_preview()

    def apply_filter(self):
        """Apply the filter"""
        filter_parts = []

        # Check custom BPF first
        custom_bpf = self.custom_bpf_input.text().strip()
        if custom_bpf:
            filter_str = custom_bpf
        else:
            # Build filter from UI elements
            filter_parts.extend(self.get_ip_filters())
            filter_parts.extend(self.get_protocol_filters())
            filter_parts.extend(self.get_port_filters())

            if filter_parts:
                filter_str = " and ".join(filter_parts)
            else:
                filter_str = ""

        self.filter_applied.emit(filter_str)
        self.accept()
