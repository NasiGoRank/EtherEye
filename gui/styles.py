"""
Dark Grey CSS styles for EtherEye UI
"""

STYLESHEET = """
/* ===== MAIN WINDOW ===== */
QMainWindow {
    background-color: #1e1e1e;
}

/* ===== WIDGET BACKGROUNDS ===== */
QWidget {
    background-color: #2d2d2d;
    color: #e0e0e0;
}

/* ===== BUTTONS ===== */
QPushButton {
    background-color: #3d3d3d;
    color: #e0e0e0;
    border: 1px solid #555555;
    padding: 6px 12px;
    border-radius: 3px;
    font-weight: normal;
    min-width: 70px;
}

QPushButton:hover {
    background-color: #4a4a4a;
    border-color: #666666;
}

QPushButton:pressed {
    background-color: #333333;
    border-color: #444444;
}

QPushButton:disabled {
    background-color: #2a2a2a;
    color: #666666;
    border-color: #444444;
}

/* Start/Stop capture buttons */
QPushButton#startButton {
    background-color: #2e7d32;  /* Dark green */
    border-color: #4caf50;
}

QPushButton#startButton:hover {
    background-color: #388e3c;
    border-color: #66bb6a;
}

QPushButton#stopButton {
    background-color: #c62828;  /* Dark red */
    border-color: #f44336;
}

QPushButton#stopButton:hover {
    background-color: #d32f2f;
    border-color: #ef5350;
}

/* ===== TOOLBAR ===== */
QToolBar {
    background-color: #252525;
    border-bottom: 1px solid #3d3d3d;
    spacing: 5px;
    padding: 3px;
}

QToolBar QLabel {
    color: #b0b0b0;
    font-weight: normal;
}

/* ===== COMBO BOXES ===== */
QComboBox {
    background-color: #3d3d3d;
    color: #e0e0e0;
    border: 1px solid #555555;
    border-radius: 3px;
    padding: 5px;
    min-width: 150px;
}

QComboBox:hover {
    border-color: #666666;
}

QComboBox::drop-down {
    border: none;
    background-color: #4a4a4a;
}

QComboBox::down-arrow {
    width: 12px;
    height: 12px;
    image: url(down_arrow_light.png);
}

QComboBox QAbstractItemView {
    background-color: #3d3d3d;
    color: #e0e0e0;
    border: 1px solid #555555;
    selection-background-color: #4a4a4a;
    selection-color: #ffffff;
}

/* ===== LINE EDITS ===== */
QLineEdit {
    background-color: #3d3d3d;
    color: #e0e0e0;
    border: 1px solid #555555;
    border-radius: 3px;
    padding: 5px;
}

QLineEdit:focus {
    border: 1px solid #666666;
    background-color: #424242;
}

QLineEdit::placeholder {
    color: #888888;
}

/* ===== STATUS BAR ===== */
QStatusBar {
    background-color: #252525;
    color: #b0b0b0;
    border-top: 1px solid #3d3d3d;
}

/* ===== MENU BAR ===== */
QMenuBar {
    background-color: #252525;
    color: #e0e0e0;
    border-bottom: 1px solid #3d3d3d;
}

QMenuBar::item {
    background-color: transparent;
    padding: 5px 10px;
}

QMenuBar::item:selected {
    background-color: #3d3d3d;
}

QMenuBar::item:pressed {
    background-color: #4a4a4a;
}

/* ===== MENUS ===== */
QMenu {
    background-color: #3d3d3d;
    color: #e0e0e0;
    border: 1px solid #555555;
}

QMenu::item {
    padding: 5px 20px 5px 20px;
}

QMenu::item:selected {
    background-color: #4a4a4a;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #555555;
    margin: 5px 10px;
}

/* ===== SPLITTER ===== */
QSplitter::handle {
    background-color: #3d3d3d;
}

QSplitter::handle:hover {
    background-color: #4a4a4a;
}

/* ===== GROUP BOXES ===== */
QGroupBox {
    border: 1px solid #555555;
    border-radius: 4px;
    margin-top: 10px;
    padding-top: 15px;
    font-weight: bold;
    color: #cccccc;
    background-color: #2d2d2d;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 5px 0 5px;
    color: #aaaaaa;
}

/* ===== TAB WIDGETS ===== */
QTabWidget::pane {
    border: 1px solid #555555;
    background-color: #2d2d2d;
}

QTabBar::tab {
    background-color: #3d3d3d;
    color: #b0b0b0;
    padding: 8px 16px;
    margin-right: 2px;
    border: 1px solid #555555;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}

QTabBar::tab:selected {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border-bottom: 1px solid #2d2d2d;
}

QTabBar::tab:hover {
    background-color: #4a4a4a;
}

/* ===== SCROLL BARS ===== */
QScrollBar:vertical {
    background-color: #3d3d3d;
    width: 15px;
    border-radius: 3px;
}

QScrollBar::handle:vertical {
    background-color: #5a5a5a;
    min-height: 20px;
    border-radius: 3px;
}

QScrollBar::handle:vertical:hover {
    background-color: #666666;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    background-color: #3d3d3d;
    height: 0px;
}

QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
    background: none;
}

QScrollBar:horizontal {
    background-color: #3d3d3d;
    height: 15px;
    border-radius: 3px;
}

QScrollBar::handle:horizontal {
    background-color: #5a5a5a;
    min-width: 20px;
    border-radius: 3px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #666666;
}

/* ===== LIST VIEWS ===== */
QListView, QListWidget {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #555555;
    border-radius: 3px;
}

QListView::item, QListWidget::item {
    padding: 5px;
    border-bottom: 1px solid #3d3d3d;
}

QListView::item:selected, QListWidget::item:selected {
    background-color: #4a4a4a;
    color: #ffffff;
}

QListView::item:hover, QListWidget::item:hover {
    background-color: #3d3d3d;
}

/* ===== TREE VIEWS ===== */
QTreeView, QTreeWidget {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #555555;
    border-radius: 3px;
    alternate-background-color: #333333;
}

QTreeView::item, QTreeWidget::item {
    padding: 3px;
    border-bottom: 1px solid #3d3d3d;
}

QTreeView::item:selected, QTreeWidget::item:selected {
    background-color: #4a4a4a;
    color: #ffffff;
}

QTreeView::item:hover, QTreeWidget::item:hover {
    background-color: #3d3d3d;
}

/* ===== TABLE VIEWS ===== */
QTableView, QTableWidget {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #555555;
    border-radius: 3px;
    gridline-color: #3d3d3d;
    alternate-background-color: #333333;
}

QHeaderView::section {
    background-color: #3d3d3d;
    color: #cccccc;
    padding: 5px;
    border: 1px solid #555555;
    font-weight: bold;
}

QTableView::item, QTableWidget::item {
    padding: 2px;
    border-bottom: 1px solid #3d3d3d;
}

QTableView::item:selected, QTableWidget::item:selected {
    background-color: #4a4a4a;
    color: #ffffff;
}

/* ===== TEXT EDITS ===== */
QTextEdit, QPlainTextEdit {
    background-color: #2d2d2d;
    color: #e0e0e0;
    border: 1px solid #555555;
    border-radius: 3px;
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
}

/* ===== DIALOGS ===== */
QDialog {
    background-color: #2d2d2d;
    color: #e0e0e0;
}

/* ===== PROGRESS BARS ===== */
QProgressBar {
    background-color: #3d3d3d;
    border: 1px solid #555555;
    border-radius: 3px;
    text-align: center;
    color: #e0e0e0;
}

QProgressBar::chunk {
    background-color: #4a4a4a;
    border-radius: 2px;
}

/* ===== CHECK BOXES ===== */
QCheckBox {
    color: #e0e0e0;
    spacing: 5px;
}

QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #555555;
    border-radius: 2px;
    background-color: #3d3d3d;
}

QCheckBox::indicator:checked {
    background-color: #4a4a4a;
    image: url(check_light.png);
}

QCheckBox::indicator:hover {
    border: 1px solid #666666;
}

/* ===== RADIO BUTTONS ===== */
QRadioButton {
    color: #e0e0e0;
    spacing: 5px;
}

QRadioButton::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid #555555;
    border-radius: 8px;
    background-color: #3d3d3d;
}

QRadioButton::indicator:checked {
    background-color: #4a4a4a;
    border: 4px solid #3d3d3d;
}

/* ===== LABELS ===== */
QLabel {
    color: #e0e0e0;
    font-weight: normal;
}

QLabel#titleLabel {
    font-size: 14px;
    font-weight: bold;
    color: #ffffff;
}

/* ===== SEPARATORS ===== */
QFrame[frameShape="4"] { /* HLine */
    background-color: #555555;
    max-height: 1px;
    min-height: 1px;
}

QFrame[frameShape="5"] { /* VLine */
    background-color: #555555;
    max-width: 1px;
    min-width: 1px;
}
"""

# Additional specific styles for packet table
PACKET_TABLE_STYLES = """
/* Specific styles for packet table */
QTableWidget#packetTable {
    background-color: #2d2d2d;
    alternate-background-color: #333333;
}

QTableWidget#packetTable::item {
    border-bottom: 1px solid #3d3d3d;
}

QTableWidget#packetTable::item:selected {
    background-color: #4a4a4a;
    color: #ffffff;
}
"""

# Hex view specific styles
HEX_VIEW_STYLES = """
QTextEdit#hexView {
    background-color: #1e1e1e;
    color: #e0e0e0;
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    font-size: 12px;
}
"""

# Apply all styles
ALL_STYLES = STYLESHEET + PACKET_TABLE_STYLES + HEX_VIEW_STYLES