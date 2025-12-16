#!/usr/bin/env python3
"""
EtherEye - Main Application Entry Point
Complete with all features
"""

import sys
import os
import traceback

def main():
    """Main application function"""
    # Set environment variables to fix Qt issues
    os.environ['QT_LOGGING_RULES'] = 'qt.qpa.theme.*=false'
    os.environ['QT_QPA_PLATFORM'] = 'xcb'  # Force X11 instead of Wayland
    
    # Disable wayland if present
    if 'WAYLAND_DISPLAY' in os.environ:
        os.environ.pop('WAYLAND_DISPLAY', None)
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("=" * 60)
        print("ERROR: Root privileges required!")
        print("This application needs root access to capture packets.")
        print("\nPlease run with:")
        print("  sudo python main.py")
        print("=" * 60)
        return 1
    
    try:
        # Suppress Qt warnings about portal
        os.environ['QT_QPA_PLATFORM'] = 'xcb'
        os.environ['XDG_CURRENT_DESKTOP'] = 'GNOME'
        
        from PyQt6.QtWidgets import QApplication
        from gui.main_window import MainWindow
        
        # Create application
        app = QApplication(sys.argv)
        app.setApplicationName("EtherEye")
        app.setApplicationDisplayName("EtherEye")
        app.setApplicationVersion("1.0")
        app.setOrganizationName("Politeknik Negeri Jakarta")
        app.setOrganizationDomain("pnj.ac.id")
        
        # Create and show main window
        window = MainWindow()
        window.show()
        
        # Start application event loop
        return app.exec()
        
    except ImportError as e:
        print(f"Import Error: {e}")
        print("\nTroubleshooting steps:")
        print("1. Make sure all dependencies are installed:")
        print("   pip install PyQt6 scapy")
        print("2. Check that all required files exist")
        print("3. Run from the project root directory")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())