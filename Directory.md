ethereye_app/
│
├── core/
│   ├── capturer.py       # Handles pcapy, interface listing, start/stop capture
│   ├── decoder.py        # Uses scapy to parse packets into layers
│   └── filter_engine.py  # Manages BPF filter translation and application
│
├── models/
│   └── packet_session.py # Defines data structures for packets and sessions
│
├── gui/
│   ├── main_window.py    # Main PyQt6 window with three-panel layout
│   ├── packet_list.py    # Widget for the packet table (FU-04, FU-05)
│   ├── detail_tree.py    # Widget for the protocol tree view (FU-06)
│   └── hex_view.py       # Widget for the hex/ASCII payload view (FU-06)
│
├── utils/
│   ├── history_manager.py # Manages SQLite database for session history (FU-08)
│   └── exporter.py       # Handles .pcap and .csv export (FU-09)
│
└── main.py              # Application entry point