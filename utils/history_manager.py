"""
History Manager for EtherEye
SRS Compliance: Implements FU-08 - Auto-History Log
Manages SQLite database for storing capture sessions
"""

import sqlite3
import json
import zlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any
import threading

from models.packet_session import CaptureSession

class HistoryManager:
    """Manages capture history in SQLite database"""
    
    def __init__(self, db_path: str = "ethereye_history.db"):
        """Initialize history manager with database path"""
        self.db_path = db_path
        self._init_database()
        self._cleanup_old_sessions()
    
    def _init_database(self):
        """Initialize database tables if they don't exist"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    name TEXT,
                    description TEXT,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    duration INTEGER,  -- in seconds
                    interface TEXT,
                    filter_string TEXT,
                    packet_count INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    protocol_stats TEXT,
                    session_data BLOB NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    tags TEXT
                )
            ''')
            
            # Create indexes for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sessions_time 
                ON sessions(start_time DESC)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_sessions_interface 
                ON sessions(interface)
            ''')
            
            conn.commit()
    
    def _cleanup_old_sessions(self, max_age_days: int = 30):
        """Automatically remove sessions older than max_age_days"""
        try:
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM sessions 
                    WHERE date(start_time) < date(?)
                ''', (cutoff_date.isoformat(),))
                
                deleted_count = cursor.rowcount
                if deleted_count > 0:
                    print(f"Cleaned up {deleted_count} old sessions")
                
                conn.commit()
        except Exception as e:
            print(f"Error cleaning up old sessions: {e}")
    
    def save_session(self, session: CaptureSession, 
                    name: str = "", 
                    description: str = "",
                    tags: List[str] = None) -> bool:
        """
        Save a capture session to history (SRS FU-08-02)
        Returns: True if successful, False otherwise
        """
        try:
            # Calculate duration
            duration = None
            if session.end_time:
                duration = int((session.end_time - session.start_time).total_seconds())
            
            # Compress session data
            session_json = session.to_json()
            compressed_data = zlib.compress(session_json.encode('utf-8'))
            
            # Convert protocol stats to JSON
            protocol_stats_json = json.dumps(session.get_stats())
            
            # Prepare tags
            tags_str = json.dumps(tags) if tags else "[]"
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO sessions 
                    (session_id, name, description, start_time, end_time, duration,
                     interface, filter_string, packet_count, total_bytes,
                     protocol_stats, session_data, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    session.session_id,
                    name or f"Capture {session.start_time.strftime('%Y-%m-%d %H:%M')}",
                    description,
                    session.start_time.isoformat(),
                    session.end_time.isoformat() if session.end_time else None,
                    duration,
                    session.interface,
                    session.filter_string,
                    session.packet_count,
                    session.total_bytes,
                    protocol_stats_json,
                    compressed_data,
                    tags_str
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            print(f"Error saving session to history: {e}")
            return False
    
    def get_all_sessions(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get all capture sessions from history
        Returns: List of session metadata (without full packet data)
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, session_id, name, description, start_time, end_time,
                           duration, interface, filter_string, packet_count,
                           total_bytes, protocol_stats, created_at, tags
                    FROM sessions 
                    ORDER BY start_time DESC
                    LIMIT ? OFFSET ?
                ''', (limit, offset))
                
                sessions = []
                for row in cursor.fetchall():
                    session_data = dict(row)
                    
                    # Parse JSON fields
                    if session_data['protocol_stats']:
                        session_data['protocol_stats'] = json.loads(session_data['protocol_stats'])
                    
                    if session_data['tags']:
                        session_data['tags'] = json.loads(session_data['tags'])
                    else:
                        session_data['tags'] = []
                    
                    # Format sizes
                    session_data['total_size_mb'] = session_data['total_bytes'] / (1024 * 1024)
                    
                    sessions.append(session_data)
                
                return sessions
                
        except Exception as e:
            print(f"Error loading sessions: {e}")
            return []
    
    def get_session_by_id(self, session_id: str) -> Optional[CaptureSession]:
        """Retrieve a specific session by ID with full packet data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT session_data FROM sessions WHERE session_id = ?
                ''', (session_id,))
                
                row = cursor.fetchone()
                if row:
                    # Decompress and load session data
                    compressed_data = row[0]
                    session_json = zlib.decompress(compressed_data).decode('utf-8')
                    return CaptureSession.from_json(session_json)
                
                return None
                
        except Exception as e:
            print(f"Error loading session {session_id}: {e}")
            return None
    
    def get_session_metadata(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session metadata without loading full packet data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT id, session_id, name, description, start_time, end_time,
                           duration, interface, filter_string, packet_count,
                           total_bytes, protocol_stats, created_at, tags
                    FROM sessions WHERE session_id = ?
                ''', (session_id,))
                
                row = cursor.fetchone()
                if row:
                    metadata = dict(row)
                    
                    # Parse JSON fields
                    if metadata['protocol_stats']:
                        metadata['protocol_stats'] = json.loads(metadata['protocol_stats'])
                    
                    if metadata['tags']:
                        metadata['tags'] = json.loads(metadata['tags'])
                    
                    return metadata
                
                return None
                
        except Exception as e:
            print(f"Error loading session metadata {session_id}: {e}")
            return None
    
    def update_session_info(self, session_id: str, name: str = None, 
                          description: str = None, tags: List[str] = None) -> bool:
        """Update session name, description, or tags"""
        try:
            updates = []
            params = []
            
            if name is not None:
                updates.append("name = ?")
                params.append(name)
            
            if description is not None:
                updates.append("description = ?")
                params.append(description)
            
            if tags is not None:
                updates.append("tags = ?")
                params.append(json.dumps(tags))
            
            if not updates:
                return True  # Nothing to update
            
            params.append(session_id)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                query = f'''
                    UPDATE sessions 
                    SET {', '.join(updates)}
                    WHERE session_id = ?
                '''
                
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            print(f"Error updating session {session_id}: {e}")
            return False
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session from history"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    DELETE FROM sessions WHERE session_id = ?
                ''', (session_id,))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            print(f"Error deleting session {session_id}: {e}")
            return False
    
    def search_sessions(self, query: str, field: str = 'name') -> List[Dict[str, Any]]:
        """Search sessions by field"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                if field == 'name':
                    cursor.execute('''
                        SELECT session_id, name, start_time, interface, packet_count
                        FROM sessions 
                        WHERE name LIKE ?
                        ORDER BY start_time DESC
                        LIMIT 50
                    ''', (f'%{query}%',))
                elif field == 'interface':
                    cursor.execute('''
                        SELECT session_id, name, start_time, interface, packet_count
                        FROM sessions 
                        WHERE interface LIKE ?
                        ORDER BY start_time DESC
                        LIMIT 50
                    ''', (f'%{query}%',))
                elif field == 'filter':
                    cursor.execute('''
                        SELECT session_id, name, start_time, interface, packet_count
                        FROM sessions 
                        WHERE filter_string LIKE ?
                        ORDER BY start_time DESC
                        LIMIT 50
                    ''', (f'%{query}%',))
                else:
                    return []
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            print(f"Error searching sessions: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics about stored sessions"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total sessions
                cursor.execute('SELECT COUNT(*) FROM sessions')
                total_sessions = cursor.fetchone()[0]
                
                # Total packets
                cursor.execute('SELECT SUM(packet_count) FROM sessions')
                total_packets = cursor.fetchone()[0] or 0
                
                # Total bytes
                cursor.execute('SELECT SUM(total_bytes) FROM sessions')
                total_bytes = cursor.fetchone()[0] or 0
                
                # Average packets per session
                avg_packets = total_packets / total_sessions if total_sessions > 0 else 0
                
                # Most active interface
                cursor.execute('''
                    SELECT interface, COUNT(*) as count
                    FROM sessions 
                    GROUP BY interface 
                    ORDER BY count DESC 
                    LIMIT 1
                ''')
                most_active = cursor.fetchone()
                
                return {
                    'total_sessions': total_sessions,
                    'total_packets': total_packets,
                    'total_bytes': total_bytes,
                    'total_size_gb': total_bytes / (1024**3),
                    'avg_packets_per_session': round(avg_packets, 1),
                    'most_active_interface': most_active[0] if most_active else 'N/A',
                    'interface_count': most_active[1] if most_active else 0
                }
                
        except Exception as e:
            print(f"Error getting statistics: {e}")
            return {}
    
    def clear_all_history(self) -> bool:
        """Clear all history (use with caution!)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM sessions')
                cursor.execute('VACUUM')  # Reclaim disk space
                conn.commit()
                return True
        except Exception as e:
            print(f"Error clearing history: {e}")
            return False
    
    def export_session_to_file(self, session_id: str, file_path: str) -> bool:
        """Export session to a JSON file (for backup or sharing)"""
        session = self.get_session_by_id(session_id)
        if not session:
            return False
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Error exporting session: {e}")
            return False
    
    def import_session_from_file(self, file_path: str) -> Optional[str]:
        """Import session from a JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                session_dict = json.load(f)
            
            session = CaptureSession.from_dict(session_dict)
            
            # Generate new session ID to avoid conflicts
            from datetime import datetime
            import uuid
            session.session_id = f"imported_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
            
            # Save to database
            if self.save_session(session, name=f"Imported: {session.start_time}"):
                return session.session_id
            return None
            
        except Exception as e:
            print(f"Error importing session: {e}")
            return None
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get information about the database"""
        path = Path(self.db_path)
        
        if not path.exists():
            return {"exists": False}
        
        stats = path.stat()
        
        return {
            "exists": True,
            "path": str(path.absolute()),
            "size_bytes": stats.st_size,
            "size_mb": stats.st_size / (1024 * 1024),
            "created": datetime.fromtimestamp(stats.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stats.st_mtime).isoformat(),
        }