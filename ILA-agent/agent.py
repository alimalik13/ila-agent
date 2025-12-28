#!/usr/bin/env python3
"""
ILA-SOC Log Collection Agent
A production-ready log collection agent for security monitoring.
"""

import json
import logging
import os
import platform
import signal
import socket
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from typing import Dict, List, Optional, Any

import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "server_url": "http://localhost:5000",
    "api_key": "ila-soc-agent-key-2024",
    "agent_id": None,
    "heartbeat_interval": 60,
    "batch_interval": 5,
    "batch_size": 50,
    "log_sources": {
        "linux": ["/var/log/syslog", "/var/log/auth.log", "/var/log/secure"],
        "windows": ["Security", "System", "Application"]
    },
    "buffer_db": "log_buffer.db",
    "agent_log_file": "agent.log",
    "retry_interval": 30,
    "max_retries": 5
}


class LogBuffer:
    """SQLite-based local buffer for storing logs when server is unreachable."""
    
    def __init__(self, db_path: str, logger: logging.Logger):
        self.db_path = db_path
        self.logger = logger
        self._init_db()
    
    def _init_db(self):
        """Initialize the SQLite database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS log_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    log_text TEXT NOT NULL,
                    source TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON log_buffer(created_at)')
            conn.commit()
            conn.close()
            self.logger.info(f"Log buffer database initialized: {self.db_path}")
        except Exception as e:
            self.logger.error(f"Failed to initialize log buffer database: {e}")
            raise
    
    def store(self, logs: List[Dict[str, str]]):
        """Store logs in the buffer."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            for log in logs:
                cursor.execute(
                    'INSERT INTO log_buffer (log_text, source, timestamp, created_at) VALUES (?, ?, ?, ?)',
                    (log['log_text'], log['source'], log.get('timestamp', ''), time.time())
                )
            conn.commit()
            conn.close()
            self.logger.debug(f"Stored {len(logs)} logs in buffer")
        except Exception as e:
            self.logger.error(f"Failed to store logs in buffer: {e}")
    
    def retrieve(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve logs from the buffer."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT id, log_text, source, timestamp FROM log_buffer ORDER BY created_at ASC LIMIT ?', (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [{'id': row[0], 'log_text': row[1], 'source': row[2], 'timestamp': row[3]} for row in rows]
        except Exception as e:
            self.logger.error(f"Failed to retrieve logs from buffer: {e}")
            return []
    
    def delete(self, ids: List[int]):
        """Delete logs from the buffer after successful send."""
        if not ids:
            return
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            placeholders = ','.join('?' * len(ids))
            cursor.execute(f'DELETE FROM log_buffer WHERE id IN ({placeholders})', ids)
            conn.commit()
            conn.close()
            self.logger.debug(f"Deleted {len(ids)} logs from buffer")
        except Exception as e:
            self.logger.error(f"Failed to delete logs from buffer: {e}")
    
    def count(self) -> int:
        """Get the number of buffered logs."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM log_buffer')
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            self.logger.error(f"Failed to count buffered logs: {e}")
            return 0


class LogFileHandler(FileSystemEventHandler):
    """Watchdog event handler for monitoring log files."""
    
    def __init__(self, file_path: str, log_queue: Queue, logger: logging.Logger):
        super().__init__()
        self.file_path = file_path
        self.log_queue = log_queue
        self.logger = logger
        self.file_position = self._get_file_size()
    
    def _get_file_size(self) -> int:
        """Get the current file size."""
        try:
            return os.path.getsize(self.file_path)
        except OSError:
            return 0
    
    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
        src_path = str(event.src_path)
        if src_path == self.file_path or src_path.endswith(os.path.basename(self.file_path)):
            self._read_new_lines()
    
    def _read_new_lines(self):
        """Read new lines from the log file."""
        try:
            current_size = self._get_file_size()
            if current_size < self.file_position:
                self.file_position = 0
            
            if current_size > self.file_position:
                with open(self.file_path, 'r', errors='replace') as f:
                    f.seek(self.file_position)
                    for line in f:
                        line = line.strip()
                        if line:
                            self.log_queue.put({
                                'log_text': line,
                                'source': os.path.basename(self.file_path),
                                'timestamp': datetime.utcnow().isoformat()
                            })
                    self.file_position = f.tell()
        except Exception as e:
            self.logger.error(f"Error reading log file {self.file_path}: {e}")


class WindowsEventLogHandler:
    """
    Handler for Windows Event Logs.
    
    IMPORTANT: Collecting real-time Windows Event Logs requires:
    1. Running the agent with root/SYSTEM privileges (administrator/elevated permissions)
    2. Installing the pywin32 package: pip install pywin32
    """
    
    def __init__(self, log_names: List[str], log_queue: Queue, logger: logging.Logger):
        self.log_names = log_names
        self.log_queue = log_queue
        self.logger = logger
        self.last_record_numbers = {}
        self._running = False
        self._thread = None
        
        try:
            import win32evtlog
            import win32evtlogutil
            self.win32evtlog = win32evtlog
            self.win32evtlogutil = win32evtlogutil
            self.available = True
            self.logger.info("Windows Event Log handler initialized successfully")
        except ImportError as e:
            self.available = False
            self.logger.error(f"win32evtlog not available - Windows Event Log monitoring disabled. Error: {e}")
            self.logger.error("Please install pywin32: pip install pywin32")
            self.logger.error("Note: You may need to run 'python -m pip install pywin32' and restart the agent")
    
    def start(self):
        """Start monitoring Windows Event Logs."""
        if not self.available:
            self.logger.warning("Cannot start Windows Event Log monitoring - pywin32 not available")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.logger.info(f"Windows Event Log monitoring started for: {', '.join(self.log_names)}")
        self.logger.info("Note: Administrator privileges may be required for full access to Security logs")
    
    def stop(self):
        """Stop monitoring Windows Event Logs."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Main monitoring loop for Windows Event Logs."""
        consecutive_errors = {}  # Track consecutive errors per log
        while self._running:
            for log_name in self.log_names:
                try:
                    self._read_events(log_name)
                    consecutive_errors[log_name] = 0  # Reset error count on success
                except Exception as e:
                    error_count = consecutive_errors.get(log_name, 0) + 1
                    consecutive_errors[log_name] = error_count
                    # Only log error every 10 attempts to avoid spam
                    if error_count % 10 == 1:
                        self.logger.debug(f"Error reading Windows Event Log {log_name}: {e}")
            time.sleep(1)
    
    def _read_events(self, log_name: str):
        """Read new events from a Windows Event Log."""
        try:
            hand = self.win32evtlog.OpenEventLog(None, log_name)
            
            # Get the oldest and newest record numbers
            oldest = self.win32evtlog.GetOldestEventLogRecord(hand)
            num_records = self.win32evtlog.GetNumberOfEventLogRecords(hand)
            newest = oldest + num_records - 1
            
            # Initialize last_record if not set
            if log_name not in self.last_record_numbers:
                # On first run, start reading from the last 50 events (or the oldest, whichever is newer)
                start_record = max(oldest, newest - 49)
                
                # Set the marker to the event *before* the one we want to read
                self.last_record_numbers[log_name] = start_record - 1
                self.logger.info(f"Initializing Windows Event Log '{log_name}': reading {newest - start_record + 1} initial events (records {start_record} to {newest})")
                # DO NOT CLOSE HANDLE HERE - continue to read the events
            
            last_record = self.last_record_numbers[log_name]
            
            # Only read if there are new records
            if newest > last_record:
                # Read backwards from the end - read up to 200 events to catch all new ones
                flags = self.win32evtlog.EVENTLOG_BACKWARDS_READ | self.win32evtlog.EVENTLOG_SEQUENTIAL_READ
                num_new = newest - last_record
                # Read at least the number of new events, but cap at 200 for performance
                records_to_read = min(200, max(1, num_new))
                events = self.win32evtlog.ReadEventLog(hand, flags, records_to_read)
                
                new_events = []
                max_record = last_record
                min_new_record = newest + 1  # Track the lowest new record we've seen
                
                # Process events - they come in reverse order (newest first)
                for event in events:
                    # Only process events newer than what we've seen
                    if event.RecordNumber > last_record:
                        try:
                            message = self.win32evtlogutil.SafeFormatMessage(event, log_name)
                        except:
                            message = str(event.StringInserts) if event.StringInserts else "No message"
                        
                        # Truncate very long messages
                        if len(message) > 1000:
                            message = message[:1000] + "..."
                        
                        # Format timestamp
                        try:
                            if hasattr(event.TimeGenerated, 'isoformat'):
                                timestamp = event.TimeGenerated.isoformat()
                            else:
                                timestamp = str(event.TimeGenerated)
                        except:
                            timestamp = str(event.TimeGenerated)
                        
                        new_events.append({
                            'log_text': f"[{event.SourceName}] EventID:{event.EventID} - {message}",
                            'source': f"Windows-{log_name}",
                            'timestamp': timestamp,
                            'record_number': event.RecordNumber  # Store for sorting
                        })
                        
                        # Track the highest and lowest record numbers we've seen
                        if event.RecordNumber > max_record:
                            max_record = event.RecordNumber
                        if event.RecordNumber < min_new_record:
                            min_new_record = event.RecordNumber
                
                # Sort events by record number (chronological order) before queuing
                new_events.sort(key=lambda x: x['record_number'])
                
                # Remove the record_number from the dict before queuing
                for evt in new_events:
                    evt.pop('record_number', None)
                    self.log_queue.put(evt)
                
                # Update last record number to the highest we've seen
                if max_record > last_record:
                    self.last_record_numbers[log_name] = max_record
                
                if new_events:
                    self.logger.info(f"Collected {len(new_events)} new events from Windows Event Log: {log_name} (records {min_new_record} to {max_record})")
            else:
                # No new events
                pass  # Don't log, just continue
            
            self.win32evtlog.CloseEventLog(hand)
        except Exception as e:
            error_msg = str(e)
            # Don't spam logs for permission errors - log once per log type
            if "privilege" in error_msg.lower() or "1314" in error_msg:
                # Only log this once per session for Security log
                if log_name == "Security" and not hasattr(self, '_security_log_warned'):
                    self.logger.warning(f"Cannot read Security log - administrator privileges required. Continuing with other logs...")
                    self._security_log_warned = True
            else:
                # Log other errors at warning level to ensure they appear on console
                if not hasattr(self, f'_error_logged_{log_name}'):
                    self.logger.warning(f"Could not read Windows Event Log '{log_name}': {e}. This may indicate insufficient permissions - ensure the agent is running with administrator/elevated privileges.")
                    setattr(self, f'_error_logged_{log_name}', True)


class ILASOCAgent:
    """Main log collection agent for ILA-SOC security system."""
    
    def __init__(self, config_path: str = CONFIG_FILE, server_url: Optional[str] = None, api_key: Optional[str] = None):
        self.config_path = config_path
        self.config = self._load_config(config_path, server_url=server_url, api_key=api_key)
        self.logger = self._setup_logging()
        
        self.agent_id = self.config.get('agent_id') or str(uuid.uuid4())
        self.hostname = socket.gethostname()
        self.os_type = platform.system()
        
        self.server_url = self.config['server_url'].rstrip('/')
        self.api_key = self.config['api_key']
        self.headers = {
            'Content-Type': 'application/json',
            'X-API-Key': self.api_key
        }
        
        self.log_queue = Queue()
        self.buffer = LogBuffer(self.config['buffer_db'], self.logger)
        self.server_available = False
        
        self._running = False
        self._shutdown_event = threading.Event()
        self._threads = []
        self._observer = None
        self._windows_handler = None
        self._test_log_generator = None
        
        self._save_agent_id()
    
    def _load_config(self, config_path: str, server_url: Optional[str] = None, api_key: Optional[str] = None) -> Dict:
        """Load configuration from file, with optional overrides for server_url and api_key."""
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                for key, value in DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
        else:
            with open(config_path, 'w') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
            config = DEFAULT_CONFIG.copy()
        
        # Override with provided values if they exist
        if server_url:
            config['server_url'] = server_url
        if api_key:
            config['api_key'] = api_key
        
        return config
    
    def _save_agent_id(self):
        """Save the agent ID to config file."""
        self.config['agent_id'] = self.agent_id
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the agent."""
        logger = logging.getLogger('ILASOCAgent')
        logger.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        file_handler = logging.FileHandler(self.config['agent_log_file'])
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _api_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Optional[Dict]:
        """Make an API request to the server."""
        url = f"{self.server_url}{endpoint}"
        try:
            if method.upper() == 'POST':
                response = requests.post(url, json=data, headers=self.headers, timeout=30)
            elif method.upper() == 'GET':
                response = requests.get(url, headers=self.headers, timeout=30)
            else:
                return None
            
            if response.status_code in (200, 201):
                self.server_available = True
                return response.json() if response.text else {}
            else:
                self.logger.warning(f"API request failed: {response.status_code} - {response.text}")
                return None
        except requests.exceptions.ConnectionError:
            self.server_available = False
            self.logger.warning(f"Server unavailable: {url}")
            return None
        except requests.exceptions.Timeout:
            self.server_available = False
            self.logger.warning(f"Request timeout: {url}")
            return None
        except Exception as e:
            self.logger.error(f"API request error: {e}")
            return None
    
    def register(self) -> bool:
        """Register the agent with the server."""
        self.logger.info(f"Registering agent {self.agent_id} with server...")
        
        data = {
            'agent_id': self.agent_id,
            'hostname': self.hostname,
            'os_type': self.os_type
        }
        
        result = self._api_request('POST', '/api/agent/register', data)
        if result is not None:
            self.logger.info(f"Agent registered successfully: {self.agent_id}")
            return True
        else:
            self.logger.warning("Agent registration failed - will retry")
            return False
    
    def heartbeat(self) -> bool:
        """Send heartbeat to the server."""
        data = {'agent_id': self.agent_id}
        result = self._api_request('POST', '/api/agent/heartbeat', data)
        if result is not None:
            self.logger.debug("Heartbeat sent successfully")
            return True
        else:
            self.logger.warning("Heartbeat failed")
            return False
    
    def send_logs(self, logs: List[Dict[str, str]]) -> bool:
        """Send logs to the server."""
        if not logs:
            return True
        
        data = {
            'agent_id': self.agent_id,
            'logs': logs
        }
        
        self.logger.info(f"Attempting to send {len(logs)} logs to server...")
        result = self._api_request('POST', '/api/agent/ingest-batch', data)
        if result is not None:
            self.logger.info(f"Successfully sent {len(logs)} logs to server")
            return True
        else:
            self.logger.warning(f"Failed to send {len(logs)} logs - buffering locally")
            self.buffer.store(logs)
            return False
    
    def _heartbeat_loop(self):
        """Background loop for sending heartbeats."""
        interval = self.config['heartbeat_interval']
        while self._running and not self._shutdown_event.is_set():
            if not self.server_available:
                if self.register():
                    self._flush_buffer()
            else:
                self.heartbeat()
            
            self._shutdown_event.wait(interval)
    
    def _batch_sender_loop(self):
        """Background loop for batching and sending logs."""
        batch_interval = self.config['batch_interval']
        batch_size = self.config['batch_size']
        last_log_count_log = 0
        
        while self._running and not self._shutdown_event.is_set():
            batch = []
            start_time = time.time()
            
            while len(batch) < batch_size:
                remaining_time = batch_interval - (time.time() - start_time)
                if remaining_time <= 0:
                    break
                
                try:
                    log_entry = self.log_queue.get(timeout=min(0.5, remaining_time))
                    batch.append(log_entry)
                except Empty:
                    continue
            
            if batch:
                self.logger.info(f"Batch sender: Collected {len(batch)} logs from queue, sending...")
                self.send_logs(batch)
            else:
                # Log periodically that we're waiting for logs (every 30 seconds)
                current_time = time.time()
                if current_time - last_log_count_log >= 30:
                    queue_size = self.log_queue.qsize()
                    self.logger.debug(f"Batch sender: Waiting for logs... (queue size: {queue_size})")
                    last_log_count_log = current_time
    
    def _flush_buffer(self):
        """Flush buffered logs to the server."""
        buffered_count = self.buffer.count()
        if buffered_count == 0:
            return
        
        self.logger.info(f"Flushing {buffered_count} buffered logs...")
        
        while True:
            logs = self.buffer.retrieve(limit=self.config['batch_size'])
            if not logs:
                break
            
            log_data = [{'log_text': l['log_text'], 'source': l['source']} for l in logs]
            ids = [l['id'] for l in logs]
            
            data = {
                'agent_id': self.agent_id,
                'logs': log_data
            }
            
            result = self._api_request('POST', '/api/agent/ingest-batch', data)
            if result is not None:
                self.buffer.delete(ids)
                self.logger.info(f"Flushed {len(logs)} buffered logs")
            else:
                self.logger.warning("Failed to flush buffered logs - will retry later")
                break
    
    def _setup_file_watchers(self):
        """Set up file watchers for log files."""
        self._observer = Observer()
        
        if self.os_type == 'Linux':
            log_files = self.config['log_sources'].get('linux', [])
        elif self.os_type == 'Darwin':
            log_files = ['/var/log/system.log', '/var/log/secure.log']
        elif self.os_type == 'Windows':
            # Windows log files (if they exist)
            windows_log_paths = [
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Logs', 'Application', '*.log'),
                os.path.join(os.environ.get('WINDIR', 'C:\\Windows'), 'Logs', 'System', '*.log'),
            ]
            # For Windows, we'll primarily rely on Windows Event Log handler
            # File watchers are less common on Windows
            log_files = []
            self.logger.info("Windows detected: Using Windows Event Log handler for log collection")
        else:
            log_files = []
        
        watched_files = []
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    handler = LogFileHandler(log_file, self.log_queue, self.logger)
                    dir_path = os.path.dirname(log_file)
                    self._observer.schedule(handler, dir_path, recursive=False)
                    watched_files.append(log_file)
                except Exception as e:
                    self.logger.error(f"Failed to watch {log_file}: {e}")
            else:
                self.logger.warning(f"Log file not found: {log_file}")
        
        if watched_files:
            self._observer.start()
            self.logger.info(f"Watching log files: {', '.join(watched_files)}")
        else:
            if self.os_type == 'Windows':
                self.logger.info("No file watchers configured for Windows (relying on Windows Event Log handler)")
            else:
                self.logger.warning("No log files to watch")
    
    def _setup_windows_watcher(self):
        """
        Set up Windows Event Log watcher.
        
        IMPORTANT: Collecting real-time Windows Event Logs requires:
        1. Running the agent with root/SYSTEM privileges (administrator/elevated permissions)
        2. Installing the pywin32 package: pip install pywin32
        """
        if self.os_type != 'Windows':
            return
        
        log_names = self.config['log_sources'].get('windows', [])
        self._windows_handler = WindowsEventLogHandler(log_names, self.log_queue, self.logger)
        self._windows_handler.start()
    
    def _start_test_log_generator(self):
        """Start a test log generator if no real log sources are available or if Windows logs aren't working."""
        # Check if we have any active log sources
        has_file_watchers = self._observer and self._observer.is_alive() if self._observer else False
        has_windows_logs = self._windows_handler and self._windows_handler.available if self._windows_handler else False
        
        # Always start test log generator as a fallback to ensure logs are sent
        # It will generate logs every 10 seconds to verify transmission works
        self.logger.info("Starting test log generator to ensure log transmission is working")
        self.logger.info("Test logs will be generated every 10 seconds alongside real logs (if available)")
        self._test_log_generator = threading.Thread(target=self._test_log_generator_loop, daemon=True)
        self._test_log_generator.start()
        self._threads.append(self._test_log_generator)
    
    def _test_log_generator_loop(self):
        """Generate test logs periodically to verify log transmission."""
        test_log_counter = 0
        while self._running and not self._shutdown_event.is_set():
            test_log_counter += 1
            test_log = {
                'log_text': f"[TEST] Agent {self.agent_id} - Test log entry #{test_log_counter} at {datetime.utcnow().isoformat()}",
                'source': 'Agent-Test',
                'timestamp': datetime.utcnow().isoformat()
            }
            self.log_queue.put(test_log)
            self.logger.info(f"Generated test log #{test_log_counter}")
            # Wait 10 seconds before generating next test log
            self._shutdown_event.wait(10)
    
    def _update_status_display(self):
        """Clear console and display current agent status."""
        # Clear console based on OS
        if platform.system() == 'Windows':
            os.system('cls')
        else:
            os.system('clear')
        
        # Display status information
        print("=" * 60)
        print("ILA-SOC Log Collection Agent - Status")
        print("=" * 60)
        print(f"Agent ID:     {self.agent_id}")
        print(f"Hostname:     {self.hostname}")
        print(f"Server URL:   {self.server_url}")
        
        # Connection status
        if self.server_available:
            print(f"Connection:   Server Connected ✅")
        else:
            retry_interval = self.config.get('retry_interval', 30)
            print(f"Connection:   Disconnected ❌, Retrying registration in {retry_interval} seconds...")
        
        # Buffer status
        buffer_count = self.buffer.count()
        print(f"Buffer Status: {buffer_count} logs in local buffer")
        print("=" * 60)
        print("Press Ctrl+C to stop the agent")
        print()
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.stop()
    
    def start(self):
        """Start the agent."""
        self.logger.info("=" * 60)
        self.logger.info("ILA-SOC Log Collection Agent Starting")
        self.logger.info(f"Agent ID: {self.agent_id}")
        self.logger.info(f"Hostname: {self.hostname}")
        self.logger.info(f"OS Type: {self.os_type}")
        self.logger.info(f"Server URL: {self.server_url}")
        self.logger.info("=" * 60)
        
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        self._running = True
        
        retry_count = 0
        max_retries = self.config['max_retries']
        retry_interval = self.config['retry_interval']
        
        while retry_count < max_retries:
            if self.register():
                self._flush_buffer()
                break
            retry_count += 1
            self.logger.info(f"Registration retry {retry_count}/{max_retries} in {retry_interval}s...")
            time.sleep(retry_interval)
        
        if not self.server_available:
            self.logger.warning("Starting in offline mode - logs will be buffered locally")
        
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        self._threads.append(heartbeat_thread)
        
        batch_thread = threading.Thread(target=self._batch_sender_loop, daemon=True)
        batch_thread.start()
        self._threads.append(batch_thread)
        
        self._setup_file_watchers()
        self._setup_windows_watcher()
        
        # Start test log generator if no log sources are available
        self._start_test_log_generator()
        
        self.logger.info("Agent started successfully")
        
        # Update status display periodically
        last_status_update = 0
        status_update_interval = 1.0  # Update every second
        
        try:
            while self._running:
                current_time = time.time()
                if current_time - last_status_update >= status_update_interval:
                    self._update_status_display()
                    last_status_update = current_time
                self._shutdown_event.wait(0.1)  # Small sleep to avoid busy waiting
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the agent gracefully."""
        if not self._running:
            return
        
        self.logger.info("Stopping agent...")
        self._running = False
        self._shutdown_event.set()
        
        if self._observer and hasattr(self._observer, 'is_alive') and self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5)
        
        if self._windows_handler:
            self._windows_handler.stop()
        
        remaining_logs = []
        while True:
            try:
                log_entry = self.log_queue.get_nowait()
                remaining_logs.append(log_entry)
            except Empty:
                break
        
        if remaining_logs:
            self.logger.info(f"Buffering {len(remaining_logs)} remaining logs...")
            self.buffer.store(remaining_logs)
        
        for thread in self._threads:
            thread.join(timeout=5)
        
        buffered_count = self.buffer.count()
        self.logger.info(f"Agent stopped. Buffered logs: {buffered_count}")
        self.logger.info("=" * 60)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='ILA-SOC Log Collection Agent')
    parser.add_argument('--config', '-c', default=CONFIG_FILE, help='Path to configuration file')
    parser.add_argument('--server-url', help='Server URL for the ILA-SOC server')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--version', '-v', action='version', version='ILA-SOC Agent 1.0.0')
    args = parser.parse_args()
    
    # Prompt for missing configuration values
    server_url = args.server_url
    api_key = args.api_key
    
    if not server_url:
        server_url = input("Enter Server URL (or press Enter to use config.json value): ").strip()
        if not server_url:
            server_url = None
    
    if not api_key:
        api_key = input("Enter API Key (or press Enter to use config.json value): ").strip()
        if not api_key:
            api_key = None
    
    agent = ILASOCAgent(config_path=args.config, server_url=server_url, api_key=api_key)
    agent.start()


if __name__ == '__main__':
    main()
