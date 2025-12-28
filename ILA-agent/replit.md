# ILA-SOC Log Collection Agent

## Overview
A production-ready Python log collection agent for the ILA-SOC security monitoring system. The agent monitors log files in real-time, batches and sends logs to a central server, and includes robust offline buffering capabilities.

## Project Structure
```
.
├── agent.py              # Main agent script with all functionality
├── config.json           # Configuration file (server URL, API key, log paths)
├── requirements.txt      # Python dependencies
├── SERVICE_INSTALL.md    # Service installation guide (Linux/Windows)
├── log_buffer.db         # SQLite database for offline log buffering (auto-created)
├── agent.log             # Agent activity log file (auto-created)
└── replit.md             # Project documentation
```

## Features
1. **File Monitoring**: Real-time log file monitoring using watchdog library
2. **Configurable Sources**: Supports multiple log files (Linux) or Event Logs (Windows)
3. **Batching**: Collects logs and sends in batches (every 5 seconds or 50 logs)
4. **Local Buffer**: SQLite database stores logs when server is unreachable
5. **Heartbeat**: Sends heartbeat every 60 seconds to maintain active status
6. **Auto-reconnect**: Retries connection automatically when server is available
7. **Graceful Shutdown**: Proper signal handling and log flushing on exit

## Configuration
Edit `config.json` to set:
- `server_url`: ILA-SOC server URL
- `api_key`: API key for authentication (sent in X-API-Key header)
- `agent_id`: Unique agent identifier (auto-generated if null)
- `log_sources`: Log files to monitor (Linux/Windows)
- Timing settings: heartbeat_interval, batch_interval, batch_size

## API Endpoints Used
1. `POST /api/agent/register` - Register agent on startup
2. `POST /api/agent/heartbeat` - Send heartbeat every 60 seconds
3. `POST /api/agent/ingest-batch` - Send collected logs

## Running the Agent
```bash
# Run directly
python agent.py

# With custom config
python agent.py --config /path/to/config.json
```

## Service Installation
See `SERVICE_INSTALL.md` for instructions on running as:
- Linux: systemd service
- Windows: Task Scheduler or Windows Service (NSSM/pywin32)

## Dependencies
- requests: HTTP client for API communication
- watchdog: File system monitoring library

## Recent Changes
- 2025-11-29: Initial implementation with all required features
