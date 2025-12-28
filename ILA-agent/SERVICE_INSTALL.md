# ILA-SOC Log Collection Agent - Service Installation Guide

## Prerequisites

1. Python 3.8 or higher
2. Required Python packages (install via pip):
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Before running the agent, edit `config.json`:

```json
{
    "server_url": "http://your-ila-soc-server:5000",
    "api_key": "your-api-key",
    "agent_id": null,
    "heartbeat_interval": 60,
    "batch_interval": 5,
    "batch_size": 50,
    "log_sources": {
        "linux": [
            "/var/log/syslog",
            "/var/log/auth.log",
            "/var/log/secure"
        ],
        "windows": [
            "Security",
            "System",
            "Application"
        ]
    }
}
```

---

## Linux Installation (systemd)

### 1. Copy Files to Installation Directory

```bash
sudo mkdir -p /opt/ila-soc-agent
sudo cp agent.py config.json requirements.txt /opt/ila-soc-agent/
sudo chown -R root:root /opt/ila-soc-agent
```

### 2. Install Dependencies

```bash
cd /opt/ila-soc-agent
sudo pip3 install -r requirements.txt
```

### 3. Create systemd Service File

Create `/etc/systemd/system/ila-soc-agent.service`:

```ini
[Unit]
Description=ILA-SOC Log Collection Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/ila-soc-agent
ExecStart=/usr/bin/python3 /opt/ila-soc-agent/agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ila-soc-agent

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/ila-soc-agent /var/log
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 4. Enable and Start the Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable ila-soc-agent
sudo systemctl start ila-soc-agent
```

### 5. Check Status and Logs

```bash
# Check service status
sudo systemctl status ila-soc-agent

# View logs
sudo journalctl -u ila-soc-agent -f

# Or check the agent log file
tail -f /opt/ila-soc-agent/agent.log
```

### 6. Commands Reference

```bash
# Stop the service
sudo systemctl stop ila-soc-agent

# Restart the service
sudo systemctl restart ila-soc-agent

# Disable auto-start
sudo systemctl disable ila-soc-agent
```

---

## Windows Installation

### Option 1: Windows Task Scheduler (Recommended for Simple Setup)

#### 1. Install Python and Dependencies

```powershell
# Install Python from python.org
# Then install dependencies:
pip install -r requirements.txt
```

#### 2. Create a Batch File

Create `run_agent.bat` in the agent directory:

```batch
@echo off
cd /d "C:\ILA-SOC-Agent"
python agent.py
```

#### 3. Create Scheduled Task

```powershell
# Run PowerShell as Administrator
$action = New-ScheduledTaskAction -Execute "C:\ILA-SOC-Agent\run_agent.bat" -WorkingDirectory "C:\ILA-SOC-Agent"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)

Register-ScheduledTask -TaskName "ILA-SOC-Agent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "ILA-SOC Log Collection Agent"
```

#### 4. Start the Task

```powershell
Start-ScheduledTask -TaskName "ILA-SOC-Agent"
```

### Option 2: Windows Service (Using NSSM)

NSSM (Non-Sucking Service Manager) allows running any executable as a Windows service.

#### 1. Download NSSM

Download from: https://nssm.cc/download

#### 2. Install as Service

```powershell
# Run as Administrator
nssm install ILA-SOC-Agent "C:\Python311\python.exe" "C:\ILA-SOC-Agent\agent.py"
nssm set ILA-SOC-Agent AppDirectory "C:\ILA-SOC-Agent"
nssm set ILA-SOC-Agent DisplayName "ILA-SOC Log Collection Agent"
nssm set ILA-SOC-Agent Description "Collects and forwards security logs to ILA-SOC server"
nssm set ILA-SOC-Agent Start SERVICE_AUTO_START
nssm set ILA-SOC-Agent AppStdout "C:\ILA-SOC-Agent\service.log"
nssm set ILA-SOC-Agent AppStderr "C:\ILA-SOC-Agent\service_error.log"
```

#### 3. Start the Service

```powershell
nssm start ILA-SOC-Agent
```

#### 4. Service Management

```powershell
# Check status
nssm status ILA-SOC-Agent

# Stop service
nssm stop ILA-SOC-Agent

# Restart service
nssm restart ILA-SOC-Agent

# Remove service
nssm remove ILA-SOC-Agent confirm
```

### Option 3: Python Windows Service (Using pywin32)

For production deployments, you can convert the agent to a native Windows service.

#### 1. Install pywin32

```powershell
pip install pywin32
```

#### 2. Create Windows Service Wrapper

Create `windows_service.py`:

```python
import win32serviceutil
import win32service
import win32event
import servicemanager
import sys
import os

# Add agent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import ILASOCAgent

class ILASOCService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'ILASOCAgent'
    _svc_display_name_ = 'ILA-SOC Log Collection Agent'
    _svc_description_ = 'Collects and forwards security logs to ILA-SOC server'

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.agent:
            self.agent.stop()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        self.agent = ILASOCAgent()
        self.agent.start()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(ILASOCService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(ILASOCService)
```

#### 3. Install and Run

```powershell
# Install the service
python windows_service.py install

# Start the service
python windows_service.py start

# Stop the service
python windows_service.py stop

# Remove the service
python windows_service.py remove
```

---

## Troubleshooting

### Common Issues

1. **Permission Denied on Log Files**
   - Linux: Ensure the service runs as root or a user with read access to log files
   - Windows: Run as Administrator or SYSTEM account

2. **Server Connection Failed**
   - Check `config.json` for correct server URL
   - Verify network connectivity to the server
   - Check firewall rules

3. **Agent Not Starting**
   - Check `agent.log` for error messages
   - Verify Python and dependencies are installed correctly

4. **Logs Not Being Collected**
   - Verify log file paths in `config.json`
   - Check if files exist and are readable
   - On Windows, ensure the agent runs with elevated privileges for Event Log access

### Log Files

- Agent activity log: `agent.log` (in the agent directory)
- Buffered logs database: `log_buffer.db` (SQLite database for offline storage)

### Health Check

To verify the agent is running correctly:

1. Check the agent log file for recent activity
2. Verify heartbeats are being sent (every 60 seconds by default)
3. Check the server's agent list to confirm the agent is registered

---

## Uninstallation

### Linux

```bash
sudo systemctl stop ila-soc-agent
sudo systemctl disable ila-soc-agent
sudo rm /etc/systemd/system/ila-soc-agent.service
sudo systemctl daemon-reload
sudo rm -rf /opt/ila-soc-agent
```

### Windows (Task Scheduler)

```powershell
Unregister-ScheduledTask -TaskName "ILA-SOC-Agent" -Confirm:$false
Remove-Item -Recurse -Force "C:\ILA-SOC-Agent"
```

### Windows (NSSM)

```powershell
nssm stop ILA-SOC-Agent
nssm remove ILA-SOC-Agent confirm
Remove-Item -Recurse -Force "C:\ILA-SOC-Agent"
```
