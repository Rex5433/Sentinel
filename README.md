# Sentinel

A locally hosted, homegrown cybersecurity analysis tool designed for log interpretation, network monitoring, and incident response. Developed by **ROAR Cyber** and inspired by OptimSecurity's Security Dashboard.

## Setup
- Download the repository using **Code → Download ZIP**, then extract it to a writable folder.
- Install Python 3.11 or newer. On Windows, add Python to PATH and include Tcl/Tk for the desktop launcher.
- **Windows:** Double-click `Start Sentinel.vbs` to open the desktop launcher, or run `Start Sentinel.bat` for the console launcher.
- **macOS:** Open Terminal in the extracted folder and run `bash "Start Sentinel.command"`.
- **First launch:** Stay online while Sentinel installs its Python dependencies. Create a local owner account when prompted, then sign in when the dashboard opens. If the browser stays closed, open the local URL shown by the launcher.
- **Later launches:** Use the same launcher. The local dashboard can start offline after setup. Keep the launcher open while using Sentinel.

## Features

### Logs
- Import and analyze Windows and Linux system logs.
- Identify suspicious activity and authentication failures.
- Review flagged events and detection summaries.
- Inspect original event records.
- Paste Windows or Linux log text and save it under a custom name.
- Search saved logs, download the original, edit a copy, or delete a saved entry.
- Label events involving Blue Team and environment user accounts while keeping security flags visible.

### Live Logs
- Watch Windows event logs and Linux journal entries over SSH using a password or private key.
- Review flagged events as new records arrive and keep watches running while using other tabs.
- Save a capture to Logs or automatically archive new records.

### Network
- Analyze network traffic and packet captures.
- Review network connections, protocols, and ports.
- Identify unusual communication patterns.

### Timeline
- View security events in chronological order.
- Track suspicious activity across multiple events.
- Correlate findings during investigations.

### Commands
- Reference Windows PowerShell and Linux Bash commands.
- Access commands for security investigations and troubleshooting.
- Support manual, authorized incident-response workflows.

### MySQL
- Build and copy terminal commands for MySQL 8.0 and 8.4.
- Inspect databases, tables, and grants, or preview rows with filters.
- Generate a schema-only export or a guarded one-row update for manual review and execution.

### Changes
- Review account and privilege changes.
- Identify service and process modifications.
- Investigate security-relevant system changes.
- Compare Windows or Linux inventory snapshots and generate recovery commands for manual use.

### Wazuh Tools
- Connect to the Wazuh VM over SSH using a password or private key. Verify new host keys once and reconnect with saved settings.
- Run Nmap on the Wazuh VM against authorized targets. Review scan results, compare scan history, and see port changes in Timeline.
- Open the native Wazuh Dashboard in a separate tab and save connection settings per laptop for localhost or private hotspot access.

### SIEM Agents
- Collect logs from multiple Windows and Linux hosts over read-only SSH and review findings by severity.
- Check host connection and collector status, then pause the view while collection continues.
- Import or export host profiles and save live captures to the Logs library.

## Machine Learning
- Custom CNN-based security event classifier.
- Locally trained without third-party pretrained model weights.
- Designed to distinguish normal activity from suspicious patterns.
- Experimental detection with rule-based analysis.

## Technology
- **Backend:** Python, FastAPI
- **Frontend:** HTML, CSS, JavaScript
- **Machine Learning:** PyTorch
- **Deployment:** Local hosting

## Project Information
- **Developer:** Purdue ROAR Cyber
- **Project:** Sentinel
- **Purpose:** Cybersecurity research, training, and competition preparation
- **Status:** Active development

*Sentinel is an experimental security analysis tool. Findings should be independently verified.*
