# Sentinel

A locally hosted, homegrown cybersecurity analysis tool designed for log interpretation, network monitoring, and incident response. Developed by **Team 84** and inspired by OptimSecurity's Security Dashboard.

## Features

### Logs
- Import and analyze Windows and Linux system logs.
- Identify suspicious activity and authentication failures.
- Review flagged events and detection summaries.
- Inspect original event records.

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

### Changes
- Review account and privilege changes.
- Identify service and process modifications.
- Investigate security-relevant system changes.

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
- **Developer:** Team 84
- **Project:** Sentinel
- **Purpose:** Cybersecurity research, training, and competition preparation
- **Status:** Active development

*Sentinel is an experimental security analysis tool. Findings should be independently verified.*
