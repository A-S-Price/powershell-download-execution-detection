# PowerShell Download & Execution Detection (MDE + KQL)

Custom Microsoft Defender for Endpoint (MDE) detection rule using KQL to identify suspicious PowerShell behavior where a command line includes both `Invoke-WebRequest` and `Start-Process`.

This project demonstrates the full workflow: simulate activity → hunt with KQL → trigger a custom detection → review alert + process timeline.

## Detection Summary
- **Data source:** MDE Advanced Hunting (`DeviceProcessEvents`)
- **Behavior:** download + execute via PowerShell
- **Suspicious flags:** `-ExecutionPolicy Bypass`, `-NoProfile`

## MITRE ATT&CK
- **T1059.001 – Command and Scripting Interpreter: PowerShell**

## Detection in Action

### 1. Attack Execution
The following PowerShell command simulates downloading and executing a file:

![Attack Command](screenshots/attack-command.png)

---

### 2. KQL Query Results
The detection query identifies PowerShell processes with download and execution behavior:

![KQL Results](screenshots/kql-query.png)

---

### 3. Alert Details
A custom detection alert is generated based on the query:

![Alert Details](screenshots/alert-details.png)

---

### 4. Process Timeline
The process tree shows the sequence of events from command execution to file launch:

![Process Timeline](screenshots/process-timeline.png)

---

### 5. Device Context
Additional context about the affected device:

![Device Overview](screenshots/device-overview.png)
