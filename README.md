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

### 5. Device Context (Optional)
Additional context about the affected device:

![Device Overview](screenshots/device-overview.png)
