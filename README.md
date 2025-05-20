
⸻

What This Project Does

This SOC Automation Project simulates a real-world Security Operations Center (SOC) pipeline using Wazuh, Shuffle, and TheHive—all deployed on AWS infrastructure. It demonstrates how to automate detection, triage, enrichment, case creation, analyst notification, and active response actions in a modern cybersecurity workflow.

⸻

1. Real-Time Threat Detection (Wazuh SIEM)
	•	Wazuh monitors endpoint activity via a Windows 10 VM with Sysmon installed.
	•	A specific rule (e.g., Mimikatz execution) triggers an alert with detailed telemetry.
	•	Alerts are filtered by rule ID and forwarded to Shuffle through a custom webhook integration.

⸻

2. Security Orchestration (Shuffle SOAR)
	•	Shuffle receives alerts via webhook and launches a prebuilt automation workflow:
	•	Regex node parses out file hashes (SHA-256) from the alert.
	•	VirusTotal app checks the hash’s reputation.
	•	Alert details are formatted for an email to notify analysts.
	•	Optionally triggers Wazuh’s API to launch an active response based on conditions.

⸻

3. Threat Enrichment (VirusTotal API)
	•	The extracted file hash is automatically queried against VirusTotal.
	•	Reputation data (e.g., malicious count) is returned and passed along to the workflow.
	•	Malicious ratings are included in the alert for analyst decision-making.

⸻

4. Case Management (TheHive)
	•	Alerts are automatically sent to TheHive, creating detailed case records:
	•	Includes host, user, process ID, command line, hash, and timestamp
	•	Custom summary and description help prioritize and triage incidents
	•	Analysts can track all SOC events within TheHive’s dashboard.

⸻

5. Analyst Notification (Email Integration)
	•	Shuffle sends automated emails with key alert data (host, user, hash, description).
	•	Analysts receive actionable summaries and links to investigate further.
	•	Emails use disposable secure mailboxes (SquareX) to avoid exposing real inboxes during testing.

⸻

6. Optional: Active Response Capability
	•	If enabled, Shuffle can send a Wazuh API command to block a malicious IP via iptables.
	•	The workflow includes:
	•	Analyst input via email or approval
	•	A dynamic firewall rule pushed to the affected Linux host
	•	This simulates real-time containment of a threat post-detection.

⸻

7. Workflow Summary

Trigger → Mimikatz alert from Wazuh agent
SOAR Flow → Shuffle webhook → parse → enrich → notify → case create
Response → Optional Wazuh firewall rule (block IP)

This lab mimics modern SOC tooling to detect, investigate, and respond to threats in a fully automated pipeline.

⸻
