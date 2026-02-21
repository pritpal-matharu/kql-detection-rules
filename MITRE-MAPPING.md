# MITRE ATT&CK Mapping

This document maps all KQL detection rules in this repository to MITRE ATT&CK techniques and tactics.

## Endpoint Detections

### Suspicious Process Creation from System Directories
- **File:** `detections/endpoint/suspicious_process_creation.kql`
- **MITRE Tactics:** Execution, Defense Evasion
- **MITRE Techniques:**
  - [T1036](https://attack.mitre.org/techniques/T1036/) - Masquerading
  - [T1202](https://attack.mitre.org/techniques/T1202/) - Indirect Command Execution
- **Data Sources:** DeviceProcessEvents
- **Alert Threshold:** Process appears 2+ times from unusual directories (temp, downloads, recycler)
- **Key Detections:**
  - Processes created from AppData temp folders
  - Processes with encoded commands (-enc, -encodedcommand)
  - Suspicious named pipes

---

## Identity Detections

### Impossible Travel - Sign-in from Geographically Distant Locations
- **File:** `detections/identity/impossible_travel_signin.kql`
- **MITRE Tactics:** Initial Access, Lateral Movement
- **MITRE Techniques:**
  - [T1078](https://attack.mitre.org/techniques/T1078/) - Valid Accounts
  - [T1556](https://attack.mitre.org/techniques/T1556/) - Modify Authentication Process
- **Data Sources:** SigninLogs
- **Alert Threshold:** Same user sign-in from 900+ km/h travel speed (impossible for commercial flight)
- **Time Window:** Within 8 hours
- **Key Detections:**
  - Geographic distance calculation between consecutive sign-ins
  - Required travel speed exceeds human capability
  - Cross-country/continent sign-ins within minutes

---

## Cloud Detections

### Suspicious Azure Resource Deletion Activity
- **File:** `detections/cloud/suspicious_azure_resource_deletion.kql`
- **MITRE Tactics:** Impact, Defense Evasion
- **MITRE Techniques:**
  - [T1485](https://attack.mitre.org/techniques/T1485/) - Data Destruction
  - [T1531](https://attack.mitre.org/techniques/T1531/) - Account Access Removal
- **Data Sources:** AzureActivity
- **Alert Threshold:**
  - 5+ deletions within 1 hour = HIGH
  - 10+ deletions within 1 hour = CRITICAL
- **Monitored Resources:**
  - Storage Accounts
  - Virtual Machines
  - Network Security Groups (NSGs)
  - Key Vaults
  - Cosmos DB instances

---

## Email Detections

### Phishing Emails with Malicious Attachments and URL Threats
- **File:** `detections/email/phishing_with_malicious_attachments.kql`
- **MITRE Tactics:** Initial Access
- **MITRE Techniques:**
  - [T1566](https://attack.mitre.org/techniques/T1566/) - Phishing
  - [T1598](https://attack.mitre.org/techniques/T1598/) - Phishing for Information
- **Data Sources:** EmailEvents, EmailAttachmentInfo, UrlClickEvents
- **Alert Threshold:**
  - Campaign targeting 3+ users = MEDIUM
  - Campaign targeting 5+ users = HIGH
  - Campaign targeting 10+ users = CRITICAL
- **Key Detections:**
  - Executable attachments (.exe, .scr, .bat, .cmd, .vbs, .js)
  - Archive files with suspicious content (.zip, .rar, .7z)
  - Malicious URLs (Malware, Phishing, PUA threats)
  - External senders with domain spoofing

---

## Helper Functions

### IP Address Threat Intelligence Enrichment
- **File:** `helper-functions/fn_enrich_ip_threat_intelligence.kql`
- **Type:** Reusable KQL Function
- **Purpose:** Enrich any detection with IP threat intelligence
- **Returns:** Threat level (clean, suspicious, malicious) and severity
- **Usage:**
  ```kql
  SigninLogs
  | invoke fn_enrich_ip_threat_intelligence("IPAddress")
  | where threat_level == "malicious"
  ```

---

## Coverage Summary

| Tactic | Count | Coverage |
|--------|-------|----------|
| Initial Access | 1 | Phishing detection |
| Execution | 1 | Process creation |
| Lateral Movement | 1 | Impossible travel |
| Defense Evasion | 2 | Process masquerading, resource deletion |
| Impact | 1 | Data destruction |
| **Total Techniques** | **6** | - |

---

## Updating This Document

When adding new detection rules:
1. Add MITRE technique mapping in the rule header
2. Update this document with new technique entry
3. Include data source, alert threshold, and key detections
4. Reference official MITRE ATT&CK documentation

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Threat Intelligence Blog](https://www.microsoft.com/security/blog/)
- [Azure Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
