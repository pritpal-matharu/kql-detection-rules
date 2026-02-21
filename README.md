# kql-detection-rules

KQL analytics detection rules for Microsoft Sentinel, focused on enterprise cloud security operations and mapped to MITRE ATT&CK.

## Goals

- Provide reusable KQL queries for common attacker TTPs.
- Serve as a reference for building high-fidelity, low-noise detections.
- Showcase detection engineering patterns for Microsoft Sentinel.

## Folder layout

- `detections/endpoint` – Endpoint and Defender for Endpoint–centric rules.
- `detections/identity` – Entra ID, risky sign-ins, token abuse.
- `detections/cloud` – Azure control-plane, resource abuse, and IAM anomalies.
- `detections/email` – Defender for Office 365–centric rules.
- `helper-functions` – Reusable KQL functions (parsers, normalizers).
- `MITRE-MAPPING.md` – ATT&CK technique mappings.

## Example rule template

Each rule should include:

- Description
- Data sources
- MITRE ATT&CK mapping
- Tuning guidance

```kql
// Title: Suspicious Azure Portal sign-in from new country
// Data source: SigninLogs
// MITRE: T1078 – Valid Accounts

SigninLogs
| where AppDisplayName == "Azure Portal"
| summarize count() by UserPrincipalName, Country = LocationDetails.countryOrRegion, bin(TimeGenerated, 1h)
| join kind=inner (
    SigninLogs
    | summarize Countries = make_set(LocationDetails.countryOrRegion) by UserPrincipalName
) on UserPrincipalName
| where array_length(Countries) > 1
```
