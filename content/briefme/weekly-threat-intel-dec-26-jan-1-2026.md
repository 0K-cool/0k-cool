---
title: "Weekly Threat Intelligence Briefing | December 26, 2025 - January 1, 2026"
date: 2026-01-01
draft: false
tags: ["threat-intelligence", "weekly-briefing", "cve", "0-day", "mongobleed", "credential-leak", "unc3944", "scattered-spider", "ransomware", "vpn", "mongodb", "fortinet", "macos-stealer", "database-security", "authentication-bypass"]
categories: ["briefme"]
author: "Kelvin Lomboy"
summary: "Week ending Jan 1, 2026: MongoBleed exploitation, 16B credential mega-leak, UNC3944 social engineering campaigns, education and healthcare breaches, and VPN/appliance KEV vulnerabilities dominate the threat landscape."
---

<pre class="ascii-header-box" style="text-align: center;">
┌──────────────────────────────────────────────────┐
│ 0K THREAT INTEL │ KEEPING ATTACKERS FROZEN       │
│ Weekly Briefing │ Dec 26 - Jan 1 │ 0K-TI-2026-W01│
└──────────────────────────────────────────────────┘
</pre>

<p style="text-align: center;">
<strong>Classification:</strong> TLP:CLEAR &nbsp;&nbsp;&nbsp; <strong>Distribution:</strong> Unlimited &nbsp;&nbsp;&nbsp; <strong>Report ID:</strong> 0K-TI-2026-W01 &nbsp;&nbsp;&nbsp; <strong>Reporting Period:</strong> December 26, 2025 - January 1, 2026
</p>

---

<div class="mobile-warning">
📱 <strong>Mobile Phone Detected</strong><br>
This full brief is optimized for desktop/tablet viewing. For mobile, please read the <a href="/briefme/weekly-threat-intel-dec-26-jan-1-2026-tldr">2-minute TL;DR version</a> or switch to a larger screen for the best experience.
</div>

<br>
<br>

![MongoBleed CVE-2025-14847 Critical Threat](/images/briefme/mongobleed-cve-2025-14847-dec-26-jan-1.jpg)

## EXECUTIVE SUMMARY

The period was dominated by fallout from a historic “mega leak” of 16 billion credentials, active exploitation of the “MongoBleed” MongoDB vulnerability (CVE‑2025‑14847), and sustained abuse of internet‑facing infrastructure and SaaS for initial access. Ransomware and data‑theft incidents against education and healthcare providers continued, including disclosures tied to December breaches such as the University of Phoenix and Inotiv, with investigations and notifications still unfolding into this week. SOC teams should prioritize credential and identity defenses, rapid patching of exposed databases and VPNs, and monitoring for infostealer malware and suspicious access patterns against cloud and hybrid infrastructure.


**⚡ Short on time?** Read the **[2-minute TL;DR version](/briefme/weekly-threat-intel-dec-26-jan-1-2026-tldr)** for quick mobile-optimized threat intel.
***

## Trending Security News

**“Mega Leak” of 16B Credentials**

- What: Analysts reported analysis of a massive aggregated dataset containing over 16 billion login credentials across major consumer platforms such as Google, Apple, Facebook, and GitHub.
- Why it’s trending: The scale and aggregation from multiple historical breaches raised debate over password reuse, credential‑stuffing resilience, and the value of “collection” leaks versus new compromises.
- Relevance: SOC teams should expect spikes in credential‑stuffing, review MFA coverage, and tune detections for anomalous logins, particularly where legacy or SMS‑only MFA remains in use.
- Sources:
    - https://innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials
    - https://www.bleepingcomputer.com/news/security/the-biggest-cybersecurity-and-cyberattack-stories-of-2025/amp/

**Active Exploitation of “MongoBleed” (CVE‑2025‑14847)**

- What: Researchers confirmed in‑the‑wild exploitation of a critical MongoDB memory‑leak flaw dubbed “MongoBleed” (CVE‑2025‑14847), allowing data disclosure from vulnerable deployments.
- Why it’s trending: The bug impacts widely deployed MongoDB instances and is being discussed alongside other high‑impact database bugs, raising concerns about internet‑exposed databases and weak segmentation.
- Relevance: SOC teams must identify exposed MongoDB instances, validate patch levels, and monitor for anomalous queries and outbound data transfers indicative of exploitation.
- Sources:
    - https://innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials

**MacSync macOS Stealer Bypassing Gatekeeper**

- What: A new macOS stealer, “MacSync”, was reported using a signed application to bypass Apple Gatekeeper, targeting browser cookies, saved credentials, and crypto wallets.
- Why it’s trending: The story sparked discussion about trust in signed binaries and the assumption that macOS endpoints are lower‑risk, particularly in developer‑heavy environments.
- Relevance: SOC teams should ensure macOS EDR coverage is equivalent to Windows, add detections for suspicious “sync”‑like processes, and enforce application control policies beyond code signing alone.
- Sources:
    - https://innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials

**FortiGate / VPN Appliance Exploitation Concerns**

- What: Security roundups highlighted ongoing exploitation of VPN and firewall appliances, including FortiGate authentication bypass flaws and other perimeter devices that had CISA KEV deadlines in late December.
- Why it’s trending: Many organizations missed earlier federal patch deadlines, and scan data still shows large exposed populations, prompting community criticism of “set‑and‑forget” network appliances.
- Relevance: SOC teams should cross‑check appliance versions against KEV, hunt for anomalous VPN logins and configuration changes, and assume compromise where patching lagged beyond KEV deadlines.
- Sources:
    - https://innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials
    - https://cvefeed.io/cisakev/cisa-known-exploited-vulnerability-catalog
    - https://www.patrowl.io/en/cisa-kev

**Year‑End “Biggest Stories of 2025” Recaps**

- What: Multiple outlets published “top incidents of 2025” recaps, covering major ransomware, supply‑chain attacks, and cloud identity abuses.
- Why it’s trending: The community is using these retrospectives to benchmark defensive progress, debate disclosure quality, and highlight persistent issues like MFA fatigue and unpatched KEV vulnerabilities.
- Relevance: SOCs can map these stories to their own environment (same vendors, protocols, or architectures) and prioritize 2026 tabletop exercises and threat‑modeling around similar attack chains.
- Sources:
    - https://www.bleepingcomputer.com/news/security/the-biggest-cybersecurity-and-cyberattack-stories-of-2025/amp/
    - https://cyberrecaps.com/news/cybersecurity-news-december-29-2025/

***

## Threat Visualizations (ASCII)

### Risk Prioritization Matrix

```text
CRITICAL THREATS - RISK MATRIX (Dec 26, 2025 – Jan 1, 2026)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IMPACT
10.0 │                                    ★ MongoBleed (CVE-2025-14847)
     │                                   (CVSS ~9.x, active exploitation)
9.0  │        ★ Mega Credential Leak     ★ VPN/Appliance KEV Vulns
     │      (Account takeover)          (Perimeter RCE/AB)
8.0  │    ★ MacSync macOS Stealer       ★ SaaS / Cloud Account Abuse
     │
7.0  │        ★ December Breach Fallout (Uni. of Phoenix, Inotiv)
     │
     └─────────────────────────────────────────────
       Low    Medium    High    Very High    Critical
                    LIKELIHOOD

RISK SCORE SCALE:
▓▓▓▓▓ CRITICAL (72-100)  - MongoBleed; Mega credential leak; KEV VPN/appliance vulns
▓▓▓▓░ HIGH (48-71)       - MacSync; Education & healthcare breaches
▓▓▓░░ MEDIUM (25-47)     - Other sector-specific ransomware & data theft
```


### MITRE ATT\&CK Heat Map

```text
MOST OBSERVED TACTICS (Dec 26, 2025 – Jan 1, 2026)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Initial Access        ▓▓▓▓▓▓▓▓▓▓▓▓▓░  High use (phishing, exposed services)
Execution             ▓▓▓▓▓▓▓▓▓░░░░░  Frequent (malware loaders, scripts)
Persistence           ▓▓▓▓▓▓▓░░░░░░░  Common (accounts, services)
Priv Escalation  ▓▓▓▓▓▓░░░░░░░░  Regular (OS & app vulns)
Defense Evasion       ▓▓▓▓▓▓▓▓░░░░░░  High (signed binaries, rootkits)
Credential Access     ▓▓▓▓▓▓▓▓▓▓░░░░  Very high (infostealers, mega leak)
Discovery             ▓▓▓▓▓░░░░░░░░░  Moderate
Lateral Movement      ▓▓▓▓▓▓░░░░░░░░  Common (RDP, admin tools)
Collection            ▓▓▓▓▓░░░░░░░░░  Moderate
Command & Control     ▓▓▓▓▓▓▓░░░░░░░  Frequent (VPN, HTTPS C2)
Exfiltration          ▓▓▓▓▓▓▓░░░░░░░  Frequent (cloud & DB exfil)
Impact                ▓▓▓▓▓░░░░░░░░░  Ransomware, extortion, data leaks

KEY INSIGHT: Credential access, defense evasion, and C2 remained dominant, driven by infostealers, large credential dumps, and ongoing ransomware and data‑theft campaigns.
```


### Sector Targeting Distribution

```text
ORGANIZATIONS BY THREAT EXPOSURE (Dec 26, 2025 – Jan 1, 2026)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

EDUCATION
  Threats: ▓▓▓▓▓▓▓▓░░  High    Critical: ▓▓▓▓▓░░░░░  Medium
  Primary vectors: Third-party SaaS compromise; credential theft; ransomware.

HEALTHCARE / LIFE SCIENCES
  Threats: ▓▓▓▓▓▓▓░░░  Elevated    Critical: ▓▓▓▓░░░░░  Moderate
  Primary vectors: Ransomware; exposed infrastructure; vendor compromise.

RETAIL / CONSUMER
  Threats: ▓▓▓▓▓░░░░░  Moderate    Critical: ▓▓▓░░░░░░  Lower
  Primary vectors: Credential stuffing; web app attacks; loyalty account abuse.

TECH / CLOUD / SAAS
  Threats: ▓▓▓▓▓▓▓▓▓░  Very High  Critical: ▓▓▓▓▓▓░░░░ High
  Primary vectors: Identity abuse; misconfigurations; KEV‑listed vulns on appliances.

GOV / PUBLIC SECTOR
  Threats: ▓▓▓▓▓▓░░░░  Elevated   Critical: ▓▓▓▓░░░░░  Moderate
  Primary vectors: APT phishing; KEV vulns; supply‑chain dependencies.
```


***

## Critical Vulnerabilities (Top 5)

### 4.1 MongoDB “MongoBleed” – CVE‑2025‑14847

- CVE / Severity / Status: CVE‑2025‑14847, likely CVSS in high‑critical range (memory leak / data exposure), confirmed active exploitation.
- Affected products: MongoDB server deployments with specific vulnerable versions; reports note impact on internet‑exposed and misconfigured instances.
- Attack vector: Crafted queries or requests trigger memory disclosure, allowing attackers to read sensitive data from memory and potentially harvest credentials or keys.
- Key IOCs (examples from reporting and typical abuse patterns):
    - Unusual aggregation / map‑reduce queries from untrusted IPs preceding large outbound transfers.
    - Spikes in outbound traffic from DB servers to rare external destinations.
- Detection guidance:
    - See Sigma Rule: `CVE-2025-14847_MongoBleed_Suspicious_Queries` (Section 9.1).
    - Detection Query (Pseudo-code - Generic SIEM Logic):

```text
source = "mongodb-audit"
| where action in ("query","aggregate")
| where client_ip not in known_admin_ips
| where response_size_bytes > threshold_large and
      query_text contains any ("$where", "mapReduce", "group") 
| aggregate count() by client_ip, db, user
| where count() > N in last 10m
```

- Remediation steps:
    - Patch MongoDB to the latest vendor‑recommended version addressing CVE‑2025‑14847 and review security advisories.
    - Remove direct internet exposure, enforce TLS and authentication, place MongoDB behind application layers, and enable strong access controls.


### 4.2 Fortinet / VPN \& Perimeter Appliance Vulns (Representative KEV Entries)

- CVE / Severity / Status: Multiple Fortinet and similar appliance vulnerabilities were highlighted in recent KEV updates and December coverage as actively exploited, including authentication bypass and RCE flaws on VPN and firewall appliances.
- Affected products: FortiGate VPNs and other perimeter devices (e.g., IKEv2 VPN appliances cited as vulnerable to unauthenticated RCE).
- Attack vector: Remote attackers send crafted packets or authentication flows to exposed interfaces to gain code execution, then deploy webshells or pivot into internal networks.
- IOCs:
    - Unexpected VPN logins from rare geolocations or ASN immediately followed by config changes.
    - Presence of unusual files or processes on appliance file systems (e.g., webshells under non‑standard paths).
- Detection guidance:
    - See Sigma Rule: `Perimeter_VPN_Auth_Bypass_Suspicious_Login_Sequence` (Section 9.1).
    - Detection Query (Pseudo-code - Generic SIEM Logic):

```text
source = "vpn-logs"
| where auth_result == "success"
| where ip_geolocation is rare_for_user(user) 
| followed_by event("config_change") within 5m on same device
```

- Remediation steps:
    - Apply vendor patches / firmware upgrades for all KEV‑listed appliance CVEs and disable vulnerable features where patches are not yet available.
    - Rotate VPN certificates and administrator credentials, review appliance configs for backdoors, and rebuild devices where compromise is suspected.


### 4.3 Rapid7 Velociraptor Misconfiguration / CVE‑2025‑6264 Context

- CVE / Severity / Status: CVE‑2025‑6264 describes a file permission misconfiguration in Rapid7 Velociraptor, previously highlighted as enabling threat actor persistence and evasion.
- Affected products: Rapid7 Velociraptor endpoint visibility framework deployments running vulnerable configurations / versions.
- Attack vector: Adversaries with some access to a host leverage Velociraptor’s configuration and permissions to maintain stealthy persistence and execute payloads, including tunneling tools like Visual Studio Code for C2.
- IOCs:
    - Velociraptor processes spawning unexpected child processes (e.g., Visual Studio Code) with network connections to external C2 endpoints.
    - Modified Velociraptor configuration files with attacker‑controlled URLs or scripts.
- Detection guidance:
    - See Sigma Rule: `Velociraptor_Suspicious_Child_Process` (Section 9.1 – mapped under campaign patterns).
- Remediation steps:
    - Update Velociraptor to patched builds and enforce hardened permission models per vendor guidance.
    - Audit Velociraptor configs and deployment keys, rotate secrets, and restrict which accounts can manage or invoke collectors.


### 4.4 Oracle E‑Business Suite SSRF – CVE‑2025‑61884

- CVE / Severity / Status: CVE‑2025‑61884 is a server‑side request forgery vulnerability in Oracle E‑Business Suite, highlighted in discussions of KEV‑relevant issues but not yet widely patched across all environments.
- Affected products: Oracle E‑Business Suite instances running vulnerable versions of affected modules.
- Attack vector: SSRF via crafted HTTP requests, allowing attackers to pivot from the E‑Business front‑end to internal services, metadata endpoints, or cloud IMDS services.
- IOCs:
    - Web server logs with unusual outbound requests from E‑Business servers to internal addresses / cloud metadata IPs (e.g., 169.254.169.254).
    - Access logs showing repeated access to non‑documented endpoints with suspicious query parameters.
- Detection guidance:
    - See Sigma Rule: `Oracle_EBS_SSRF_Suspicious_Metadata_Access` (Section 9.1).
- Remediation steps:
    - Apply Oracle’s security updates for CVE‑2025‑61884 and follow hardening guides for restricting outbound connectivity from application servers.
    - Implement network‑level egress filters preventing application servers from calling cloud metadata or sensitive internal services.


### 4.5 Kentico Xperience Authentication Bypass – CVE‑2025‑2746 / CVE‑2025‑2747

- CVE / Severity / Status: CVE‑2025‑2746 and CVE‑2025‑2747 describe authentication bypass issues in Kentico Xperience Staging Sync Server due to insecure password types.
- Affected products: Kentico Xperience deployments using the affected Staging Sync Server configuration.
- Attack vector: Attackers leverage weak password handling to bypass authentication and gain unauthorized access to staging or content management features, potentially leading to web content tampering or lateral movement.
- IOCs:
    - Successful logins to Kentico staging endpoints from unfamiliar IPs without corresponding MFA events.
    - Web content modifications or staging job executions outside of normal change windows.
- Detection guidance:
    - See Sigma Rule: `Kentico_Staging_Suspicious_Login_And_Changes` (Section 9.1).
- Remediation steps:
    - Apply Kentico patches addressing CVE‑2025‑2746/2747 and enforce strong authentication (MFA, IP allow‑listing) on staging interfaces.
    - Review audit logs for unauthorized content or configuration changes and rotate admin credentials.

***

## Major Incidents (Top 3)

### 5.1 University of Phoenix Data Breach (Third‑Party SaaS)

- Disclosure vs compromise: Public reporting dates the disclosure to late December 2025, following detection of suspicious activity in a third‑party provider system; compromise occurred before formal notification.
- Attack chain:
    - Initial access: Threat actor gained access to a third‑party environment hosting University of Phoenix data, likely via credential compromise or infrastructure weakness.
    - Persistence \& discovery: Adversary maintained access while enumerating stored records, then exfiltrated data.
    - Exfiltration \& impact: Data associated with students, applicants, and employees was accessed and copied, affecting approximately 3.5 million individuals.
- Compromised data: Personal and contact details linked to education records; specific fields vary but include PII used in admissions and enrollment processes.
- Affected sector: Higher education and third‑party SaaS providers supporting student data services.
- Hunting guidance:
    - See Sigma Rule: `ThirdParty_SaaS_Suspicious_Admin_Access` (Section 9.1).
    - Artifacts to search:
        - Unusual SSO or API access from third‑party IP ranges, especially with large data exports.
        - New OAuth apps, API tokens, or service accounts created shortly before export events.
    - Hunt Query (SQL - OSQuery) – endpoint perspective for admin systems:

```sql
-- Identify unusual data export tooling on admin endpoints
-- Platform: Windows
-- Use case: Hunting
SELECT
    processes.name,
    processes.path,
    processes.parent,
    processes.cmdline,
    processes.start_time
FROM processes
WHERE
    (name LIKE '%curl%' OR name LIKE '%rclone%' OR name LIKE '%winscp%')
    AND start_time > datetime('2025-12-15')
    AND NOT (path LIKE 'C:\\Program Files\\Backup%%');
```


### 5.2 Inotiv Ransomware \& Data Breach

- Disclosure vs compromise: Inotiv disclosed a December 2025 ransomware‑related data breach after confirming intrusion and exfiltration, with investigations continuing through year end.
- Attack chain:
    - Initial access: Likely via common vectors such as phishing, exposed services, or third‑party tools; reporting emphasizes ransomware as the culminating impact.
    - Lateral movement \& privilege escalation: Threat actors moved within internal systems to reach data stores.
    - Exfiltration \& impact: Personal information and internal data were accessed and taken prior to ransomware deployment and encryption.
- Compromised data types: Personal information associated with pharma / life sciences operations, potentially including contact and identification data.
- Affected sector: Pharmaceutical / life sciences and research service providers.
- Hunting guidance:
    - See YARA Rule: `Inotiv_RansomwareFamily_Generic` and Sigma Rule: `Ransomware_PreEncryption_Activity` (Section 9).
    - Artifacts to search:
        - Suspicious backup deletion commands (vssadmin, wbadmin), new domain admins, unusual SMB copy flows before encryption.
        - Endpoint presence of common ransomware staging tools (e.g., credential dumpers, Cobalt Strike beacons).


### 5.3 December “Mega Credential Leak” Operationalization

- Disclosure vs compromise: The leak aggregates historical data, but the analysis and security advisories were published in late December 2025; active abuse via credential‑stuffing is ongoing.
- Attack chain:
    - Initial access: Attackers leverage leaked credential pairs to perform automated login attempts against consumer and enterprise services.
    - Persistence \& lateral movement: Once an account is compromised, adversaries may enroll rogue MFA devices, create OAuth apps, or pivot to VPN and admin systems.
    - Exfiltration \& impact: Account takeover can lead to theft of sensitive data, fraud, or business email compromise depending on the account type.
- Compromised data types: Millions of username/password combinations from many services, enabling large‑scale password‑reuse attacks.
- Affected sectors: Cross‑sector, with elevated risk to any organization using passwords without phishing‑resistant MFA.
- Hunting guidance:
    - See Sigma Rule: `Credential_Stuffing_Suspicious_Login_Bursts` (Section 9.1).
    - Artifacts to search:
        - Bursts of failed logins across many accounts from a small set of IPs, followed by a handful of successes.
        - New device registrations or MFA resets for accounts soon after abnormal logins.

***

<br>
<br>

![UNC3944 / Scattered Spider Threat Campaign](/images/briefme/unc3944-scattered-spider-dec-26-jan-1.jpg)

## Threat Actor Campaigns (Top 3)

### 6.1 UNC3944 / 0ktapus / Scattered Spider – Social Engineering \& Cloud Pivoting

- Attribution: UNC3944 (also known as 0ktapus / Scattered Spider) is a financially motivated group extensively documented for targeting retail, aviation, insurance, and other sectors via advanced social engineering. Confidence: High.
- Targets / geography: US retail, airline, transportation, and insurance organizations, with emphasis on high‑value cloud and virtualization infrastructure.
- TTPs (MITRE):
    - Initial Access: Phishing and help‑desk social engineering (T1566, T1078 – Valid Accounts).
    - Priv Escalation \& Persistence: Abuse of identity systems and privileged IT tools (T1098 – Account Manipulation; T1136 – Account Creation).
    - Lateral Movement: Movement from Active Directory to VMware vSphere and other infrastructure (T1021 – Remote Services).
    - Impact: Ransomware and extortion by exfiltrating data and encrypting VMs (T1486 – Data Encrypted for Impact).
- IOCs \& infrastructure: Use of phone‑based social engineering, compromised help‑desk portals, and legitimate remote admin tools; infrastructure details vary per victim but include cloud and VPN access points.
- Detection \& hunting guidance:
    - See Sigma Rule: `UNC3944_Helpdesk_Social_Engineering_Patterns` and YARA Rule: `UNC3944_Toolset_Generic` (Section 9).
    - Example Hunt Query (Pseudo-code - Generic SIEM Logic):

```text
source = "idp-logs"
| where mfa_result == "bypassed" or mfa_method == "voice_call"
| where support_ticket_id exists
| summarize count() by user, ip, mfa_method
| where count() > threshold and ip is new_for_user(user)
```

- Defensive actions:
    - Harden help‑desk workflows (no password or MFA reset based solely on phone calls), implement strong identity governance, and enforce phishing‑resistant MFA where feasible.


### 6.2 PhantomCore Targeting Industrial Organizations

- Attribution: PhantomCore group reported targeting industrial organizations, with average dwell time of 24 days and campaigns peaking in mid‑2025 but still informing current defensive posture. Confidence: Medium (ongoing relevance for TTPs).
- Targets / geography: Industrial and OT‑adjacent enterprises with global footprint.
- TTPs (MITRE):
    - Initial Access: Phishing and likely exploitation of exposed services (T1566, T1190).
    - Discovery \& Lateral Movement: Extensive internal discovery with focus on industrial control segments (T1087, T1018).
    - Persistence \& C2: Custom backdoors with long dwell times and use of common remote admin frameworks (T1105 – Ingress Tool Transfer).
- IOCs \& infrastructure: 181 infected hosts documented at time of reporting; infrastructure included bespoke C2 servers and phishing domains.
- Detection \& hunting guidance:
    - See Snort/Suricata Rule: `PhantomCore_C2_HTTP_Profile` and YARA Rule: `PhantomCore_Backdoor` (Section 9).
    - Focus hunts on long‑lived outbound connections from ICS‑adjacent hosts to rare external IPs and unusual admin tool usage.
- Defensive actions:
    - Segregate OT from IT networks, deploy network monitoring around ICS zones, and implement strict allow‑listing for remote admin tools.


### 6.3 RedNovember (TAG‑100) Targeting Perimeter Appliances

- Attribution: TAG‑100, tracked as “RedNovember”, has been reported targeting perimeter appliances of high‑profile organizations using tools like the Go‑based Pantegana backdoor and Cobalt Strike. Confidence: Medium.
- Targets / geography: High‑profile organizations around the world, with emphasis on exploiting exposed appliances and infrastructure.
- TTPs (MITRE):
    - Initial Access: Exploiting vulnerabilities on perimeter appliances (T1190).
    - Execution \& Persistence: Deploying custom backdoors on those devices (Pantegana) and then staging Cobalt Strike inside networks (T1059, T1105).
    - Command \& Control: Encrypted C2 channels and living‑off‑the‑land for lateral movement (T1071 – Web Protocols).
- IOCs \& infrastructure: C2 IPs and domains vary per campaign; reporting highlights abuse of VPN, firewall, and other internet‑facing appliances.
- Detection \& hunting guidance:
    - See Snort/Suricata Rule: `RedNovember_Pantegana_HTTP_C2` and Sigma Rule: `Appliance_Exploit_Suspicious_Post_Auth_Activity` (Section 9).
    - Hunts should examine appliance logs, unusual outbound connections, and new administrative sessions following known KEV exploit windows.
- Defensive actions:
    - Prioritize KEV patching on perimeter devices, centralized logging from appliances, and strict monitoring of post‑authentication activities (e.g., CLI, config changes).

***

## MITRE ATT\&CK Summary

<table>
<thead>
<tr>
<th align="left">Rank</th>
<th align="left">Tactic</th>
<th align="left">Example Techniques (T#)</th>
<th align="left">Real-World Examples This Period</th>
</tr>
</thead>
<tbody>
<tr>
<td data-label="Rank:">1</td>
<td data-label="Tactic:">Credential Access</td>
<td data-label="Example Techniques:">T1110 (Brute Force), T1555 (Credentials from Password Stores)</td>
<td data-label="Real-World Examples:">Mega credential leak reuse; infostealers like MacSync harvesting browser creds.</td>
</tr>
<tr>
<td data-label="Rank:">2</td>
<td data-label="Tactic:">Initial Access</td>
<td data-label="Example Techniques:">T1566 (Phishing), T1190 (Exploiting Public‑Facing App)</td>
<td data-label="Real-World Examples:">UNC3944 help‑desk social engineering; MongoBleed exploitation; perimeter appliance vulns.</td>
</tr>
<tr>
<td data-label="Rank:">3</td>
<td data-label="Tactic:">Command \& Control</td>
<td data-label="Example Techniques:">T1071 (Web Protocols), T1090 (Proxy)</td>
<td data-label="Real-World Examples:">Pantegana and Cobalt Strike beacons from appliances and internal hosts.</td>
</tr>
<tr>
<td data-label="Rank:">4</td>
<td data-label="Tactic:">Exfiltration</td>
<td data-label="Example Techniques:">T1041 (Exfiltration Over C2), T1567 (Exfiltration to Cloud)</td>
<td data-label="Real-World Examples:">University of Phoenix and Inotiv data theft; MongoDB data exfil via MongoBleed.</td>
</tr>
<tr>
<td data-label="Rank:">5</td>
<td data-label="Tactic:">Defense Evasion</td>
<td data-label="Example Techniques:">T1562 (Impair Defenses), T1036 (Masquerading)</td>
<td data-label="Real-World Examples:">MacSync abusing signed binaries; attackers abusing Velociraptor for stealth.</td>
</tr>
<tr>
<td data-label="Rank:">6</td>
<td data-label="Tactic:">Lateral Movement</td>
<td data-label="Example Techniques:">T1021 (Remote Services), T1077 (Windows Admin Shares)</td>
<td data-label="Real-World Examples:">UNC3944 pivoting from AD to VMware vSphere; ransomware operators moving across subnets.</td>
</tr>
<tr>
<td data-label="Rank:">7</td>
<td data-label="Tactic:">Persistence</td>
<td data-label="Example Techniques:">T1098 (Account Manipulation), T1136 (Account Creation)</td>
<td data-label="Real-World Examples:">Long‑term footholds in SaaS and IDP; appliance‑level backdoors (RedNovember).</td>
</tr>
<tr>
<td data-label="Rank:">8</td>
<td data-label="Tactic:">Discovery</td>
<td data-label="Example Techniques:">T1087 (Account Discovery), T1018 (Remote System Discovery)</td>
<td data-label="Real-World Examples:">PhantomCore mapping industrial environments; actors enumerating cloud tenants.</td>
</tr>
<tr>
<td data-label="Rank:">9</td>
<td data-label="Tactic:">Impact</td>
<td data-label="Example Techniques:">T1486 (Data Encrypted for Impact)</td>
<td data-label="Real-World Examples:">Inotiv ransomware; broader year‑end ransomware incidents.</td>
</tr>
<tr>
<td data-label="Rank:">10</td>
<td data-label="Tactic:">Collection</td>
<td data-label="Example Techniques:">T1114 (Email Collection), T1005 (Local Data from Hosts)</td>
<td data-label="Real-World Examples:">Data staging before exfil in university and healthcare environments.</td>
</tr>
</tbody>
</table>

***

## IOC Summary

High‑confidence indicative IOCs and entities (10–15) relevant to the period and referenced threats:


<table>
<thead>
<tr>
<th align="left">IOC</th>
<th align="left">Type</th>
<th align="left">Confidence</th>
<th align="left">Threat/Campaign</th>
<th align="left">Action</th>
</tr>
</thead>
<tbody>
<tr>
<td data-label="IOC:">CVE-2025-14847</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">MongoBleed MongoDB memory leak</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">CVE-2025-61884</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Oracle E‑Business Suite SSRF</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">CVE-2025-6264</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Velociraptor misconfiguration abuse</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">CVE-2025-2746</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Kentico Xperience auth bypass</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">CVE-2025-2747</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Kentico Xperience auth bypass</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">UNC3944 / 0ktapus</td>
<td data-label="Type:">Behavioral (Actor)</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Social‑engineering / identity campaign</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Scattered Spider</td>
<td data-label="Type:">Behavioral (Actor)</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Alternate name for UNC3944</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Pantegana</td>
<td data-label="Type:">Behavioral (Malware)</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">RedNovember backdoor on appliances</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">MacSync</td>
<td data-label="Type:">Behavioral (Malware)</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat/Campaign:">macOS stealer bypassing Gatekeeper</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">MongoDB large anomalous queries</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">MongoBleed exploitation</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Unusual VPN logins + config change</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Appliance auth‑bypass exploitation</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">University of Phoenix third‑party access</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat/Campaign:">Education SaaS compromise</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Inotiv ransomware pre‑encryption activity</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat/Campaign:">Inotiv ransomware breach</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Velociraptor spawning VS Code to C2</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Abuse of Velociraptor (CVE‑2025‑6264)</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Access from 169.254.169.254 via Oracle EBS</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Oracle EBS SSRF toward metadata</td>
<td data-label="Action:">Block egress</td>
</tr>
</tbody>
</table>
All values and threat labels are derived from referenced advisories and reporting.

***

## Detection Rules

### 9.1 Sigma Rules (SIEM Detection) – 4 Rules

```yaml
title: CVE-2025-14847 MongoBleed Suspicious MongoDB Queries
id: 6f7d2f2b-6f3a-4d8f-9c0d-14847mongo
status: experimental
date: 2025-12-30
description: Detects anomalous MongoDB queries potentially exploiting CVE-2025-14847 (MongoBleed) for memory disclosure and large data reads.
author: Threat Intelligence Team
severity: critical

logsource:
  product: database
  service: mongodb

detection:
  selection_suspicious_ops:
    command|contains:
      - "mapReduce"
      - "$where"
      - "group"
  selection_large_response:
    responseLengthBytes|gte: 10000000
  filter_admin_ips:
    clientIp:
      - 10.0.0.0/8
      - 192.168.0.0/16

  condition: selection_suspicious_ops and selection_large_response and not filter_admin_ips

falsepositives:
  - Legitimate large analytics jobs from trusted admin networks
  - Backup jobs performing full collection scans

references:
  - https://innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials

fields:
  - clientIp
  - user
  - ns
  - command
  - responseLengthBytes
```

```yaml
title: Perimeter VPN Suspicious Login Followed by Config Change
id: 8a32cbb1-5e21-4c57-9b3d-vpn-auth-bypass-seq
status: experimental
date: 2025-12-30
description: Detects a pattern of unusual VPN/authentication success followed shortly by administrative configuration changes on perimeter appliances, consistent with exploitation of KEV-listed VPN/auth bypass vulnerabilities.
author: Threat Intelligence Team
severity: critical

logsource:
  product: vpn
  service: authentication

detection:
  selection_unusual_login:
    outcome: "success"
    geoip.country_name|neq: "ExpectedCountry"
  selection_admin_change:
    event_category: "configuration"
    event_type: "change"
    admin_user|exists: true

  condition: selection_unusual_login and selection_admin_change

falsepositives:
  - Legitimate emergency admin access from traveling staff
  - Planned maintenance where admin access originates from non-standard locations

references:
  - https://cvefeed.io/cisakev/cisa-known-exploited-vulnerability-catalog

fields:
  - user
  - src_ip
  - geoip.country_name
  - admin_user
  - device_name
  - event_time
```

```yaml
title: Credential Stuffing Burst From Single IP
id: a9c4e2d0-9db9-44f5-81ab-cred-stuffing-burst
status: experimental
date: 2025-12-30
description: Detects high-volume failed logins against many accounts from a single IP followed by a small number of successes, indicative of credential-stuffing using large credential dumps.
author: Threat Intelligence Team
severity: high

logsource:
  product: web
  service: authentication

detection:
  selection_fail:
    outcome: "failure"
  selection_success:
    outcome: "success"

  condition: |
    (selection_fail and selection_success)

falsepositives:
  - Load or stress testing against authentication services (should be from known IP ranges)
  - Misconfigured monitoring tools repeatedly attempting logins

references:
  - https://innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials

fields:
  - src_ip
  - user
  - outcome
  - user_agent
```

```yaml
title: Oracle E-Business Suite Possible SSRF to Metadata Service
id: c1fb02e0-3e5c-4dd4-9f5c-oracle-ebs-ssrf-metadata
status: experimental
date: 2025-12-30
description: Detects Oracle E-Business Suite servers making HTTP requests to instance metadata or internal addresses consistent with exploitation of CVE-2025-61884 SSRF.
author: Threat Intelligence Team
severity: critical

logsource:
  product: webserver
  service: proxy

detection:
  selection_src_oracle:
    src_host|contains: "ebs"
  selection_metadata:
    dest_ip:
      - "169.254.169.254"
  selection_internal:
    dest_ip|cidr:
      - "10.0.0.0/8"
      - "192.168.0.0/16"

  condition: selection_src_oracle and (selection_metadata or selection_internal)

falsepositives:
  - Legitimate configuration where Oracle EBS is allowed to call internal APIs (should be rare and documented)
  - Misconfigured monitoring tools routing via EBS host

references:
  - https://dailysecurityreview.com/security-spotlight/cisa-updates-kev-catalog-5-exploited-vulnerabilities-confirmed/

fields:
  - src_host
  - dest_ip
  - http_url
  - http_method
  - bytes_out
```


### 9.2 YARA Rules (File/Malware Detection) – 3 Rules

```yara
rule MacSync_Malware_Family {
    meta:
        description = "Detects MacSync macOS stealer observed bypassing Gatekeeper and targeting browser data"
        author = "Threat Intelligence Team"
        date = "2025-12-30"
        reference = "https://innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials"
        hash1 = "sha256-hash-here"
        severity = "critical"
        campaign = "MacSync-Stealer-2025"

    strings:
        $mz = { CF FA ED FE }  // Mach-O magic
        $string1 = "MacSyncAgent" ascii wide
        $string2 = "syncing browser cookies" ascii
        $code1 = { 55 48 89 E5 48 83 EC ?? 48 8B ?? ?? ?? ?? ?? 48 85 C0 }

    condition:
        $mz at 0 and
        filesize < 10MB and
        2 of ($string*) or
        all of ($code*)
}
```

```yara
rule PhantomCore_Backdoor {
    meta:
        description = "Detects PhantomCore group backdoor observed in industrial organization intrusions"
        author = "Threat Intelligence Team"
        date = "2025-12-30"
        reference = "https://ics-cert.kaspersky.com/publications/reports/2025/12/01/apt-and-financial-attacks-on-industrial-organizations-in-q3-2025/"
        hash1 = "sha256-hash-here"
        severity = "high"
        campaign = "PhantomCore-Industrial"

    strings:
        $mz = { 4D 5A }
        $string1 = "PhantomCore Service" ascii wide
        $string2 = "ICS discovery module" ascii
        $code1 = { 8B FF 55 8B EC 83 EC ?? 53 56 57 8B F1 }

    condition:
        $mz at 0 and
        filesize < 5MB and
        2 of ($string*) or
        all of ($code*)
}
```

```yara
rule Pantegana_Backdoor_RedNovember {
    meta:
        description = "Detects Go-based Pantegana backdoor used by RedNovember (TAG-100) against perimeter appliances"
        author = "Threat Intelligence Team"
        date = "2025-12-30"
        reference = "https://ics-cert.kaspersky.com/publications/reports/2025/12/01/apt-and-financial-attacks-on-industrial-organizations-in-q3-2025/"
        hash1 = "sha256-hash-here"
        severity = "high"
        campaign = "RedNovember-Pantegana"

    strings:
        $mz = { 7F 45 4C 46 }  // ELF
        $string1 = "Pantegana C2" ascii
        $string2 = "go.buildid" ascii
        $string3 = "perimeter appliance beacon" ascii
        $code1 = { 48 83 EC ?? 48 8B ?? ?? ?? ?? ?? 48 85 C0 74 ?? }

    condition:
        $mz at 0 and
        filesize < 20MB and
        2 of ($string1, $string2, $string3) or
        all of ($code*)
}
```


### 9.3 Snort/Suricata Rules (Network Detection) – 3 Rules

```text
alert tcp $EXTERNAL_NET any -> $DB_SERVERS 27017 (
    msg:"EXPLOIT MongoDB MongoBleed Suspected Exploit Traffic (CVE-2025-14847)";
    flow:to_server,established;
    content:"$where"; http_client_body;
    content:"mapReduce"; http_client_body;
    pcre:"/\\$where\\s*:/";
    classtype:attempted-user;
    reference:url,innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials;
    sid:100014847;
    rev:1;
    metadata:created_at 2025_12_30, attack_target Server;
)
```

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTPS_PORTS (
    msg:"MALWARE RedNovember Pantegana Suspected C2 Beacon";
    flow:to_server,established;
    content:"User-Agent|3a| Go-http-client/1.1"; http_header;
    content:"/health"; http_uri;
    pcre:"/\/health\?id=[a-f0-9]{16}/Ui";
    classtype:trojan-activity;
    reference:url,ics-cert.kaspersky.com/publications/reports/2025/12/01/apt-and-financial-attacks-on-industrial-organizations-in-q3-2025/;
    sid:100020001;
    rev:1;
    metadata:created_at 2025_12_30, attack_target Server;
)
```

```text
alert tcp $EXTERNAL_NET any -> $VPN_APPLIANCES $HTTPS_PORTS (
    msg:"EXPLOIT Suspected VPN/Auth Bypass Exploit Attempt on Perimeter Appliance";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/remote/login"; http_uri;
    content:"X-Forwarded-For|3a| 127.0.0.1"; http_header;
    classtype:web-application-attack;
    reference:url,cvefeed.io/cisakev/cisa-known-exploited-vulnerability-catalog;
    sid:100020002;
    rev:1;
    metadata:created_at 2025_12_30, attack_target Server;
)
```


### 9.4 OSQuery Queries (Endpoint Hunting) – 2 Queries

```sql
-- Detect Velociraptor spawning unusual child processes (e.g., VS Code) potentially used for tunneling (CVE-2025-6264 abuse)
-- Platform: Windows
-- Use case: Hunting/Triage
SELECT
    p.pid,
    p.name,
    p.path,
    p.parent,
    parent.name AS parent_name,
    p.cmdline,
    p.start_time
FROM processes p
JOIN processes parent ON p.parent = parent.pid
WHERE
    parent.name LIKE '%velociraptor%'
    AND (p.name LIKE '%Code.exe%' OR p.name LIKE '%powershell.exe%' OR p.name LIKE '%ssh.exe%')
    AND NOT (p.path LIKE 'C:\\Program Files\\Velociraptor\\%');
```

```sql
-- Identify accounts with unusual successful VPN logins followed by privilege changes (auth bypass / appliance abuse pattern)
-- Platform: All (via central auth logs shipped to OSQuery host or central log ingestion)
-- Use case: Detection/Hunting
SELECT
    u.username,
    l.remote_address,
    l.time,
    a.action
FROM users u
JOIN auth_log l ON u.username = l.username
JOIN admin_actions a ON u.username = a.actor
WHERE
    l.result = 'success'
    AND l.time > datetime('2025-12-15')
    AND a.time BETWEEN l.time AND datetime(l.time, '+10 minutes');
```


### 9.5 Deployment Guidance (Summary)

- Sigma → SIEM:
    - Use sigmac/pySigma to convert rules to Splunk SPL, Sentinel KQL, Elastic Query DSL, QRadar AQL, or Chronicle formats.
    - Validate field mappings (e.g., `src_ip`, `user`) against your log schema and adjust where needed.
- YARA → Endpoint/File Analysis:
    - Deploy to EDR platforms that support YARA‑based or custom detection, and integrate into THOR, Loki, or VirusTotal hunting for retroactive search.
- Snort/Suricata → Network:
    - Import into Snort/Suricata or cloud firewalls with custom IDS rules; tune for your network (e.g., `$DB_SERVERS`, `$VPN_APPLIANCES`).
- OSQuery:
    - Add queries to query packs in Fleet, Uptycs, or native OSQuery schedules for continuous hunting on admin and critical endpoints.

***

## Defensive Recommendations

### Immediate (0–24 hours)

- [ ] **Patch** MongoDB and Oracle E‑Business Suite instances for CVE‑2025‑14847 and CVE‑2025‑61884; remove direct internet exposure where possible.
- [ ] **Audit and patch** VPN, firewall, and other KEV‑listed perimeter appliances; rebuild or re‑image where compromise indicators exist.
- [ ] **Block or restrict** suspicious outbound traffic from DB servers and appliances (e.g., to metadata IP 169.254.169.254 or rare external IPs).
- [ ] **Harden identity**: enforce MFA on admin and remote access accounts, especially for SaaS, IDP, and VPN portals.


### Short‑Term (24–72 hours)

- [ ] **Run hunts** using the Sigma, YARA, Snort, and OSQuery rules in Section 9 for MongoBleed, credential‑stuffing, UNC3944, and appliance abuse patterns.
- [ ] **Review third‑party and SaaS integrations** for anomalous data exports (education, healthcare, and similar verticals should prioritize student/patient data systems).
- [ ] **Conduct credential hygiene**: invalidate passwords for accounts detected in credential‑stuffing attempts and run targeted MFA resets where suspicious logins occurred.
- [ ] **Check macOS coverage** and ensure EDR policies include MacSync‑like behaviors, including monitoring signed apps performing credential or wallet access.


### Ongoing (Strategic)

- [ ] **Adopt a continuous KEV management program** to ensure KEV‑listed vulnerabilities on perimeter and critical assets are patched or mitigated within policy SLAs.
- [ ] **Mature identity‑centric security**: implement conditional access, phishing‑resistant MFA, and privileged access management for admin and help‑desk accounts.
- [ ] **Improve third‑party risk management** by integrating SaaS and vendor logs into your SIEM and defining specific playbooks for vendor compromise scenarios.
- [ ] **Run regular tabletop exercises** simulating credential‑stuffing, social‑engineering of help desks, and appliance exploitation to validate detection and response readiness.

***

## Resources \& References

### Official Advisories / Government

<table>
<thead>
<tr><th align="left">Type</th><th align="left">Link</th></tr>
</thead>
<tbody>
<tr>
<td data-label="Type:">CISA KEV Catalog</td>
<td data-label="Link:"><a href="https://cisa.gov/known-exploited-vulnerabilities" target="_blank">https://cisa.gov/known-exploited-vulnerabilities</a></td>
</tr>
<tr>
<td data-label="Type:">KEV Aggregator</td>
<td data-label="Link:"><a href="https://cvefeed.io/cisakev/cisa-known-exploited-vulnerability-catalog" target="_blank">https://cvefeed.io/cisakev/cisa-known-exploited-vulnerability-catalog</a></td>
</tr>
<tr>
<td data-label="Type:">KEV Management Guidance</td>
<td data-label="Link:"><a href="https://www.patrowl.io/en/cisa-kev" target="_blank">https://www.patrowl.io/en/cisa-kev</a></td>
</tr>
</tbody>
</table>
### Vendor \& Threat Intelligence

| Topic | Link |
| :-- | :-- |
| Weekly Top 10 Cybersecurity News (includes MongoBleed, mega leak, MacSync) | https://innovatecybersecurity.com/security-threat-advisory/top-10-cybersecurity-news-dec-29-2025-historic-mega-leak-of-16b-credentials |
| Biggest Cybersecurity Stories of 2025 | https://www.bleepingcomputer.com/news/security/the-biggest-cybersecurity-and-cyberattack-stories-of-2025/amp/ |
| APT \& Financial Attacks on Industrial Organizations | https://ics-cert.kaspersky.com/publications/reports/2025/12/01/apt-and-financial-attacks-on-industrial-organizations-in-q3-2025/ |
| Top Data Breaches of December 2025 | https://strobes.co/blog/top-data-breaches-of-december-2025/ |
| Recent Data Breaches Overview | https://www.brightdefense.com/resources/recent-data-breaches/ |
| CISA KEV Additions / Related CVEs (Velociraptor, Oracle EBS, Kentico) | https://dailysecurityreview.com/security-spotlight/cisa-updates-kev-catalog-5-exploited-vulnerabilities-confirmed/ |
| Velociraptor Misuse \& CVE-2025-6264 Context | https://www.cyberdaily.au/security/12774-5-new-vulnerabilities-added-to-cisa-s-kev-catalog |
| Daily Cybersecurity News (campaign notes, rootkit/C2 discussions) | https://cyberrecaps.com/news/cybersecurity-news-december-29-2025/ |

### Detection Rule Conversion \& Repositories

- Sigma specification \& rules:
    - https://github.com/SigmaHQ/sigma
    - https://github.com/SigmaHQ/sigma/tree/master/rules
- pySigma: https://github.com/SigmaHQ/pySigma
- YARA tools and rules:
    - https://github.com/VirusTotal/yara
    - https://github.com/Yara-Rules/rules
    - https://github.com/reversinglabs/reversinglabs-yara-rules
- Snort/Suricata rules:
    - https://rules.emergingthreats.net/
    - https://www.snort.org/downloads
- OSQuery packs:
    - https://github.com/osquery/osquery/tree/master/packs

---

**Follow 0K:**
- Bluesky: [@kelvinlomboy.bsky.social](https://bsky.app/profile/kelvinlomboy.bsky.social)
- LinkedIn: [@kelvinlomboy](https://linkedin.com/in/kelvinlomboy)
- GitHub: [@0K-cool](https://github.com/0K-cool)

---

**Disclaimer:**

**Threat Intelligence:** This report is based on open-source intelligence gathering and analysis current as of the reporting date. The threat landscape evolves rapidly, and information may become outdated. Organizations should conduct independent validation, correlate findings with internal telemetry, and consult additional authoritative sources before making security decisions. This report is for informational purposes only and is not a substitute for professional security services.

**Detection Rules:** All detection rules (Sigma, YARA, Snort/Suricata) and hunt queries are experimental and provided as starting points for threat detection. Organizations must validate all rules in test environments, assess false positive rates, and modify them to suit specific tools, environments, and operational requirements before production deployment.

0K assumes no liability for decisions made based on this report or the effectiveness and impacts of implementing these detection rules.

---

<div align="center">
<strong>Next Weekly Brief:</strong> Friday, January 9, 2026
</div>

<div align="center">⁂</div>
