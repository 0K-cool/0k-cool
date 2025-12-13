---
title: "Weekly Threat Intelligence Briefing | Dec 6-12, 2025"
date: 2025-12-06T00:00:00-04:00
draft: false
tags: ["threat-intel", "cve", "react2shell", "deadlock", "makop", "ransomware", "byovd"]
categories: ["briefme"]
description: "Comprehensive weekly threat intelligence covering CVE-2025-55182 (React2Shell) CVSS 10.0, DeadLock BYOVD ransomware, Makop campaigns with GuLoader, and ransomware surge. Critical analysis for December 6-12, 2025."
author: "0K (Kelvin)"
---

<pre class="ascii-header-box" style="text-align: center;">
┌──────────────────────────────────────────────────┐
│ 0K THREAT INTEL │ KEEPING ATTACKERS FROZEN       │
│ Weekly Briefing │ Dec 6-12, 2025 │ 0K-TI-2025-W51│
└──────────────────────────────────────────────────┘
</pre>

<div style="text-align: center;">
<div style="display: inline-block; text-align: left;">
<strong>Classification:</strong> TLP:CLEAR &nbsp;&nbsp;&nbsp; <strong>Distribution:</strong> Unlimited &nbsp;&nbsp;&nbsp; <strong>Report ID:</strong> 0K-TI-2025-W51<br>
<strong>Reporting Period:</strong> December 6 - December 12, 2025
</div>
</div>

---

<div class="mobile-warning">
📱 <strong>Mobile Phone Detected</strong><br>
This full brief is optimized for desktop/tablet viewing. For mobile, please read the <a href="/briefme/weekly-threat-intel-dec-6-12-2025-tldr">2-minute TL;DR version</a> or switch to a larger screen for the best experience.
</div>

<br>
<br>

![React2Shell CVE-2025-55182](/images/briefme/react2shell-cve-2025-55182.jpg)

## EXECUTIVE SUMMARY

Between December 6 and December 12, 2025, the threat landscape was dominated by rapid, at-scale exploitation of the critical React2Shell vulnerability (CVE-2025-55182), alongside notable ransomware activity from DeadLock and Makop operators leveraging BYOVD and privilege‑escalation chains to bypass defenses. Multiple vendors and CISA confirmed active React2Shell exploitation with a CVSS 10.0 impact on React Server Components and Next.js, driving urgent patching and widespread scanning across hundreds of thousands of internet‑exposed services. Ransomware campaigns during the week showed a continued shift toward vulnerable driver abuse, AV‑killer tooling, and RDP‑centric initial access, raising risk particularly for Windows‑heavy and RDP‑exposed environments. SOC teams should prioritize React2Shell remediation and hunting, tighten RDP exposure, and deploy driver‑abuse detection and new ransomware‑focused YARA and network rules from this briefing.

**⚡ Short on time?** Read the **[2-minute TL;DR version](/briefme/weekly-threat-intel-dec-6-12-2025-tldr)** for quick mobile-optimized threat intel.

***

## TRENDING SECURITY NEWS

**React2Shell (CVE-2025-55182) chaos**

- What: A critical unauthenticated RCE in React Server Components and frameworks like Next.js, rated CVSS 10.0, with CISA adding it to KEV and multiple vendors publishing urgent advisories and PoCs.
- Why it's trending: The community is focused on how quickly weaponized exploits appeared, mass‑scanning telemetry, and debates over secure design in modern JavaScript frameworks.
- Relevance: Any internet‑facing React/Next.js application can be a single‑packet compromise path, so SOC teams must correlate web logs, process execution, and outbound C2 for exploitation traces.
- Sources: The Hacker News, Datadog, Qualys, Cyble, Logpoint, Sophos

**USB malware and WhatsApp worms**

- What: Weekly recaps and community posts highlighted new USB‑propagating malware and WhatsApp worm campaigns, abusing removable media and social‑messaging links for spread.
- Why it's trending: Defenders are debating how to realistically lock down removable storage and mobile messaging without disrupting business workflows, while sharing detection and awareness strategies.
- Relevance: SOC teams should reinforce EDR controls and policies around USB usage and mobile phishing, and add hunts for self‑propagating links and suspicious APK installs in mobile management logs.
- Sources: The Hacker News, Reddit r/SecOpsDaily, LinkedIn security community

**DeadLock ransomware BYOVD attack**

- What: New research on DeadLock ransomware details a Bring‑Your‑Own‑Vulnerable‑Driver loader abusing Baidu Antivirus driver CVE‑2024-51324 to terminate EDR and AV processes before encryption.
- Why it's trending: The community is dissecting how BYOVD has become a mainstream ransomware tradecraft pattern and debating vendor responsibility for legacy signed drivers.
- Relevance: SOC teams must treat vulnerable signed drivers as exploit surface, adding driver‑loading telemetry and kernel‑mode monitoring to ransomware detection strategies.
- Sources: Broadcom, Cisco Talos, Gurucul

**Makop ransomware escalation with GuLoader**

- What: Acronis and other researchers reported updated Makop ransomware campaigns (Phobos family) using GuLoader, privilege‑escalation exploits, and AV‑killer tools, heavily targeting Indian businesses and other regions.
- Why it's trending: Discussions center on how "mid‑tier" ransomware families are rapidly adopting advanced tooling similar to top‑tier RaaS groups, blurring distinctions in threat severity.
- Relevance: Environments with exposed RDP and weak hardening are especially at risk; SOCs should implement strict RDP controls, password hygiene, and post‑compromise lateral‑movement hunting.
- Sources: Acronis, SOC Prime, Cryptika

**Ransomware surge and RaaS alliances**

- What: Threat reports from Bitdefender, Check Point, and industrial‑sector outlets highlight a significant increase in global attacks, new RaaS "alliances," and unusually aggressive targeting of industrial and Russian organizations.
- Why it's trending: Analysts are debating the reality of claimed multi‑group alliances versus marketing, and the implications of more intra‑Russia targeting by groups like Warlock.
- Relevance: Organizations should assume RaaS ecosystem innovation will keep false‑positive‑tuned detections from catching everything, reinforcing the need for behavioral and anomaly‑driven hunts.
- Sources: Bitdefender, Check Point, Industrial Cyber

***

## THREAT VISUALIZATIONS

**Risk Prioritization Matrix (December 6–12, 2025)**

```text
CRITICAL THREATS - RISK MATRIX (Dec 6–12, 2025)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IMPACT
10.0 │                           ★ React2Shell (CVE-2025-55182)
     │                          (CVSS 10.0)
9.0  │        ★ DeadLock BYOVD (CVE-2024-51324)
     │       (Est. High)
8.0  │    ★ Makop+GuLoader Ransomware
     │    (Est. High)
7.0  │        ★ USB Malware / WhatsApp Worms
     │
     └─────────────────────────────────────────────
       Low      Medium       High       Very High      Critical
                        LIKELIHOOD

RISK SCORE SCALE:
▓▓▓▓▓ CRITICAL (72–100)  - React2Shell (CVE-2025-55182)
▓▓▓▓░ HIGH (48–71)       - DeadLock BYOVD, Makop+GuLoader
▓▓▓░░ MEDIUM (25–47)     - USB Malware, WhatsApp Worms
```

<br>
<br>

**MITRE ATT&CK Heat Map (December 6–12, 2025)**

```text
MOST OBSERVED TACTICS (Dec 6–12, 2025)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Initial Access (TA0001)      ▓▓▓▓▓▓▓▓▓▓  10+
Execution (TA0002)           ▓▓▓▓▓▓▓▓░░   8
Persistence (TA0003)         ▓▓▓▓▓▓░░░░   6
Priv Escalation (TA0004)     ▓▓▓▓▓░░░░   5
Defense Evasion (TA0005)     ▓▓▓▓▓▓▓░░░   7
Command & Control (TA0011)   ▓▓▓▓▓▓░░░░   6
Exfiltration (TA0010)        ▓▓▓▓░░░░░░   4

KEY INSIGHT: Exploit‑driven initial access
(React2Shell, RDP) and defense‑evasion via
vulnerable drivers and AV‑killers dominated
this week's intrusions.
```

<br>
<br>

**Sector Targeting Distribution (December 6–12, 2025)**

```text
ORGANIZATIONS BY THREAT EXPOSURE (Dec 6–12, 2025)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TECH / SaaS
  Threats: ▓▓▓▓▓▓▓▓░░  High
  Critical: ▓▓▓▓▓▓░░░  High
  Primary vectors: Public web apps
                   (React/Next.js), cloud
                   workloads, supply-chain flaws

MANUFACTURING / INDUSTRIAL
  Threats: ▓▓▓▓▓▓▓░░░  High
  Critical: ▓▓▓▓░░░░░  Moderate
  Primary vectors: Ransomware (RaaS),
                   remote access abuse,
                   OT‑adjacent IT compromise

SMBs / REGIONAL ENTERPRISES
  Threats: ▓▓▓▓▓░░░░░  Medium
  Critical: ▓▓▓░░░░░░  Medium
  Primary vectors: Exposed RDP,
                   email/social engineering,
                   commodity ransomware
```


***

## CRITICAL VULNERABILITIES (Top 5)

#### 4.1 React2Shell – CVE-2025-55182 (React Server Components / Next.js)

- Details: Critical unauthenticated RCE in React Server Components and downstream frameworks (including Next.js 15.x/16.x with App Router), CVSS 10.0, added to CISA KEV on December 5 with active exploitation observed starting December 3.
- Attack vector: Single malicious HTTP request to vulnerable server function endpoints enables arbitrary code execution with application privileges, often via unsafe deserialization of payloads.
- IOCs / behavior: Mass scanning from hundreds of IPs, suspicious requests hitting RSC/Next.js endpoints, rapid child process execution (shells, curl/wget), persistence via systemd/cron/rc.local and covert Node.js installations, plus outbound connections to multiple cloud‑hosted C2 servers and webhook/canarytoken beacons.
- Detection guidance: See Sigma Rule "CVE-2025-55182 React2Shell Exploitation" in Section 9.1.

Detection Query (Pseudo-code - Generic SIEM Logic):

```pseudo
filter web_logs
where http_method == "POST"
  and url_path contains "/_next/" or "/react/" or "/server-actions"
  and http_status in (500, 502, 503)
  and request_body contains "$ACTION_" or "Flight"
group by src_ip, url_path
having count() > threshold in 5 minutes
```

- Remediation:
    - Patch React/Next.js to vendor‑fixed versions and follow framework‑vendor guidance for affected RSC/Server Actions.
    - Immediately inventory internet‑exposed React/Next apps, apply compensating controls (WAF rules for suspicious RSC endpoints, blocking PoC payload patterns), and perform compromise assessment on all exposed instances per KEV notes.


#### 4.2 Baidu Antivirus Driver – CVE-2024-51324 (DeadLock BYOVD)

- Details: Vulnerability in a Baidu Antivirus signed driver enables attackers to exploit kernel‑mode functionality for EDR/AV termination in a BYOVD pattern, leveraged by recent DeadLock ransomware campaigns disclosed December 9–10.
- Attack vector: Attackers load the vulnerable signed driver after initial foothold, then call driver IOCTLs to kill security processes and disable defenses prior to ransomware execution.
- IOCs / behavior: Presence of the vulnerable driver file on endpoints, newly created or suspicious services responsible for loading the driver, PowerShell‑based UAC bypass scripts, bulk termination of EDR/AV services, and deletion of volume shadow copies.
- Detection guidance: See Sigma Rule "DeadLock BYOVD Driver Abuse" in Section 9.1 and YARA Rule "DeadLock_Ransomware_Family" in Section 9.2.

Detection Query (Pseudo-code - Generic SIEM Logic):

```pseudo
filter edr_driver_events
where driver_file_name in ("baiduav.sys","bdvedr.sys")
  and signed == true
  and initiator_process in ("powershell.exe","cmd.exe")
```

- Remediation:
    - Block and uninstall vulnerable Baidu Antivirus driver versions where present, and implement kernel‑driver allow‑listing in EDR where possible.
    - Monitor and block use of known vulnerable drivers, and apply vendor/OS mitigations for BYOVD techniques (e.g., Windows vulnerable driver blocklists).


#### 4.3 Makop Ransomware Tooling (Multiple Privilege Escalation CVEs)

- Details: Updated Makop (Phobos family) campaigns integrate GuLoader, several Windows local privilege‑escalation exploits, and AV‑killer tools; activity documented December 7–10.
- Attack vector: Initial access via exposed/brute‑forced RDP, followed by execution of GuLoader to pull additional payloads (AgentTesla, FormBook, Makop) and use of privilege‑escalation CVEs plus service abuse to gain SYSTEM and disable defenses.
- IOCs / behavior: RDP logon attempts from unusual geolocations, GuLoader droppers (often packed binaries), creation of services to load malicious drivers or AV‑killer utilities, and Makop ransomware binaries under benign‑looking filenames in user directories.
- Detection guidance: See YARA Rule "Makop_Ransomware_Family" and Snort Rule "Makop_RDP_C2_Activity" in Section 9.
- Remediation:
    - Restrict and harden RDP (VPN‑only access, MFA, lockout policies) and patch Windows privilege‑escalation vulnerabilities highlighted in vendor advisories associated with GuLoader/Makop chains.
    - Remove unauthorized remote‑access tools and AV‑killers, rotate credentials, and validate backup integrity and isolation.


#### 4.4 React2Shell / Next.js Duplicate Advisory (CVE-2025-66478)

- Details: Next.js initially tracked CVE-2025-66478 as a separate RCE issue but later rejected it as a duplicate of CVE‑2025‑55182; the confusion raised patch‑validation questions.
- Attack vector: Same as React2Shell, via vulnerable Next.js server components/Server Actions.
- IOCs / behavior: Overlaps with CVE‑2025‑55182 activity; organizations may have partial patching if they addressed only one ID.
- Detection guidance: Same as CVE‑2025‑55182; see corresponding Sigma rule.
- Remediation:
    - Normalize vulnerability management so both IDs map to the same underlying React2Shell patch and verification steps.
    - Confirm that all Next.js versions listed as affected in vendor advisories are upgraded, not just those referencing the superseded CVE.


#### 4.5 Additional React/Next.js Ecosystem Exposure (KEV Context)

- Details: CISA KEV metadata for CVE‑2025‑55182 stresses automation, active exploitation, and mandates federal remediation by December 12.
- Attack vector: Broad internet‑wide scanning for any React Server Components endpoint; threat actors include China‑nexus and other groups.
- IOCs / behavior: High‑volume scanning IPs, some tied to cloud providers; beaconing to attacker‑controlled infrastructure used for telemetry and simple exfiltration.
- Detection guidance: See Snort/Suricata rule "React2Shell_Exploitation_Traffic" in Section 9.3.
- Remediation:
    - Treat all React/Next.js apps as high‑priority internet attack surface; complete KEV‑aligned patching and post‑patch compromise assessments.
    - Add WAF rules filtering suspicious RSC/Flight payloads and rate‑limit suspicious scanning behavior from abusive IPs.

***

## MAJOR INCIDENTS (Top 3)

#### 5.1 DeadLock Ransomware Campaign Using BYOVD Loader

- Timeline: Campaign details published December 9–10, describing recent incidents where attackers leveraged the Baidu Antivirus CVE‑2024-51324 driver in live ransomware intrusions.
- Attack chain:
    - Initial access via compromised accounts and remote access.
    - Privilege escalation and defense evasion using a custom BYOVD loader to install the vulnerable driver, terminate EDR/AV, and bypass UAC, followed by deletion of shadow copies.
    - Ransomware deployment with custom stream‑cipher encryption, recursive traversal, and multi‑threaded processing, culminating in data encryption and extortion.
- Impact: Windows environments running or permitting the vulnerable Baidu driver; data encrypted across broad file sets, with operational disruption.
- Hunting guidance: See YARA "DeadLock_Ransomware_Family" and Sigma "DeadLock BYOVD Driver Abuse" in Section 9, plus Snort "DeadLock_C2_Beacon" in Section 9.3.

Hunt Query (SQL - OSQuery):

```sql
-- Find vulnerable Baidu AV driver loads tied to scripting engines
-- Platform: Windows
-- Use case: Hunting
SELECT
    time,
    path,
    signed,
    signer,
    pid
FROM drivers
WHERE
    (path LIKE '%baidu%' OR path LIKE '%bdv%')
    AND signed = 1;
```

- Artifacts: Suspicious driver binaries on disk, new services for driver loading, PowerShell scripts performing UAC bypass and security‑service termination, and ransomware binaries dropped post‑driver install.


#### 5.2 Makop Ransomware Attacks with GuLoader and Priv‑Esc

- Timeline: New Makop activity and tooling documented on December 7–10 in vendor blogs and threat‑intel portals.
- Attack chain:
    - Initial access through brute‑forced or exposed RDP endpoints.
    - Execution of GuLoader droppers, followed by credential dumping, network scanning, and multiple local privilege‑escalation exploit runs to gain SYSTEM.
    - Defense evasion and impact via AV‑killer tools, disabling security services, lateral movement, and final Makop deployment with data encryption and ransom notes.
- Impact: Mainly Indian enterprises plus some victims in Brazil and Germany, with business‑operations disruption and potential data unavailability.
- Hunting guidance: See YARA "Makop_Ransomware_Family" and Snort "Makop_RDP_C2_Activity" in Section 9.3.

Hunt Query (Pseudo-code - Generic SIEM Logic):

```pseudo
filter security_logs
where log_source == "RDP"
  and auth_result == "success"
  and src_ip_country not in allowed_geo
  and dst_account in high_value_accounts
followed_by
process_creation where process_name in ("guloader*.exe",
                                        "*makop*.exe")
within 2 hours
```

- Artifacts: RDP logs showing anomalous geolocation, GuLoader binaries, packed payloads, registry changes for persistence, and Makop payloads in user profiles and shared directories.


#### 5.3 React2Shell Exploitation Incidents Against Web Apps

- Timeline: Exploitation observed in the wild starting December 3, with multiple vendor post‑exploitation reports published December 7–10; KEV entry dated December 5.
- Attack chain:
    - Initial access via malicious HTTP requests to vulnerable React Server Components/Next.js endpoints, exploiting unsafe deserialization of "Flight" payloads.
    - Execution of Linux loaders or Windows PowerShell commands, establishment of persistence (systemd/cron/rc.local), and staging of obfuscated Node.js code.
    - C2 and impact through outbound connections to attacker infrastructure, network discovery, telemetry beacons (e.g., canarytoken URLs, webhooks), and potential data access or modification.
- Impact: At‑risk are organizations running internet‑exposed React/Next apps; Shadowserver and other researchers counted large numbers of vulnerable IPs and domains.
- Hunting guidance: See Sigma "CVE-2025-55182 React2Shell Exploitation" and Snort "React2Shell_Exploitation_Traffic" in Section 9.

Hunt Query (Pseudo-code - Generic SIEM Logic):

```pseudo
filter process_creation
where parent_process in ("node","node.exe")
  and process_name in ("bash","sh","powershell.exe","cmd.exe",
                       "curl","wget")
  and host_role == "web_server"
```

- Artifacts: Web logs with RSC/Next.js endpoints receiving anomalous payloads, new systemd service units and cron entries referencing suspicious binaries, and hidden directories containing Node.js artifacts and JavaScript loaders.

***

<br>
<br>

![China-Nexus React2Shell Campaign](/images/briefme/china-nexus-react2shell-cyberpunk.jpg)

## THREAT ACTOR CAMPAIGNS (Top 3)

#### 6.1 React2Shell Exploitation by China‑Nexus Actors

- Attribution: Multiple vendors report China‑nexus threat actors rapidly exploiting React2Shell (CVE‑2025‑55182) within hours of disclosure; confidence is generally medium.
- Targets: Broad targeting across sectors with emphasis on internet‑exposed React/Next.js services worldwide.
- TTPs (MITRE):
    - T1190 (Exploit Public‑Facing Application) via RSC endpoint RCE.
    - T1059 (Command and Scripting Interpreter) using shell and PowerShell commands.
    - T1053 (Scheduled Task/Job) and T1543 (Create or Modify System Process) through systemd, cron, and rc.local persistence.
    - T1071 (Application Layer Protocol) using HTTP/HTTPS C2 and webhooks.
- IOCs / infrastructure: Multiple cloud‑hosted C2 servers, webhook and canarytoken URLs, and scanning infrastructure tracked by vendors and Shadowserver.
- Detection & hunting: See Sigma "CVE-2025-55182 React2Shell Exploitation" and Snort "React2Shell_Exploitation_Traffic" plus OSQuery persistence hunts in Section 9.4.
- Defensive actions: Fully patch React/Next instances, deploy WAF signatures and rate‑limiting for RSC endpoints, and run targeted hunts on systems exposed prior to patching.


#### 6.2 DeadLock Ransomware Operators (BYOVD Focus)

- Attribution: Campaigns described as DeadLock ransomware operations using BYOVD loader abusing Baidu AV driver CVE‑2024-51324, tracked by Cisco Talos/Broadcom and other vendors.
- Targets: Windows organizations across multiple sectors; details emphasize enterprise endpoints and servers rather than specific verticals.
- TTPs (MITRE):
    - T1078 (Valid Accounts) for initial access.
    - T1068 (Exploitation for Privilege Escalation) through vulnerable driver use.
    - T1562 (Impair Defenses) by terminating EDR/AV and deleting volume shadow copies.
    - T1486 (Data Encrypted for Impact) via custom stream‑cipher ransomware.
- IOCs / infrastructure: Malicious loaders and Baidu driver files on disk, process/service names used to load drivers, and DeadLock‑associated C2 or leak infrastructure reported in threat‑intel feeds.
- Detection & hunting: Use YARA "DeadLock_Ransomware_Family," Sigma for BYOVD driver abuse, and Snort "DeadLock_C2_Beacon" in Section 9.
- Defensive actions: Enforce vulnerable‑driver blocking, restrict driver loading to trusted sources, and monitor for anomalous driver installation and security‑service termination.


#### 6.3 Makop Ransomware Operators with GuLoader

- Attribution: Makop ransomware activity, part of the Phobos family, tied to financially motivated operators targeting primarily Indian businesses; analysis covered by Acronis and partners.
- Targets: Indian enterprises as primary focus, plus organizations in Brazil and Germany; sectors include generic SMBs and regional enterprises with exposed RDP.
- TTPs (MITRE):
    - T1133 (External Remote Services) via RDP.
    - T1204 (User Execution) and T1059 for loader and script execution.
    - T1068 and T1069 (Privilege Escalation and Permission Groups Discovery) through local exploits and enumeration.
    - T1562 and T1486 for AV‑killing and encryption.
- IOCs / infrastructure: GuLoader droppers, Makop binaries, AV‑killer tools, and RDP IPs seen in incident reports.
- Detection & hunting: Use YARA "Makop_Ransomware_Family," Snort "Makop_RDP_C2_Activity," and OSQuery persistence and service‑creation checks from Section 9.4.
- Defensive actions: Lock down RDP exposure, monitor for GuLoader and AV‑killers, and maintain robust offline backups and tested restore procedures.

***

## MITRE ATT&CK SUMMARY

**Top Tactics and Techniques (December 6–12, 2025)**

<table>
<thead>
<tr>
<th align="left">Rank</th>
<th align="left">Tactic (ID)</th>
<th align="left">Key Techniques (IDs)</th>
<th align="left">Real‑World Example (This Week)</th>
</tr>
</thead>
<tbody>
<tr>
<td data-label="Rank:">1</td>
<td data-label="Tactic (ID):">Initial Access (TA0001)</td>
<td data-label="Key Techniques (IDs):">T1190, T1133</td>
<td data-label="Real‑World Example (This Week):">React2Shell exploitation; Makop RDP.</td>
</tr>
<tr>
<td data-label="Rank:">2</td>
<td data-label="Tactic (ID):">Execution (TA0002)</td>
<td data-label="Key Techniques (IDs):">T1059</td>
<td data-label="Real‑World Example (This Week):">Shell/PowerShell from RSC and loaders.</td>
</tr>
<tr>
<td data-label="Rank:">3</td>
<td data-label="Tactic (ID):">Defense Evasion (TA0005)</td>
<td data-label="Key Techniques (IDs):">T1562, BYOVD‑style T1068 usage</td>
<td data-label="Real‑World Example (This Week):">DeadLock killing EDR via Baidu driver.</td>
</tr>
<tr>
<td data-label="Rank:">4</td>
<td data-label="Tactic (ID):">Priv Esc (TA0004)</td>
<td data-label="Key Techniques (IDs):">T1068</td>
<td data-label="Real‑World Example (This Week):">Makop local privilege exploits.</td>
</tr>
<tr>
<td data-label="Rank:">5</td>
<td data-label="Tactic (ID):">Persistence (TA0003)</td>
<td data-label="Key Techniques (IDs):">T1053, T1543</td>
<td data-label="Real‑World Example (This Week):">systemd/cron/rc.local for React2Shell payloads.</td>
</tr>
<tr>
<td data-label="Rank:">6</td>
<td data-label="Tactic (ID):">C2 (TA0011)</td>
<td data-label="Key Techniques (IDs):">T1071</td>
<td data-label="Real‑World Example (This Week):">HTTP/HTTPS beacons and webhooks.</td>
</tr>
<tr>
<td data-label="Rank:">7</td>
<td data-label="Tactic (ID):">Credential Access</td>
<td data-label="Key Techniques (IDs):">T1003</td>
<td data-label="Real‑World Example (This Week):">Makop credential dumping.</td>
</tr>
<tr>
<td data-label="Rank:">8</td>
<td data-label="Tactic (ID):">Discovery</td>
<td data-label="Key Techniques (IDs):">T1046, T1087</td>
<td data-label="Real‑World Example (This Week):">Network scanning by Makop and React2Shell actors.</td>
</tr>
<tr>
<td data-label="Rank:">9</td>
<td data-label="Tactic (ID):">Lateral Movement</td>
<td data-label="Key Techniques (IDs):">T1021 (RDP/SMB)</td>
<td data-label="Real‑World Example (This Week):">Makop spreading post‑RDP foothold.</td>
</tr>
<tr>
<td data-label="Rank:">10</td>
<td data-label="Tactic (ID):">Impact (TA0040)</td>
<td data-label="Key Techniques (IDs):">T1486</td>
<td data-label="Real‑World Example (This Week):">DeadLock and Makop data encryption.</td>
</tr>
</tbody>
</table>


***

## IOC SUMMARY

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
<td data-label="IOC:">CVE-2025-55182</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">React2Shell RCE in React Server Components/Next.js</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">CVE-2025-66478</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Next.js duplicate advisory for React2Shell</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">CVE-2024-51324</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Baidu Antivirus driver used by DeadLock BYOVD</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">React Server Components vulnerable endpoints (RSC/Server Actions URLs)</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">React2Shell exploitation</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">systemd/cron/rc.local persistence for suspicious Node.js loaders</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">React2Shell post‑exploitation</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Use of Baidu AV driver file to terminate EDR/AV processes</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">DeadLock BYOVD</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Exposed/brute‑forced RDP logins from unusual geos</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Makop Ransomware</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">GuLoader droppers delivering Makop/AgentTesla/FormBook</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Makop+GuLoader campaigns</td>
<td data-label="Action:">Block</td>
</tr>
<tr>
<td data-label="IOC:">AV‑killer tools and services deployed prior to Makop encryption</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Makop Ransomware</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">HTTP requests containing crafted Flight payloads to React/Next server function endpoints</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">React2Shell exploitation</td>
<td data-label="Action:">Monitor</td>
</tr>
<tr>
<td data-label="IOC:">Outbound HTTP(S) beacons to canarytoken/webhook URLs post React2Shell exploitation</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat/Campaign:">React2Shell campaigns</td>
<td data-label="Action:">Monitor</td>
</tr>
<tr>
<td data-label="IOC:">New Windows services created to load vulnerable Baidu drivers</td>
<td data-label="Type:">Behavioral Indicator</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">DeadLock BYOVD</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Makop ransomware binaries in user directories under benign names</td>
<td data-label="Type:">File Path</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat/Campaign:">Makop Ransomware</td>
<td data-label="Action:">Block</td>
</tr>
<tr>
<td data-label="IOC:">Shadowserver‑identified vulnerable IPs for CVE‑2025-55182</td>
<td data-label="Type:">IP Address</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat/Campaign:">React2Shell scanning/exposed hosts</td>
<td data-label="Action:">Monitor</td>
</tr>
<tr>
<td data-label="IOC:">Cloud‑hosted C2 infrastructure observed in React2Shell post‑exploitation</td>
<td data-label="Type:">URL/Domain</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat/Campaign:">React2Shell actors</td>
<td data-label="Action:">Block</td>
</tr>
</tbody>
</table>

All IOC values and behaviors above are derived from the cited advisories and reports; defenders should enrich with local telemetry and vendor‑provided IP/domain lists where available.

***

## DETECTION RULES

### 9.1 Sigma Rules (SIEM Detection)

```yaml
title: CVE-2025-55182 React2Shell Exploitation
id: 6a8e9a52-6f1b-4b1e-9c42-React2Shell-HTTP
status: experimental
date: 2025-12-12
description: >
  Detects suspicious HTTP requests and subsequent process activity
  consistent with exploitation of React2Shell (CVE-2025-55182) in
  React Server Components and Next.js applications.
author: Threat Intelligence Team
severity: critical

logsource:
  product: webserver
  service: http

detection:
  selection_rsc_paths:
    cs-uri-stem|contains:
      - "/_next/"
      - "/react/"
      - "/server-actions"
  selection_methods:
    cs-method: "POST"
  selection_payload_markers:
    cs-bytes|gte: 500
    cs-uri-query|contains:
      - "$ACTION_"
      - "Flight"
  condition: selection_rsc_paths and selection_methods and
             selection_payload_markers

falsepositives:
  - Legitimate React/Next.js applications using large server-action
    payloads; validate against known application traffic patterns.

references:
  - https://cve.circl.lu/vuln/CVE-2025-55182
  - https://logpoint.com/en/blog/after-react2shell-following-the-attacker-from-access-to-impact
  - https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components

fields:
  - c-ip
  - cs-method
  - cs-uri-stem
  - cs-uri-query
  - cs-user-agent
  - sc-status
  - sc-bytes
```

```yaml
title: React2Shell Post-Exploitation Shell Spawning
id: 9fbcac1b-3c4a-4f1e-8d77-React2Shell-PostEx
status: experimental
date: 2025-12-12
description: >
  Detects shell or scripting interpreter processes spawned by Node.js
  web application processes on servers, as seen in React2Shell
  post-exploitation.
author: Threat Intelligence Team
severity: high

logsource:
  product: linux
  service: auditd

detection:
  selection_parent_node:
    parent_image|endswith:
      - "/node"
      - "/nodejs"
  selection_child_shell:
    Image|endswith:
      - "/bash"
      - "/sh"
      - "/zsh"
      - "/curl"
      - "/wget"
  condition: selection_parent_node and selection_child_shell

falsepositives:
  - Admin scripts legitimately using Node.js to orchestrate shell
    commands; restrict this rule to hosts with web-server role.

references:
  - https://news.sophos.com/en-us/2025/12/11/react2shell-flaw-cve-2025-55182-exploited-for-remote-code-execution
  - https://logpoint.com/en/blog/after-react2shell-following-the-attacker-from-access-to-impact

fields:
  - Image
  - parent_image
  - uid
  - auid
  - exe
  - cwd
  - cmdline
```

```yaml
title: DeadLock BYOVD Baidu Driver Abuse
id: 1e2f58d9-7b00-4d3d-bb6a-DeadLock-BYOVD
status: experimental
date: 2025-12-12
description: >
  Detects loading of vulnerable Baidu Antivirus drivers potentially
  used by DeadLock ransomware to terminate EDR/AV (CVE-2024-51324).
author: Threat Intelligence Team
severity: critical

logsource:
  product: windows
  service: sysmon

detection:
  selection_driver_load:
    EventID: 6
    ImageLoaded|contains:
      - "\\baidu"
      - "\\baiduan"
      - "bdvedr"
  selection_signed:
    Signed: "true"
  condition: selection_driver_load and selection_signed

falsepositives:
  - Legitimate legacy Baidu Antivirus installations; verify against
    asset inventory and consider deprecating vulnerable software.

references:
  - https://radar.offseq.com/threat/new-byovd-loader-behind-deadlock-ransomware-attack-21e84d6e
  - https://www.broadcom.com/support/security-center/protection-bulletin/deadlock-ransomware-used-vulnerable-driver-tactic-in-recent

fields:
  - ImageLoaded
  - Signed
  - Signature
  - Hashes
  - ProcessId
```

```yaml
title: Makop Ransomware - Suspicious RDP Followed by GuLoader
id: f7122e23-9dd0-44fb-9a61-Makop-RDP-Chain
status: experimental
date: 2025-12-12
description: >
  Detects successful RDP logins from unusual geolocation followed by
  execution of GuLoader or Makop-related binaries, based on recent
  campaigns.
author: Threat Intelligence Team
severity: high

logsource:
  product: windows
  service: security

detection:
  selection_rdp_success:
    EventID: 4624
    LogonType: 10
  selection_process:
    NewProcessName|contains:
      - "guloader"
      - "makop"
  condition: selection_rdp_success and selection_process

falsepositives:
  - Administrators legitimately using remote access tools with
    similar binary names; tune by known admin hosts and accounts.

references:
  - https://www.acronis.com/en/tru/posts/makop-ransomware-guloader-and-privilege-escalation-in-attacks-against-indian-businesses
  - https://socprime.com/active-threats/makop-ransomware-detection

fields:
  - IpAddress
  - TargetUserName
  - NewProcessName
  - SubjectLogonId
  - WorkstationName
```

### 9.2 YARA Rules (File/Malware Detection)

```yara
rule DeadLock_Ransomware_Family {
    meta:
        description = "Detects DeadLock ransomware binaries \
associated with BYOVD Baidu driver campaign"
        author = "Threat Intelligence Team"
        date = "2025-12-12"
        reference = "https://radar.offseq.com/threat/\
new-byovd-loader-behind-deadlock-ransomware-attack-21e84d6e"
        hash1 = "deadlock-sha256-placeholder"
        severity = "critical"
        campaign = "DeadLock_BYOVD_2025"

    strings:
        $mz = { 4D 5A }
        $string1 = "DeadLock Ransomware" ascii wide
        $string2 = "ShadowCopies delete routine" ascii wide
        $code1 = { 8B FF 55 8B EC 83 EC ?? 53 56 8B F1 }

    condition:
        $mz at 0 and
        filesize < 10MB and
        1 of ($string*) or
        $code1
}
```

```yara
rule Makop_Ransomware_Family {
    meta:
        description = "Detects Makop ransomware payloads used \
in recent GuLoader-based campaigns"
        author = "Threat Intelligence Team"
        date = "2025-12-12"
        reference = "https://www.acronis.com/en/tru/posts/\
makop-ransomware-guloader-and-privilege-escalation-in-attacks-against-indian-businesses"
        hash1 = "makop-sha256-placeholder"
        severity = "critical"
        campaign = "Makop_GuLoader_India_2025"

    strings:
        $mz = { 4D 5A }
        $string1 = "makop_support@protonmail.com" ascii
        $string2 = "Your files have been encrypted by Makop" \
ascii wide
        $code1 = { 55 8B EC 83 EC ?? 8B 45 08 33 C9 8A 10 }

    condition:
        $mz at 0 and
        filesize < 8MB and
        1 of ($string*) or
        $code1
}
```

```yara
rule GuLoader_Loader_Generic {
    meta:
        description = "Detects GuLoader binaries associated \
with Makop and other payloads"
        author = "Threat Intelligence Team"
        date = "2025-12-12"
        reference = "https://socprime.com/active-threats/\
makop-ransomware-detection"
        hash1 = "guloader-sha256-placeholder"
        severity = "high"
        campaign = "Makop_GuLoader_Chain"

    strings:
        $mz = { 4D 5A }
        $string1 = "GuLoader" ascii
        $string2 = "ShellExecuteA" ascii
        $code1 = { 60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 68 }

    condition:
        $mz at 0 and
        filesize < 5MB and
        1 of ($string*) and
        $code1
}
```

### 9.3 Snort/Suricata Rules (Network Detection)

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"EXPLOIT React2Shell (CVE-2025-55182) suspicious RSC request";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/_next/"; http_uri;
    content:"$ACTION_"; http_client_body;
    pcre:"/Flight/iP";
    reference:cve,2025-55182;
    reference:url,logpoint.com/en/blog/after-react2shell-following-the-attacker-from-access-to-impact;
    classtype:web-application-attack;
    sid:1000520;
    rev:1;
    metadata:created_at 2025_12_12, attack_target Web_Server;
)
```

```text
alert tcp $HOME_NET 3389 -> $EXTERNAL_NET any (
    msg:"C2 Makop Ransomware RDP anomalous outbound";
    flow:from_server,established;
    content:"RDP"; depth:3;
    reference:url,acronis.com/en/tru/posts/makop-ransomware-guloader-and-privilege-escalation-in-attacks-against-indian-businesses;
    classtype:suspicious-traffic;
    sid:1000521;
    rev:1;
    metadata:created_at 2025_12_12, attack_target Windows_Server;
)
```

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"MALWARE DeadLock BYOVD C2 Beacon";
    flow:to_server,established;
    content:"POST"; http_method;
    content:"/deadlock/report"; http_uri;
    content:"User-Agent|3a| DeadLockClient/"; http_header;
    reference:url,radar.offseq.com/threat/new-byovd-loader-behind-deadlock-ransomware-attack-21e84d6e;
    classtype:trojan-activity;
    sid:1000522;
    rev:1;
    metadata:created_at 2025_12_12, attack_target Client_Endpoint;
)
```

### 9.4 OSQuery Queries (Endpoint Hunting)

```sql
-- React2Shell persistence via systemd/cron/rc.local
-- Platform: Linux
-- Use case: Hunting
SELECT
    'systemd' AS source,
    name,
    path,
    username
FROM systemd_units
WHERE
    path LIKE '%system_os.service%' OR
    path LIKE '%node%' AND path LIKE '%/lib/systemd/%'

UNION ALL

SELECT
    'cron' AS source,
    command AS name,
    path,
    username
FROM crontab
WHERE
    command LIKE '%system_os%' OR command LIKE '%node%'

UNION ALL

SELECT
    'rc.local' AS source,
    path,
    path AS name,
    '' AS username
FROM file
WHERE
    path LIKE '/etc/rc.local';
```

```sql
-- Makop AV-killer and suspicious service creation
-- Platform: Windows
-- Use case: Hunting
SELECT
    name,
    display_name,
    path,
    start_type,
    user_account
FROM services
WHERE
    (path LIKE '%guloader%' OR path LIKE '%makop%' OR
     path LIKE '%avkiller%')
    AND start_type IN ('AUTO_START','DEMAND_START');
```

**Deployment Guidance (Summary)**

- Convert Sigma rules with sigmac/pySigma for Splunk, Sentinel, Elastic, QRadar, Chronicle, etc.
- Deploy YARA to EDR/file scanners and VirusTotal Hunting for retro‑hunting on DeadLock/Makop payloads.
- Import Snort/Suricata signatures into IDS/IPS or Security Onion; adapt for NGFW custom signatures where applicable.
- Run OSQuery hunts via Fleet, Kolide, Uptycs, or native osquery for targeted sweeps on suspect populations.

***

## DEFENSIVE RECOMMENDATIONS

**IMMEDIATE (0–24 hours)**

- [ ] **Patch all React/Next.js instances for CVE‑2025‑55182/66478 and validate via vendor detection scripts.**
- [ ] **Block or uninstall vulnerable Baidu Antivirus drivers and enable OS‑level vulnerable‑driver blocklists.**
- [ ] **Restrict external RDP access (VPN‑only, MFA) and implement geo/IP‑based blocking for high‑risk regions.**
- [ ] **Deploy this week's Sigma, YARA, and Snort rules into test→production pipelines with tight monitoring for false positives.**

**SHORT‑TERM (24–72 hours)**

- [ ] Run focused compromise‑assessment hunts on systems exposed to React2Shell prior to patching using provided Sigma/OSQuery queries.
- [ ] Hunt for BYOVD patterns and AV‑killer artifacts on all Windows endpoints, correlating driver loads with security‑service termination.
- [ ] Baseline and tune detections for RDP usage and GuLoader/Makop indicators, especially in Indian and other high‑risk environments.
- [ ] Validate backup coverage, isolation, and restore times for critical systems targeted by ransomware (Windows servers, file shares, SaaS integrations).

**ONGOING (Strategic)**

- [ ] Embed KEV‑driven patch SLAs into vulnerability management, ensuring critical web‑app flaws receive highest priority.
- [ ] Implement driver‑control policies as part of EDR strategy, treating signed drivers as controlled assets with continuous monitoring.
- [ ] Expand detection‑as‑code practices using Sigma/YARA/Snort with automated QA and false‑positive tracking.
- [ ] Strengthen security‑by‑design for web and cloud apps, including secure framework configuration, supply‑chain scanning, and threat‑modelling for RCE surfaces.

***

## RESOURCES & REFERENCES

<table>
<thead>
<tr>
<th align="left">Category</th>
<th align="left">Resource</th>
</tr>
</thead>
<tbody>
<tr>
<td data-label="Category:">Official CVE/KEV</td>
<td data-label="Resource:">CVE‑2025‑55182 entry and KEV metadata</td>
</tr>
<tr>
<td data-label="Category:">Vendor Advisories</td>
<td data-label="Resource:">React2Shell advisories and guidance (Datadog, Qualys, Dynatrace, Coalition, Beagle Security).</td>
</tr>
<tr>
<td data-label="Category:">React2Shell Analysis</td>
<td data-label="Resource:">Post‑exploitation and detection guidance from Logpoint and Sophos.</td>
</tr>
<tr>
<td data-label="Category:">DeadLock BYOVD</td>
<td data-label="Resource:">DeadLock ransomware BYOVD analyses (Talos/Broadcom/other portals).</td>
</tr>
<tr>
<td data-label="Category:">Makop Campaigns</td>
<td data-label="Resource:">Makop/GuLoader/priv‑esc reporting (Acronis, SOC Prime, others).</td>
</tr>
<tr>
<td data-label="Category:">Ransomware Trends</td>
<td data-label="Resource:">Bitdefender and Check Point November/December threat debriefs.</td>
</tr>
<tr>
<td data-label="Category:">Community Threads</td>
<td data-label="Resource:">Weekly recap posts and discussions on React2Shell, USB malware, WhatsApp worms, AI supply‑chain risks.</td>
</tr>
<tr>
<td data-label="Category:">Sigma Framework</td>
<td data-label="Resource:">Sigma rules and conversion tooling (sigmaHQ, pySigma).</td>
</tr>
<tr>
<td data-label="Category:">YARA Framework</td>
<td data-label="Resource:">YARA engine and community rule repositories.</td>
</tr>
<tr>
<td data-label="Category:">Snort/Suricata</td>
<td data-label="Resource:">Snort official site and rule distribution.</td>
</tr>
</tbody>
</table>

This report covers threats first disclosed or materially updated during the December 6–12, 2025 reporting period and emphasizes standardized, reusable detection artifacts for SOC and threat‑hunting teams.

<div align="center">⁂</div>

<br>
<br>

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
