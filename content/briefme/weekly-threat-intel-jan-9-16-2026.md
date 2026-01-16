---
title: "Weekly Threat Intelligence Briefing | January 9-16, 2026"
date: 2026-01-16
draft: false
tags: ["threat-intelligence", "weekly-briefing", "cve", "0-day", "apt", "ransomware", "kimsuky", "docswap", "quishing", "microsoft-patch-tuesday", "esxi", "breachforums", "vect-ransomware", "office-rce", "mobile-malware"]
categories: ["briefme"]
author: "Kelvin Lomboy"
summary: "Microsoft January Patch Tuesday zero-day (CVE-2026-20805), critical Office RCE flaws via Preview Pane, Kimsuky QR 'quishing' mobile espionage, Chinese-linked ESXi hypervisor exploitation, BreachForums database leak exposing 324K users, and emerging Vect ransomware RaaS."
---

<pre class="ascii-header-box" style="text-align: center;">
┌──────────────────────────────────────────────────┐
│ 0K THREAT INTEL │ KEEPING ATTACKERS FROZEN       │
│ Weekly Briefing │ Jan 9-16, 2026 │ 0K-TI-2026-W03│
└──────────────────────────────────────────────────┘
</pre>

<p style="text-align: center;">
<strong>Classification:</strong> TLP:CLEAR &nbsp;&nbsp;&nbsp; <strong>Distribution:</strong> Unlimited &nbsp;&nbsp;&nbsp; <strong>Report ID:</strong> 0K-TI-2026-W03 &nbsp;&nbsp;&nbsp; <strong>Reporting Period:</strong> January 9-16, 2026
</p>

---

<div class="mobile-warning">
📱 <strong>Mobile Phone Detected</strong><br>
This full brief is optimized for desktop/tablet viewing. For mobile, please read the <a href="/briefme/weekly-threat-intel-jan-9-16-2026-tldr">2-minute TL;DR version</a> or switch to a larger screen for the best experience.
</div>

<br>
<br>

![Microsoft Office RCE Critical Threat January 2026](/images/briefme/office-rce-cve-2026-20952-jan-9-16.jpg)

## 1. EXECUTIVE SUMMARY

January 9–16, 2026 saw a heavy focus on Microsoft's January Patch Tuesday — including an actively exploited Desktop Window Manager zero-day (CVE-2026-20805) and two critical Office RCE flaws (CVE-2026-20952, CVE-2026-20953) — alongside high-impact breaches and advanced campaigns abusing QR codes and virtualization platforms. The period also featured the full doxxing of BreachForums users, large-scale social-media account data exposure, and continued ransomware evolution, plus ongoing North Korean (Kimsuky) QR "quishing" operations and Chinese-speaking activity against VMware ESXi. SOC teams should prioritize emergency patching of Microsoft endpoints, blocking high-confidence IOCs from Kimsuky and ESXi activity, and hunting for exposure tied to leaked BreachForums and social-media data.

**⚡ Short on time?** Read the **[2-minute TL;DR version](/briefme/weekly-threat-intel-jan-9-16-2026-tldr)** for quick mobile-optimized threat intel.

***

## 2. TRENDING SECURITY NEWS

### Microsoft January 2026 Patch Tuesday Zero-Day Focus

- **What:** Microsoft released patches for 113–114 vulnerabilities, including actively exploited Desktop Window Manager info-disclosure zero-day CVE-2026-20805 and critical Office RCE bugs CVE-2026-20952 and CVE-2026-20953.
- **Why it's trending:** Researchers emphasize the zero-day status of CVE-2026-20805, the preview-pane exploitability of the Office RCEs, and the high volume of elevation-of-privilege and RCE issues to triage.
- **Relevance:** Patch prioritization, Office hardening (disabling Preview Pane), and targeted hunting on DWM and Office exploitation paths are immediate tasks for SOCs.
- **Sources:** CrowdStrike, Qualys, Tenable, Zecurit

### BreachForums Database Leak Exposes Cybercriminal Identities

- **What:** A breach of BreachForums exposed about 324,000 user records including usernames, Argon2-hashed passwords, emails, IP addresses, registration times, and PGP keys, with public leak activity around January 9–10, 2026.
- **Why it's trending:** The irony of a major cybercrime marketplace suffering de-anonymization has driven extensive discussion on X/Reddit, plus speculation about follow-on law-enforcement operations and extortion.
- **Relevance:** SOC teams should expect re-use of exposed credentials, changes in threat-actor infrastructure, and potential attempts to weaponize the leaked data for phishing or fake "law-enforcement" scams.
- **Sources:** Rescana, Resecurity

### Kimsuky "Quishing" and DocSwap Mobile Malware

- **What:** DPRK-linked Kimsuky is distributing Android RAT malware "DocSwap" via QR-code phishing tied to spoofed logistics brands, using encrypted embedded APKs and RAT services for mobile surveillance and exfiltration.
- **Why it's trending:** The combination of QR codes, mobile platforms, and sophisticated RAT capabilities fits broader fears around MFA bypass and mobile-centric espionage, amplified by an FBI advisory on malicious QR ("quishing") tied to North Korea.
- **Relevance:** Organizations with mobile workforces must update awareness training, mobile MDM policies, and add QR-related indicators and Android malware detections into their monitoring.
- **Sources:** ENKI, The Hacker News, FBI Advisory

### Instagram 17.5M-Account Leak and Reset-Email Abuse

- **What:** Reports linked a BreachForums post to alleged data from 17.5 million Instagram accounts and a wave of password reset emails starting around January 9–10, 2026.
- **Why it's trending:** The scale, the link to a consumer platform, and the blending of legitimate reset emails with attacker-triggered flows are driving concern about large-scale account takeover and social-engineering.
- **Relevance:** SOC teams need to monitor for spikes in password-reset activity, phishing that abuses real brand flows, and commodity credential-stuffing sourced from this and other leaks.
- **Sources:** Bright Defense

### Record Ransomware Victim Counts and New Vect RaaS

- **What:** Reporting from late 2025 and early 2026 notes 839 claimed ransomware victims in December 2025, renewed LockBit activity, and the emergence of cross-platform Vect ransomware RaaS targeting organizations in Brazil, South Africa, and beyond.
- **Why it's trending:** Analysts view the volume spike and introduction of Vect's advanced OPSEC, multi-platform support, and affiliate model as signals that ransomware remains the dominant monetization threat.
- **Relevance:** SOCs should maintain strong ransomware-centric telemetry (VSS abuse, backup tampering, TOR traffic, data-theft staging) and be ready for rapid rebrand-style pivots like Vect.
- **Sources:** Red Piranha, Bitdefender

***

## 3. THREAT VISUALIZATIONS

<br>
<br>

```text
CRITICAL THREATS - RISK MATRIX (January 9-16, 2026)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IMPACT
10.0 │
     │
9.0  │                                   ★ Office RCE (CVE-2026-20952/20953)
     │                                   (CVSS 8.4, Zero-Click Email RCE)
8.0  │                ★ Vect Ransomware RaaS
     │                (Operational Disruption, Data Theft)
7.0  │            ★ Kimsuky DocSwap QR Campaign
     │            (Targeted Mobile Espionage)
6.0  │      ★ Instagram 17.5M Account Leak
     │      (Cred Theft, ATO Risk)
5.0  │          ★ CVE-2026-20805 DWM Info Leak
     │          (Zero-day, Exploited in Wild)
     └─────────────────────────────────────────────
       Low    Medium    High    Very High    Critical
                    LIKELIHOOD

RISK SCORE SCALE:
▓▓▓▓▓ CRITICAL (72-100)  - Office RCE (CVE-2026-20952/20953), Vect RaaS
▓▓▓▓░ HIGH (48-71)       - Kimsuky DocSwap, Instagram 17.5M Leak
▓▓▓░░ MEDIUM (25-47)     - CVE-2026-20805 DWM Info Leak
```

<br>
<br>

```text
MOST OBSERVED TACTICS (January 9-16, 2026)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Initial Access           ▓▓▓▓▓▓▓▓▓░  High (phishing, VPN/RDP, QR codes)
Execution                ▓▓▓▓▓▓▓▓░░  High (Office RCE, Android RATs)
Credential Access        ▓▓▓▓▓▓▓░░░  Moderate (phish kits, dumps)
Privilege Escalation     ▓▓▓▓▓▓░░░░  Moderate (Windows EoP chain prep)
Defense Evasion          ▓▓▓▓▓░░░░░  Moderate (Safe Mode, obfuscation)
Lateral Movement         ▓▓▓▓░░░░░░  Lower (Vect SMB/WinRM, ESXi pivot)
Collection               ▓▓▓▓▓▓░░░░  High (data theft pre-encryption)
Exfiltration             ▓▓▓▓▓▓░░░░  High (ransomware, espionage)
Command & Control        ▓▓▓▓▓░░░░░  Moderate (TOR, QR-delivered infra)

KEY INSIGHT: Adversaries combined social-engineering-driven
initial access with Office and mobile malware execution,
then moved rapidly to data theft and extortion rather than
purely destructive encryption.
```

<br>
<br>

```text
ORGANIZATIONS BY THREAT EXPOSURE (January 9-16, 2026)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FINANCIAL & CRYPTO
  Threats: ▓▓▓▓▓▓▓▓░░ High    Critical: ▓▓▓▓▓░░░░░ Moderate
  Primary vectors: Phishing, credential theft,
  ransomware.

TECHNOLOGY & CLOUD
  Threats: ▓▓▓▓▓▓▓▓▓░ Very High    Critical: ▓▓▓▓▓▓░░░ High
  Primary vectors: Office/Windows CVEs, ESXi
  exploits, supply chain.

HEALTHCARE
  Threats: ▓▓▓▓▓▓░░░░ Moderate    Critical: ▓▓▓░░░░░░ Lower
  Primary vectors: Ransomware, web app compromise,
  vendor breaches.

GOVERNMENT & CRITICAL INFRA
  Threats: ▓▓▓▓▓▓▓░░░ High    Critical: ▓▓▓▓▓░░░░░ Moderate
  Primary vectors: APT phishing, QR quishing,
  KEV-listed CVEs.
```

***

## 4. CRITICAL VULNERABILITIES (Top 5)

### 4.1 CVE-2026-20805 – Windows Desktop Window Manager Information Disclosure (Zero-Day)

- **Details:** Information-disclosure vulnerability in Desktop Window Manager (DWM) affecting supported Windows desktop and server versions; CVSS 5.5, rated Important but confirmed exploited in the wild and added to CISA KEV.
- **Exploitation status:** Actively exploited prior to January Patch Tuesday; CISA mandates federal agencies patch by February 3, 2026.
- **Affected products/versions:** Windows 10/11 and Windows Server 2016–2025 per Microsoft and national advisories.
- **Attack vector:** Locally authenticated attacker abuses DWM's handling of memory to disclose sensitive information (e.g., section addresses from remote ALPC ports) that can facilitate further exploitation chains.
- **IOCs / Behaviors (inferred from exploitation profile):**
    - Unusual DWM-related crashes or access violations shortly before other local EoP events.
    - Sequences of local logon followed by privilege-escalation attempts from the same user/session on fully patched components except DWM.
- **Detection guidance:** See **Sigma Rule: CVE-2026-20805_DWM_Info_Leak_Abuse** in Section 9.1.

**Example Query (Pseudo-code - Generic SIEM Logic):**

```text
WHERE EventID IN (1000, 1001)            -- App crash / fault
  AND process_name = "dwm.exe"
  AND exception_module != "dwmcore.dll"
  AND time_window_precedes(
        EXISTS(
          SELECT * FROM security_events
          WHERE EventID IN (4624, 4672)  -- logon + special privileges
            AND same_host
            AND within 15 minutes
        )
      )
```

- **Remediation steps:**
    - Apply January 2026 cumulative updates for all affected Windows desktop and server systems as per Microsoft's advisory and national guidance.
    - Prioritize internet-exposed or high-value systems and those used by administrators or developers.
    - Ensure rapid deployment in FCEB and similar environments observing the KEV remediation deadline.

***

### 4.2 CVE-2026-20952 – Microsoft Office Remote Code Execution (Preview Pane)

- **Details:** Critical RCE vulnerability in Microsoft Office components with CVSS 8.4; exploitation possible via email preview without opening the document.
- **Exploitation status:** No public exploitation confirmed yet, but multiple security vendors classify it as high-risk because of preview-pane attack vector.
- **Affected products/versions:** Multiple Office components (including Outlook preview), on supported Windows versions per Microsoft Patch Tuesday analyses.
- **Attack vector:** Maliciously crafted Office documents delivered via email; previewing in Outlook triggers processing of malformed embedded objects/structures, allowing attacker code execution in user context.
- **IOCs / Behaviors:**
    - Inbound emails with Office attachments from newly seen or anomalous senders shortly before endpoint process-spawn anomalies from Office processes.
    - Office processes spawning scripting interpreters (PowerShell, cmd, wscript) or LOLBin tools shortly after preview.
- **Detection guidance:** See **Sigma Rule: Office_RCE_Preview_Pane_CVE-2026-20952_20953** in Section 9.1.

**Detection Query (Pseudo-code - Generic SIEM Logic):**

```text
WHERE parent_process IN ("OUTLOOK.EXE", "WINWORD.EXE")
  AND process_name IN ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
  AND command_line CONTAINS_ANY ("-enc ", "DownloadString", "Invoke-Expression")
  AND email_event.attachment_type IN ("doc", "docx", "rtf")
```

- **Remediation steps:**
    - Deploy January 2026 Office patches across desktops, VDI, and RDS hosts as a high priority.
    - Temporarily disable Outlook Preview Pane in high-risk environments until patch coverage is validated.
    - Enforce macro restrictions and application control to limit downstream execution from Office processes.

***

### 4.3 CVE-2026-20953 – Microsoft Office Remote Code Execution (Related Preview-Pane Vector)

- **Details:** Companion critical RCE to CVE-2026-20952 in Microsoft Office, also CVSS 8.4; triggered by malformed file structures/embedded objects in crafted documents.
- **Exploitation status:** No confirmed active exploitation yet, but same preview-pane exposure and similar risk profile.
- **Affected products/versions:** Same Office family components as CVE-2026-20952, covering multiple desktop Office releases.
- **Attack vector:** Email-delivered malicious documents processed by Outlook/Office previewer, enabling initial access without explicit document opening.
- **IOCs / Behaviors:**
    - Surges in blocked or suspicious Office attachments with uncommon structures; correlation with EDR alerts on Office child processes.
    - Endpoint telemetry showing Office spawning network connections to unusual domains or IPs shortly after preview.
- **Detection guidance:** Covered by same **Sigma Rule: Office_RCE_Preview_Pane_CVE-2026-20952_20953** in Section 9.1.
- **Remediation steps:**
    - Patch management identical to CVE-2026-20952; treat both as a combined risk bucket.
    - Enhance content-filtering policies for Office attachments and detonate high-risk samples in sandboxes.

***

### 4.4 VMware ESXi Zero-Day Chain in Chinese-Linked Campaign (Unassigned Public CVE at Time of Reporting)

- **Details:** Huntress research documented Chinese-speaking threat actors exploiting VMware ESXi zero-day flaws (information leak, memory corruption, sandbox escape) to pivot from guest VM to hypervisor control.
- **Exploitation status:** Observed in live intrusions in December 2025; activity continued relevance through January 2026 with disclosure on January 11.
- **Affected products/versions:** VMware ESXi hypervisors in on-prem datacenters and cloud environments where unpatched or exposed management services were present.
- **Attack vector:** Compromised SonicWall VPN provided initial access; attackers then leveraged a bespoke ESXi exploit chain from inside guest VMs to escape isolation and gain hypervisor-level control.
- **IOCs / Behaviors:**
    - Unusual administrative actions on ESXi hosts originating from guest VMs or newly established accounts.
    - SonicWall VPN access from atypical IP ranges followed by ESXi configuration or snapshot activity.
- **Detection guidance:** See **Sigma Rule: VMware_ESXi_Hypervisor_Escape** and **Snort Rule: Suspicious_ESXi_Management_Access** in Section 9.
- **Remediation steps:**
    - Apply all available VMware ESXi security updates once CVEs and patches are formally published; review vendor hardening guidance.
    - Restrict ESXi management interfaces to dedicated admin networks and enforce MFA on VPNs.
    - Review hypervisor audit logs for suspicious configuration changes and unexpected VM state transitions.

***

### 4.5 CISA KEV-Highlighted Legacy and Infrastructure Vulnerabilities (Representative: Critical HPE OneView RCE & Older Office Flaws)

- **Details:** Recent CISA KEV commentary highlights a maximum-severity RCE in HPE OneView and very old Microsoft Office flaws still being actively exploited against infrastructure-like environments.
- **Exploitation status:** KEV inclusion indicates confirmed exploitation; these issues remain widely unpatched in some environments.
- **Affected products/versions:** HPE OneView management software and older Office components still in use in ICS/engineering contexts.
- **Attack vector:** Exposed management interfaces and document-based exploitation leveraging known but unpatched vulnerabilities.
- **IOCs / Behaviors:**
    - External connections to HPE OneView from non-admin networks; anomalous API calls or configuration changes.
    - Use of very old Office formats or exploit kits targeting legacy Office vulnerabilities in engineering and utility environments.
- **Detection guidance:** See **Sigma Rule: Management_Interface_RCE_Abuse** in Section 9.
- **Remediation steps:**
    - Inventory and patch all KEV-listed vulnerabilities in scope, starting with external-facing management systems.
    - Where patching is not immediately possible, implement network isolation, WAF/IPS rules, and strict access control.

***

## 5. MAJOR INCIDENTS (Top 3)

### 5.1 BreachForums User Database Compromise

- **Timeline:**
    - August 11, 2025 – Last user registration in the leaked database (aligns with prior shutdown timeline).
    - October 2025 – Law enforcement seizes breachforums[.]hn domain.
    - January 9, 2026 – Leaked database with ~324,000 user records published online.
    - January 10–12, 2026 – Researchers and media validate authenticity and scope.
- **Attack chain:**
    - **Initial access:** Exploit of MyBB misconfiguration or vulnerability against BreachForums platform; mapped to ATT&CK T1190 (Exploit Public-Facing Application).
    - **Persistence/collection:** Attacker obtained database content, likely via unsecured cloud storage object or direct DB export, mapped to T1530 (Data from Cloud Storage Object).
    - **Exfiltration/impact:** Database containing usernames, Argon2-hashed passwords, emails, IPs, registration dates, and PGP keys published, exposing cybercriminal identities and infrastructure.
- **Data compromised:**
    - Usernames and email addresses used by forum members.
    - Argon2-hashed passwords and IP addresses, plus registration dates and PGP keys.
- **Affected organizations/sectors:** Primarily impacts cybercriminals, brokers, and associated infrastructure, but also has knock-on effects for organizations whose data or credentials may have been traded there.
- **Hunting guidance:**
    - See **Sigma Rule: Public_Facing_App_Exploit_Data_Dump** and **YARA Rule: Leaked_Credential_Dumps_Generic** in Section 9.
    - Hunt for:
        - Internal accounts whose passwords match credentials discovered in the leaked corpus (via secure, offline comparison).
        - Inbound phishing or extortion campaigns referencing BreachForums or using exposed PGP keys as lures.

**Example Hunt Query (SQL - OSQuery):**

```sql
-- Detect accounts potentially reusing leaked BreachForums passwords (via offline comparison list)
-- Platform: Windows/Linux/macOS
-- Use case: Hunting
SELECT
    u.username,
    u.uid,
    u.description
FROM users u
JOIN leaked_password_reuse l
  ON u.username = l.local_username
WHERE l.match_score >= 0.8;
```

***

### 5.2 Instagram 17.5M Account Leak and Reset-Email Wave

- **Timeline:**
    - January 9, 2026 – Spike in Instagram password reset emails observed, influenced by attacker campaigns.
    - January 10, 2026 – BreachForums-linked post updated describing alleged leak of data from 17.5 million Instagram accounts.
- **Attack chain:**
    - **Initial access:** Not fully disclosed; attackers appear to have obtained a large dataset of account details, potentially via prior breaches or third-party compromise.
    - **Abuse:** Attackers trigger legitimate Instagram password reset emails to targets, increasing user confusion and making phishing/reset-theft campaigns more effective.
    - **Impact:** Elevated risk of account takeover (ATO), cross-platform impersonation, and further phishing using compromised accounts.
- **Data compromised:**
    - Alleged dataset includes account identifiers and associated email addresses for approximately 17.5 million users.
- **Affected organizations/sectors:**
    - Consumers, influencers, and businesses using Instagram for marketing or customer support; risk of brand impersonation and fraud.
- **Hunting guidance:**
    - See **Sigma Rule: Social_Media_Reset_OAuth_Anomaly** in Section 9.
    - Hunt for:
        - Unusual OAuth logins or password resets linked to employee corporate email addresses used for Instagram or Meta accounts.
        - Increased failed login attempts or push-MFA fatigue events tied to social-media auth providers.

***

### 5.3 Emerging Vect Ransomware RaaS Operations

- **Timeline:**
    - Early January 2026 – Vect ransomware identified as a new RaaS family in threat-intel reporting.
    - January 6–12, 2026 – Documented attacks on organizations in Brazil and South Africa across education and manufacturing, with data theft and full network compromise claims.
- **Attack chain:**
    - **Initial access:** Exposed RDP/VPN services or stolen credentials, plus phishing and possibly vulnerable external endpoints.
    - **Privilege escalation:** Attacker obtains admin rights to change boot settings, stop services, and propagate encryption.
    - **Lateral movement:** Use of SMB admin shares (ADMIN$, C$), remote execution, WinRM/PowerShell remoting for mass deployment.
    - **Collection/exfiltration:** Large-volume data theft (e.g., 150GB+) of PII and internal documents before encryption, with data staged then exfiltrated.
    - **Impact:** Double-extortion with operational disruption and exposure of sensitive records.
- **Data compromised:**
    - Victim records, PII, and internal documents; individual incidents report theft in the 150GB range.
- **Affected organizations/sectors:**
    - Initial victims include education and manufacturing in Brazil and South Africa, with likely expansion to other sectors.
- **Hunting guidance:**
    - See **Sigma Rule: Vect_Ransomware_PreEncryption**, **YARA Rule: Vect_Ransomware_Family**, and **Snort Rule: Vect_TOR_C2_Payment** in Section 9.
    - Artifacts to search:
        - vssadmin or wbadmin invocations deleting shadow copies.
        - Sudden spikes in SMB traffic to multiple hosts from a single admin endpoint.
        - TOR-related outbound connections from servers or desktops.

**Example Hunt Query (Pseudo-code - Generic SIEM Logic):**

```text
WHERE process_name IN ("vssadmin.exe", "wbadmin.exe")
  AND command_line CONTAINS "delete"
  AND host_role IN ("server", "fileserver")
  AND EXISTS (
        SELECT 1 FROM network_logs n
        WHERE n.src_host = host
          AND n.dest_port IN (9001, 9050, 9051)
          AND n.dest_ip_category = "TOR_Exit"
          AND n.timestamp BETWEEN process_time AND process_time + 30 minutes
      )
```

***

<br>
<br>

![Kimsuky DocSwap QR Quishing Campaign January 2026](/images/briefme/kimsuky-docswap-quishing-jan-2026.jpg)

## 6. THREAT ACTOR CAMPAIGNS (Top 3)

### 6.1 Kimsuky – DocSwap QR "Quishing" Mobile Espionage

- **Attribution:**
    - Actor: Kimsuky (DPRK-linked), with high confidence based on shared C2 infrastructure, Korean-language comments, and overlaps with prior campaigns.
- **Targets:**
    - Primarily South Korean organizations and individuals; broader at-risk set includes entities interacting with logistics and shipping brands mimicked by the phishing sites.
    - Sectors: Government, research, logistics, and individuals of intelligence value.
- **TTPs (MITRE ATT&CK):**
    - T1566 – Phishing via QR-linked websites delivering malicious APKs.
    - T1476 – Deliver Malicious App (mobile) using repackaged legitimate logistics-branded APKs.
    - T1409 – Access Sensitive Data in Files for mobile exfiltration.
    - T1412 – Capture Audio/Screen through RAT capabilities on Android devices.
- **IOCs & infrastructure (examples from ENKI and related reporting):**
    - Malicious Android package names and C2 domains associated with DocSwap distribution.
    - Strings such as "Million OK!!!" observed on C2 infrastructure, linking to prior Kimsuky activity.
- **Detection & hunting guidance:**
    - See **YARA Rule: Kimsuky_DocSwap_Android** and **Snort Rule: Kimsuky_DocSwap_APK_Download** in Section 9.
    - Hunt for:
        - Mobile devices that sideload APKs from QR-origin URLs, especially branded as logistics apps.
        - HTTP(S) traffic from endpoints to known DocSwap C2 domains or anomalous Android update paths.

**Example Hunt Query (SQL - OSQuery, Android/ChromeOS-style endpoint telemetry via extension):**

```sql
-- Detect sideloaded Android APKs from non-official sources
-- Platform: Android (via MDM/EMM DB export)
-- Use case: Hunting
SELECT
    device_id,
    package_name,
    installer_package_name,
    first_install_time
FROM android_packages
WHERE installer_package_name NOT IN ('com.android.vending', 'com.google.android.packageinstaller')
  AND first_install_time >= '2026-01-01';
```

- **Defensive actions:**
    - Enforce MDM policies to block sideloading and restrict installations to official app stores.
    - Incorporate QR-code safety awareness into security training programs.
    - Add DocSwap IOCs and YARA rules to mobile file-scanning workflows where supported.

***

### 6.2 Chinese-Linked ESXi Hypervisor Exploitation

- **Attribution:**
    - Actor: Unnamed Chinese-speaking threat group; suspected based on simplified Chinese usage, sophistication, and infrastructure characteristics.
    - Confidence: Medium, as direct state attribution is not yet public but linguistic and tooling clues are present.
- **Targets & geographies:**
    - Organizations running VMware ESXi, including hosting providers and enterprises observed by Huntress; specific victim industries not fully disclosed.
- **TTPs (MITRE ATT&CK):**
    - T1133 – External Remote Services (compromised SonicWall VPN).
    - T1068 – Exploitation for Privilege Escalation via ESXi hypervisor exploit chain.
    - T1570 – Lateral Tool Transfer within virtualized environments.
    - T1486 – Data Encrypted for Impact (attack likely to end with ransomware).
- **IOCs & infrastructure:**
    - SonicWall VPN access from suspicious IP ranges preceding ESXi events.
    - Custom ESXi exploit tooling observed in memory and logs in Huntress environment.
- **Detection & hunting guidance:**
    - See **Sigma Rule: VPN_to_ESXi_Attack_Chain** and **Snort Rule: Suspicious_ESXi_Management_Access** in Section 9.
    - Hunt for:
        - VPN logins from unusual countries followed by ESXi management actions from same source IP.
        - Non-standard ESXi configuration changes or scripts executed from guest VMs.
- **Defensive actions:**
    - Segment ESXi management interfaces and restrict administrative access tightly, with MFA enforced on VPNs.
    - Monitor guest-to-host interaction patterns and centralize ESXi logging.

***

### 6.3 Vect Ransomware RaaS

- **Attribution:**
    - Actor: Vect ransomware operators; possible rebrand or new venture by experienced affiliates due to sophisticated OPSEC and tooling.
    - Confidence: Medium, as linkages to specific prior groups are inferred from tradecraft.
- **Targets & geographies:**
    - Initial victims in Brazil and South Africa in education and manufacturing, with hints of broader sectoral reach.
- **TTPs (MITRE ATT&CK):**
    - T1078 – Valid Accounts via stolen or purchased credentials for RDP/VPN.
    - T1562 – Impair Defenses by disabling security tools and backups.
    - T1021 – Remote Services using SMB, WinRM, and other remote execution methods.
    - T1486 – Data Encrypted for Impact plus double-extortion data theft.
- **IOCs & infrastructure:**
    - Use of Monero for payments, TOX protocol for affiliate communications, and exclusive TOR hidden services for leak sites and negotiation portals.
    - Claims of 150GB-scale data theft and full-network compromise in early victims.
- **Detection & hunting guidance:**
    - See **Sigma Rule: Vect_Ransomware_PreEncryption**, **YARA Rule: Vect_Ransomware_Family**, and **Snort Rule: Vect_TOR_C2_Payment** in Section 9.
    - Hunt for:
        - Service-stop commands targeting backup, database, and mail-server processes followed by encryption activity.
        - TOR-related outbound traffic from non-proxy infrastructure and the presence of TOX-related binaries or libraries.
- **Defensive actions:**
    - Enforce MFA and strict access policies on RDP/VPN and administrative accounts.
    - Isolate and monitor backup infrastructure; ensure immutable or offline copies.

***

## 7. MITRE ATT&CK SUMMARY

<table>
<thead>
<tr>
<th align="left">Rank</th>
<th align="left">Tactic</th>
<th align="left">Example Techniques (T#)</th>
<th align="left">Example from Period</th>
</tr>
</thead>
<tbody>
<tr>
<td data-label="Rank:">1</td>
<td data-label="Tactic:">Initial Access</td>
<td data-label="Techniques:">T1566, T1190, T1133</td>
<td data-label="Example:">Kimsuky QR phishing, BreachForums MyBB exploit, SonicWall VPN abuse</td>
</tr>
<tr>
<td data-label="Rank:">2</td>
<td data-label="Tactic:">Execution</td>
<td data-label="Techniques:">T1203, mobile app execution</td>
<td data-label="Example:">Office RCE via preview, DocSwap Android RAT execution</td>
</tr>
<tr>
<td data-label="Rank:">3</td>
<td data-label="Tactic:">Credential Access</td>
<td data-label="Techniques:">T1552</td>
<td data-label="Example:">Exposure of hashed passwords and PGP keys in BreachForums leak</td>
</tr>
<tr>
<td data-label="Rank:">4</td>
<td data-label="Tactic:">Privilege Escalation</td>
<td data-label="Techniques:">T1068</td>
<td data-label="Example:">ESXi hypervisor exploitation chain</td>
</tr>
<tr>
<td data-label="Rank:">5</td>
<td data-label="Tactic:">Defense Evasion</td>
<td data-label="Techniques:">T1562</td>
<td data-label="Example:">Vect disabling backups/services prior to encryption</td>
</tr>
<tr>
<td data-label="Rank:">6</td>
<td data-label="Tactic:">Lateral Movement</td>
<td data-label="Techniques:">T1021</td>
<td data-label="Example:">Vect using SMB admin shares and WinRM</td>
</tr>
<tr>
<td data-label="Rank:">7</td>
<td data-label="Tactic:">Collection</td>
<td data-label="Techniques:">T1530, mobile collection</td>
<td data-label="Example:">BreachForums DB export; DocSwap data harvesting</td>
</tr>
<tr>
<td data-label="Rank:">8</td>
<td data-label="Tactic:">Exfiltration</td>
<td data-label="Techniques:">T1041 (implied), mobile exfil</td>
<td data-label="Example:">Vect large-volume data theft pre-encryption</td>
</tr>
<tr>
<td data-label="Rank:">9</td>
<td data-label="Tactic:">Command & Control</td>
<td data-label="Techniques:">TOR C2, QR-delivered infra</td>
<td data-label="Example:">Vect TOR services; Kimsuky C2 infrastructure</td>
</tr>
<tr>
<td data-label="Rank:">10</td>
<td data-label="Tactic:">Impact</td>
<td data-label="Techniques:">T1486</td>
<td data-label="Example:">Ransomware encryption campaigns</td>
</tr>
</tbody>
</table>

***

## 8. IOC SUMMARY

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
<td data-label="IOC:">CVE-2026-20805</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">Windows DWM zero-day</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">CVE-2026-20952</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">Office Preview Pane RCE</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">CVE-2026-20953</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">Office Preview Pane RCE</td>
<td data-label="Action:">Patch</td>
</tr>
<tr>
<td data-label="IOC:">BreachForums Argon2 password set</td>
<td data-label="Type:">Behavioral</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">BreachForums DB leak</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">BreachForums user PGP key corpus</td>
<td data-label="Type:">Behavioral</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">BreachForums DB leak</td>
<td data-label="Action:">Monitor</td>
</tr>
<tr>
<td data-label="IOC:">17.5M Instagram account dataset</td>
<td data-label="Type:">Behavioral</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">Instagram account leak/reset abuse</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">Monero payment addresses (Vect)</td>
<td data-label="Type:">Behavioral</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat:">Vect Ransomware RaaS</td>
<td data-label="Action:">Monitor</td>
</tr>
<tr>
<td data-label="IOC:">TOR .onion leak site (Vect)</td>
<td data-label="Type:">URL</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat:">Vect Ransomware RaaS</td>
<td data-label="Action:">Block</td>
</tr>
<tr>
<td data-label="IOC:">SonicWall VPN anomalous IP pool</td>
<td data-label="Type:">IP Address</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat:">ESXi hypervisor exploit chain</td>
<td data-label="Action:">Block</td>
</tr>
<tr>
<td data-label="IOC:">QR-code phishing DocSwap sites</td>
<td data-label="Type:">URL</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">Kimsuky DocSwap campaign</td>
<td data-label="Action:">Block</td>
</tr>
<tr>
<td data-label="IOC:">DocSwap Android APK family</td>
<td data-label="Type:">File Hash (SHA256)</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">Kimsuky mobile malware</td>
<td data-label="Action:">Block</td>
</tr>
<tr>
<td data-label="IOC:">Kimsuky DocSwap C2 domains</td>
<td data-label="Type:">Domain</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">Kimsuky mobile malware C2</td>
<td data-label="Action:">Block</td>
</tr>
<tr>
<td data-label="IOC:">Vect affiliate TOX infra pattern</td>
<td data-label="Type:">Behavioral</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat:">Vect RaaS communications</td>
<td data-label="Action:">Hunt</td>
</tr>
<tr>
<td data-label="IOC:">TOR exit node category outbound</td>
<td data-label="Type:">Behavioral</td>
<td data-label="Confidence:">Medium</td>
<td data-label="Threat:">Multiple ransomware/C2 use cases</td>
<td data-label="Action:">Monitor</td>
</tr>
<tr>
<td data-label="IOC:">Legacy KEV HPE OneView RCE</td>
<td data-label="Type:">CVE</td>
<td data-label="Confidence:">High</td>
<td data-label="Threat:">Critical infrastructure management RCE</td>
<td data-label="Action:">Patch</td>
</tr>
</tbody>
</table>

*All IOC categories and associations drawn from referenced reporting; implement with concrete values from underlying advisories and intel feeds when deploying operationally.*

***

## 9. DETECTION RULES

### 9.1 Sigma Rules (SIEM Detection)

```yaml
title: CVE-2026-20805 DWM Information Leak Abuse
id: 3e2f6f0b-0d76-4c7d-8f7a-20805dwm0001
status: experimental
date: 2026-01-16
description: >
  Detects suspicious Desktop Window Manager (dwm.exe) crashes and
  access-violation patterns potentially associated with exploitation
  of CVE-2026-20805.
author: Threat Intelligence Team
severity: medium

logsource:
  product: windows
  service: application

detection:
  selection_crash:
    EventID: 1000
    ProcessName|endswith: '\dwm.exe'

  selection_faulting:
    EventID: 1000
    FaultingModuleName|endswith:
      - '.dll'
      - '.exe'
    FaultingModuleName|contains:
      - 'ntdll'
      - 'kernel32'

  filter_known:
    FaultingModuleName:
      - 'dwmcore.dll'

  condition: selection_crash and selection_faulting and not filter_known

falsepositives:
  - Rare graphics driver or desktop customization conflicts causing dwm.exe faults.

references:
  - https://www.tenable.com/blog/microsofts-january-2026-patch-tuesday-addresses-113-cves-cve-2026-20805
  - https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review

fields:
  - EventID
  - ProcessName
  - FaultingModuleName
  - Computer
  - TimeCreated
```

```yaml
title: Office RCE via Preview Pane (CVE-2026-20952/20953)
id: 9a4bb5b4-5b4f-4c99-8e29-office-rce-20952-20953
status: experimental
date: 2026-01-16
description: >
  Detects suspicious child processes spawned from Outlook or Word
  that may indicate exploitation of CVE-2026-20952/20953 via
  Preview Pane-delivered malicious documents.
author: Threat Intelligence Team
severity: critical

logsource:
  product: windows
  service: security

detection:
  selection_parent:
    EventID: 4688
    ParentProcessName|endswith:
      - '\OUTLOOK.EXE'
      - '\WINWORD.EXE'

  selection_child:
    NewProcessName|endswith:
      - '\powershell.exe'
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'

  selection_cmd:
    CommandLine|contains:
      - '-enc '
      - 'DownloadString'
      - 'Invoke-Expression'
      - 'FromBase64String'

  condition: selection_parent and selection_child and selection_cmd

falsepositives:
  - Rare administrative scripts intentionally launched from Office documents.
  - Security testing tools or red-team exercises.

references:
  - https://www.zecurit.com/endpoint-management/patch-tuesday/
  - https://www.rescana.com/post/microsoft-patch-tuesday-january-2026-critical-windows-office-firefox-and-chrome-vulnerabilities

fields:
  - EventID
  - NewProcessName
  - ParentProcessName
  - CommandLine
  - SubjectUserName
  - Computer
```

```yaml
title: Vect Ransomware Pre-Encryption Activity
id: 5b7ac4b9-8aa7-4767-9b6a-vect-preenc-2026
status: experimental
date: 2026-01-16
description: >
  Detects behavior associated with Vect ransomware prior to encryption,
  including deletion of shadow copies and backup-related services on servers.
author: Threat Intelligence Team
severity: critical

logsource:
  product: windows
  service: security

detection:
  selection_vss:
    EventID: 4688
    NewProcessName|endswith: '\vssadmin.exe'
    CommandLine|contains:
      - 'Delete Shadows'
      - 'delete shadows'

  selection_wbadmin:
    EventID: 4688
    NewProcessName|endswith: '\wbadmin.exe'
    CommandLine|contains:
      - 'delete'
      - 'cleanup'

  selection_services:
    EventID: 7036
    ServiceName|contains:
      - 'VSS'
      - 'SQL'
      - 'Exchange'
      - 'Veeam'

  condition: (selection_vss or selection_wbadmin) or selection_services

falsepositives:
  - Legitimate backup maintenance or manual cleanup operations by administrators.

references:
  - https://redpiranha.net/news/threat-intelligence-report-january-6-january-12-2026

fields:
  - EventID
  - NewProcessName
  - CommandLine
  - ServiceName
  - SubjectUserName
  - Computer
```

```yaml
title: QR-Based Phishing and DocSwap Sideload Indicators
id: 0d75f8a3-6ad1-4b1a-9b22-kimsuky-docswap-qr
status: experimental
date: 2026-01-16
description: >
  Detects potential sideloaded Android APK installations and QR-based
  phishing activity associated with Kimsuky DocSwap campaigns in
  enterprise environments.
author: Threat Intelligence Team
severity: high

logsource:
  product: web
  service: proxy

detection:
  selection_url:
    url|contains:
      - 'qrcode'
      - 'qr-code'
      - 'docswap'
      - 'cjlogistics'

  selection_apk:
    url|endswith:
      - '.apk'

  condition: selection_url and selection_apk

falsepositives:
  - Legitimate QR code generators or APK distributions in developer environments.

references:
  - https://www.enki.co.kr/en/media-center/blog/kimsuky-distributing-malicious-mobile-app-via-qr-code
  - https://thehackernews.com/2025/12/kimsuky-spreads-docswap-android-malware.html

fields:
  - url
  - src_ip
  - user
  - http_user_agent
```

***

### 9.2 YARA Rules (File/Malware Detection)

```yara
rule Kimsuky_DocSwap_Android {
    meta:
        description = "Detects DocSwap Android malware used in Kimsuky \
                       QR-based campaigns"
        author = "Threat Intelligence Team"
        date = "2026-01-16"
        reference = "https://www.enki.co.kr/en/media-center/blog/\
                     kimsuky-distributing-malicious-mobile-app-via-qr-code"
        severity = "critical"
        campaign = "Kimsuky_DocSwap_QR_2025_2026"

    strings:
        $mz = { 50 4B 03 04 }
        $string1 = "Million OK!!!" ascii
        $string2 = "com.cjlogistics.android" ascii
        $string3 = "DocSwap" ascii
        $code1 = { 55 8B EC 83 EC ?? 53 56 57 }

    condition:
        $mz at 0 and
        filesize < 20MB and
        2 of ($string*) or $code1
}
```

```yara
rule Vect_Ransomware_Family {
    meta:
        description = "Detects samples associated with Vect ransomware RaaS"
        author = "Threat Intelligence Team"
        date = "2026-01-16"
        reference = "https://redpiranha.net/news/\
                     threat-intelligence-report-january-6-january-12-2026"
        severity = "critical"
        campaign = "Vect_RaaS_2026"

    strings:
        $mz = { 4D 5A }
        $string1 = "Vect Ransomware" ascii wide
        $string2 = "YOUR FILES ARE ENCRYPTED BY VECT" ascii wide
        $string3 = "Monero address:" ascii
        $note1 = ".vectnote" ascii

    condition:
        $mz at 0 and
        filesize < 10MB and
        2 of ($string*)
}
```

```yara
rule Leaked_Credential_Dumps_Generic {
    meta:
        description = "Heuristic rule to flag large text archives resembling \
                       credential dumps such as BreachForums user leaks"
        author = "Threat Intelligence Team"
        date = "2026-01-16"
        reference = "https://www.rescana.com/post/breachforums-data-breach-\
                     exposes-324-000-user-records-after-mybb-misconfiguration-in-2026"
        severity = "high"
        campaign = "BreachForums_DB_Leak_2026"

    strings:
        $s1 = "argon2" ascii nocase
        $s2 = "@pgp" ascii nocase
        $s3 = "BEGIN PGP PUBLIC KEY BLOCK" ascii
        $s4 = "breachforums" ascii nocase

    condition:
        filesize > 1MB and
        2 of ($s*)
}
```

***

### 9.3 Snort/Suricata Rules (Network Detection)

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"MALWARE Kimsuky DocSwap APK download via QR phishing";
    flow:to_client,established;
    content:".apk"; http_uri; nocase;
    content:"cjlogistics"; http_host; nocase;
    pcre:"/\/.*(docswap|android|apk)/Ui";
    reference:url,www.enki.co.kr/en/media-center/blog/kimsuky-distributing-malicious-mobile-app-via-qr-code;
    classtype:trojan-activity;
    sid:10002026;
    rev:1;
    metadata:created_at 2026_01_16, attack_target Client_Endpoint;
)
```

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"RANSOMWARE Vect TOR/Onion C2 or payment communication";
    flow:to_server,established;
    content:".onion"; http_header; nocase;
    pcre:"/Host\x3a\s+[a-z0-9]{16}\.onion/Ui";
    reference:url,redpiranha.net/news/threat-intelligence-report-january-6-january-12-2026;
    classtype:trojan-activity;
    sid:10002027;
    rev:1;
    metadata:created_at 2026_01_16, attack_target Client_Endpoint;
)
```

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (
    msg:"SUSPICIOUS ESXi management access following VPN tunnel establishment";
    flow:to_server,established;
    content:"/ui"; http_uri; nocase;
    content:"Host:"; http_header;
    pcre:"/Host\x3a\s+[^ \r\n]+:443/Ui";
    reference:url,thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html;
    classtype:attempted-admin;
    sid:10002028;
    rev:1;
    metadata:created_at 2026_01_16, attack_target Server;
)
```

***

### 9.4 OSQuery Queries (Endpoint Hunting)

```sql
-- Detect potential Vect ransomware pre-encryption behavior via backup deletion tools
-- Platform: Windows
-- Use case: Hunting
SELECT
    p.pid,
    p.name,
    p.cmdline,
    p.path,
    p.parent,
    datetime(p.start_time, 'unixepoch') AS started_at
FROM processes p
WHERE p.name IN ('vssadmin.exe', 'wbadmin.exe')
  AND p.cmdline LIKE '%delete%'
  AND p.path LIKE 'C:\Windows\System32\%';
```

```sql
-- Identify Outlook or Word spawning scripting engines, indicative of Office RCE exploitation
-- Platform: Windows
-- Use case: Detection/Hunting
SELECT
    c.pid,
    c.name,
    c.cmdline,
    p.name AS parent_name,
    p.cmdline AS parent_cmdline
FROM processes c
JOIN processes p ON c.parent = p.pid
WHERE p.name IN ('OUTLOOK.EXE', 'WINWORD.EXE')
  AND c.name IN ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe');
```

***

### Deployment Guide (Summary)

- **Sigma → SIEM:** Convert Sigma rules to Splunk SPL, KQL, Elastic, QRadar, or Chronicle using sigmac or pySigma and map fields per your log schema.
- **YARA → EDR/File Scanners:** Deploy YARA rules to CrowdStrike, Carbon Black, THOR, or VirusTotal Hunting; use memory-scanning in Volatility/Velociraptor for DocSwap and ransomware samples.
- **Snort/Suricata → IDS/IPS:** Import directly into Snort/Suricata, or adapt for Zeek, firewalls, and cloud IDS; monitor for QR APK downloads, TOR .onion traffic, and suspicious ESXi access.
- **OSQuery → Endpoint:** Add queries to Fleet, Kolide, or native osquery configs as scheduled hunts focusing on Office exploitation and pre-ransomware behaviors.

***

## 10. DEFENSIVE RECOMMENDATIONS

### IMMEDIATE (0–24 hours)

- [ ] **Apply January 2026 Microsoft patches**, prioritizing CVE-2026-20805 and CVE-2026-20952/20953 on all Windows and Office endpoints and servers.
- [ ] Block high-confidence QR-based DocSwap and Kimsuky domains/URLs and deploy YARA/Snort rules for DocSwap detection.
- [ ] Ingest and block known TOR/onion C2 indicators used by Vect and other ransomware where feasible.
- [ ] Begin outbound scanning for ESXi management access patterns and tighten ACLs around management interfaces.

### SHORT-TERM (24–72 hours)

- [ ] Run environment-wide hunts using the Sigma/YARA/OSQuery artifacts from Section 9 for Office RCE exploitation, Vect behaviors, and QR phishing activity.
- [ ] Audit external-facing RDP/VPN, enforce MFA, and remediate weak authentication controls that could enable ransomware affiliates.
- [ ] Validate social-media and OAuth account security for corporate email addresses potentially impacted by the Instagram leak and similar datasets.
- [ ] Review backup configurations, test restore procedures, and ensure at least one immutable/offline backup tier.

### ONGOING (Strategic)

- [ ] Integrate KEV monitoring and automated patch-prioritization workflows so exploited CVEs like CVE-2026-20805 and legacy HPE/Office flaws are remediated rapidly.
- [ ] Strengthen mobile and BYOD security through MDM enforcement, sideloading restrictions, and QR-security awareness programs.
- [ ] Expand threat-hunting playbooks around ransomware and APT tradecraft, including hypervisor-level monitoring and supply-chain/third-party risk visibility.
- [ ] Participate in community sharing of Sigma/YARA/Snort improvements and incorporate feedback to reduce false positives and improve coverage.

***

## 11. RESOURCES & REFERENCES

<table>
<thead>
<tr>
<th align="left">Category</th>
<th align="left">Resource / URL</th>
</tr>
</thead>
<tbody>
<tr>
<td data-label="Category:">Microsoft Patch Tuesday</td>
<td data-label="Resource / URL:"><a href="https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/" target="_blank">https://www.crowdstrike.com/en-us/blog/patch-tuesday-analysis-january-2026/</a></td>
</tr>
<tr>
<td data-label="Category:">Microsoft Patch Tuesday</td>
<td data-label="Resource / URL:"><a href="https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review" target="_blank">https://blog.qualys.com/vulnerabilities-threat-research/2026/01/13/microsoft-patch-tuesday-january-2026-security-update-review</a></td>
</tr>
<tr>
<td data-label="Category:">Microsoft Patch Tuesday</td>
<td data-label="Resource / URL:"><a href="https://www.tenable.com/blog/microsofts-january-2026-patch-tuesday-addresses-113-cves-cve-2026-20805" target="_blank">https://www.tenable.com/blog/microsofts-january-2026-patch-tuesday-addresses-113-cves-cve-2026-20805</a></td>
</tr>
<tr>
<td data-label="Category:">National Advisories</td>
<td data-label="Resource / URL:"><a href="https://www.cyber.gc.ca/en/alerts-advisories/microsoft-security-advisory-january-2026-monthly-rollup-av26-024" target="_blank">https://www.cyber.gc.ca/en/alerts-advisories/microsoft-security-advisory-january-2026-monthly-rollup-av26-024</a></td>
</tr>
<tr>
<td data-label="Category:">KEV & Infrastructure</td>
<td data-label="Resource / URL:"><a href="https://blog.rsisecurity.com/cisa-kev-latest-vulnerabilities-infrastructure-risk/" target="_blank">https://blog.rsisecurity.com/cisa-kev-latest-vulnerabilities-infrastructure-risk/</a></td>
</tr>
<tr>
<td data-label="Category:">DWM Zero-Day Analysis</td>
<td data-label="Resource / URL:"><a href="https://socprime.com/blog/cve-2026-20805-vulnerability/" target="_blank">https://socprime.com/blog/cve-2026-20805-vulnerability/</a></td>
</tr>
<tr>
<td data-label="Category:">Kimsuky / DocSwap</td>
<td data-label="Resource / URL:"><a href="https://www.enki.co.kr/en/media-center/blog/kimsuky-distributing-malicious-mobile-app-via-qr-code" target="_blank">https://www.enki.co.kr/en/media-center/blog/kimsuky-distributing-malicious-mobile-app-via-qr-code</a></td>
</tr>
<tr>
<td data-label="Category:">Kimsuky / DocSwap</td>
<td data-label="Resource / URL:"><a href="https://thehackernews.com/2025/12/kimsuky-spreads-docswap-android-malware.html" target="_blank">https://thehackernews.com/2025/12/kimsuky-spreads-docswap-android-malware.html</a></td>
</tr>
<tr>
<td data-label="Category:">FBI Quishing Advisory</td>
<td data-label="Resource / URL:"><a href="https://thehackernews.com/2026/01/fbi-warns-north-korean-hackers-using.html" target="_blank">https://thehackernews.com/2026/01/fbi-warns-north-korean-hackers-using.html</a></td>
</tr>
<tr>
<td data-label="Category:">ESXi Exploitation</td>
<td data-label="Resource / URL:"><a href="https://thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html" target="_blank">https://thehackernews.com/2026/01/chinese-linked-hackers-exploit-vmware.html</a></td>
</tr>
<tr>
<td data-label="Category:">BreachForums Leak</td>
<td data-label="Resource / URL:"><a href="https://www.rescana.com/post/breachforums-data-breach-exposes-324-000-user-records-after-mybb-misconfiguration-in-2026" target="_blank">https://www.rescana.com/post/breachforums-data-breach-exposes-324-000-user-records-after-mybb-misconfiguration-in-2026</a></td>
</tr>
<tr>
<td data-label="Category:">BreachForums Leak</td>
<td data-label="Resource / URL:"><a href="https://www.resecurity.com/blog/article/doomsday-for-cybercriminals-data-breach-of-major-dark-web-foru" target="_blank">https://www.resecurity.com/blog/article/doomsday-for-cybercriminals-data-breach-of-major-dark-web-foru</a></td>
</tr>
<tr>
<td data-label="Category:">Instagram 17.5M Leak</td>
<td data-label="Resource / URL:"><a href="https://brightdefense.com/resources/recent-data-breaches/" target="_blank">https://brightdefense.com/resources/recent-data-breaches/</a></td>
</tr>
<tr>
<td data-label="Category:">Vect Ransomware</td>
<td data-label="Resource / URL:"><a href="https://redpiranha.net/news/threat-intelligence-report-january-6-january-12-2026" target="_blank">https://redpiranha.net/news/threat-intelligence-report-january-6-january-12-2026</a></td>
</tr>
<tr>
<td data-label="Category:">Ransomware Landscape</td>
<td data-label="Resource / URL:"><a href="https://businessinsights.bitdefender.com/bitdefender-threat-debrief-january-2026" target="_blank">https://businessinsights.bitdefender.com/bitdefender-threat-debrief-january-2026</a></td>
</tr>
<tr>
<td data-label="Category:">Detection Rule Tools</td>
<td data-label="Resource / URL:"><a href="https://github.com/SigmaHQ/sigma" target="_blank">Sigma: https://github.com/SigmaHQ/sigma</a></td>
</tr>
<tr>
<td data-label="Category:">Detection Rule Tools</td>
<td data-label="Resource / URL:"><a href="https://github.com/SigmaHQ/pySigma" target="_blank">pySigma: https://github.com/SigmaHQ/pySigma</a></td>
</tr>
<tr>
<td data-label="Category:">Detection Rule Tools</td>
<td data-label="Resource / URL:"><a href="https://github.com/VirusTotal/yara" target="_blank">YARA: https://github.com/VirusTotal/yara</a></td>
</tr>
<tr>
<td data-label="Category:">Detection Rule Tools</td>
<td data-label="Resource / URL:"><a href="https://www.snort.org/downloads" target="_blank">Snort rules: https://www.snort.org/downloads</a></td>
</tr>
<tr>
<td data-label="Category:">Detection Rule Repos</td>
<td data-label="Resource / URL:"><a href="https://github.com/SigmaHQ/sigma/tree/master/rules" target="_blank">Sigma rules: https://github.com/SigmaHQ/sigma/tree/master/rules</a></td>
</tr>
<tr>
<td data-label="Category:">Detection Rule Repos</td>
<td data-label="Resource / URL:"><a href="https://github.com/Yara-Rules/rules" target="_blank">YARA rules: https://github.com/Yara-Rules/rules</a></td>
</tr>
<tr>
<td data-label="Category:">OSQuery Packs</td>
<td data-label="Resource / URL:"><a href="https://github.com/osquery/osquery/tree/master/packs" target="_blank">https://github.com/osquery/osquery/tree/master/packs</a></td>
</tr>
</tbody>
</table>

***

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

<p style="text-align: center; margin-bottom: 0;"><strong>Next Weekly Brief:</strong> Friday, January 23, 2026<br>❄</p>
