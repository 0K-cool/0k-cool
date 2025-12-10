---
title: "TL;DR: Weekly Threat Intel | Dec 2-9, 2025"
date: 2025-12-02T00:01:00-04:00
draft: false
tags: ["threat-intel", "tldr", "quick-read"]
categories: ["briefme"]
description: "Quick 2-minute read: React2Shell CVSS 10.0, Qilin ransomware surge, China APT campaigns. Essential threat intel at a glance."
author: "0K (Kelvin)"
---

**⏱️ 2-minute read** | [📖 Full detailed version →](../weekly-threat-intel-dec-2-9-2025/)

---

## 🚨 Critical This Week

**CVE-2025-55182 (React2Shell)** — CVSS 10.0
Unauthenticated RCE in React Server Components. Proof-of-concept exploit published. **Patch immediately** if using Next.js, Remix, or similar frameworks.

**Qilin Ransomware Surge**
45% increase in attacks. New Rust-based variant evades EDR. Healthcare, manufacturing, and critical infrastructure targeted.

**China APT Campaigns (APT36/APT41)**
Government and defense sectors compromised via Linux ELF backdoors and supply chain attacks.

---

## 📊 By The Numbers

- **57 Microsoft patches** (4 critical zero-days)
- **287 ransomware incidents** (up 22% from last week)
- **15 new CISA KEV entries**
- **47 reports** analyzed for this brief

---

## 🎯 Top MITRE ATT&CK Techniques

1. **Execution (T1059)** — Command/script interpreter abuse (PowerShell, shells)
2. **Defense Evasion (T1070)** — EDR bypass, log tampering
3. **Persistence (T1053)** — Scheduled tasks, cron jobs
4. **Command & Control (T1071)** — Application layer protocols

---

## ✅ Action Items

**Immediate:**
- [ ] Patch React Server Components (CVE-2025-55182)
- [ ] Review Microsoft Dec 2025 Patch Tuesday updates
- [ ] Audit EDR coverage against Qilin ransomware indicators

**This Week:**
- [ ] Deploy detection rules for APT36 Linux backdoors
- [ ] Test backup recovery procedures (ransomware surge)
- [ ] Review exposed cloud services (GitHub Actions, AWS IMDSv1)

---

## 🔗 Quick Links

- [Full Threat Intel Report →](../weekly-threat-intel-dec-2-9-2025/) (Detailed analysis, detection rules, IOCs)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft December Patch Tuesday](https://msrc.microsoft.com/update-guide/)

---

**Follow 0K:**
- Bluesky: [@kelvinlomboy.bsky.social](https://bsky.app/profile/kelvinlomboy.bsky.social)
- LinkedIn: [@kelvinlomboy](https://linkedin.com/in/kelvinlomboy)
- GitHub: [@0K-cool](https://github.com/0K-cool)

---

**Disclaimer:** This report is for informational purposes only. Organizations should validate all information and test detection rules in non-production environments before deployment. 0K assumes no liability for decisions made based on this report.
