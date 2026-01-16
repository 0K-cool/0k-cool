---
title: "Why Detection Has Failed | And What CISOs Can Actually Do About It"
date: 2026-01-17T08:00:00-04:00
draft: true
tags: ["detection", "CISO", "SOC", "MITRE ATT&CK", "BAS", "security metrics"]
categories: ["wtf"]
description: "194 days to detect a breach. 76% of SIEM detections miss their claimed techniques. We've been measuring the wrong things. Here's how to fix it."
author: "0K (Kelvin)"
image: "/images/wtf/why-detection-has-failed-hero.jpg"
---

Last week I came across a presentation that stopped me in my tracks. Caleb Sima, Chair of the CSA AI Safety Initiative, gave a talk to the Bay Area CISO Group called "Why Detection Has Failed." And honestly? It put into words something I've been dancing around with clients for years.

Here's the uncomfortable truth: **We're spending billions on security products, and the average breach still takes 194 days to detect.**

Let that sink in. Half a year of attackers living in your network before anyone notices.

## The Question Nobody Wants to Answer

In my vCISO work, I've sat in plenty of boardrooms watching security leaders present impressive dashboards. Alert volumes trending down. MTTD improving. MTTR looking good. Green lights across the board.

Then I ask one question that usually gets an awkward silence:

> "If an attacker uses technique X against us right now, what's the probability we actually catch it?"

Most can't answer. Not because they're bad at their jobs - they're usually excellent. It's because the entire industry has been measuring the wrong things.

## The Coverage Lie

Here's where it gets ugly. Caleb's research found that **76% of SIEM detections miss the techniques they claim to cover.**

Read that again. Three-quarters of your detection rules don't actually detect what they're supposed to detect.

How does this happen? Pretty easily, actually:

- Vendor ships default rules claiming ATT&CK coverage
- Security team deploys them, checks the compliance box
- Nobody validates if the rules actually fire on real attacks
- Dashboard shows "90% ATT&CK coverage"
- Attacker uses covered technique, walks right through

It's Goodhart's Law in action: "When a measure becomes a target, it ceases to be a good measure." We optimized for coverage percentages instead of actual detection capability.

## Vanity Metrics vs. Reality

Let me break down the metrics problem:

**What we measure (vanity metrics):**
- Alert volume (more alerts = better security, right?)
- MTTD (but only for incidents we detected)
- MTTR (for the same detected incidents)
- ATT&CK coverage % (based on unvalidated claims)

**What we should measure (efficacy metrics):**
- Validated detection rate (actual attacks caught)
- Detection Quality Index (true positives vs. all outcomes)
- Probability of detection per technique
- Automation ratio for response

The difference? Vanity metrics can be gamed. Efficacy metrics require proof.

## So What Actually Works?

Alright, enough doom and gloom. Let's talk solutions. After diving deep into the research - Gartner, SANS, MITRE, IBM's breach reports - here's what the data actually supports.

### 1. Breach and Attack Simulation (BAS)

This is the game-changer, in my book. BAS platforms like Cymulate, AttackIQ, or Picus continuously simulate real attacks against your environment and validate whether your detections actually fire.

The numbers are compelling:
- Organizations catch **75% of attacks missed** by out-of-the-box EDR/SIEM
- **37% reduction in false positives**
- **68% improvement in response times** when integrated with SOAR

For smaller budgets, Atomic Red Team and MITRE Caldera are free and get you started.

### 2. Purple Teaming (Actually Do It)

Here's a stat that blew my mind: organizations with collaborative purple teams report **88% effectiveness against ransomware**. Siloed red/blue programs? Only 52%.

The difference is the feedback loop. Red team runs technique, blue team sees (or doesn't see) the alert, they fix it together, rinse and repeat. Every exercise makes your detections stronger.

Tools like VECTR help track this systematically. Schedule monthly exercises, focus on your actual threat profile, document everything.

### 3. Detection as Code

Stop treating detection rules like sacred artifacts. They're code. Treat them like code:

- Version control (Git)
- Pull requests for changes
- Automated testing before deployment
- CI/CD pipeline to production

And for the love of all things holy, use Sigma rules. It's a universal detection format with 3,000+ community rules. Write once, translate to Splunk, Elastic, Sentinel, whatever. Your detection logic shouldn't be locked into one vendor.

### 4. CTEM Framework

Gartner's Continuous Threat Exposure Management framework is worth paying attention to. Their prediction: organizations adopting CTEM will see a **two-thirds reduction in breaches by 2026**.

The key insight? Stop treating vulnerabilities as isolated issues. Continuously validate your entire attack surface with real adversarial pressure. If you can't prove a control works, assume it doesn't.

## The Metrics That Actually Matter

Here's my recommended dashboard for CISOs who want to measure reality:

| Metric | Target | Why It Matters |
|--------|--------|----------------|
| Detection Quality Index (DQI) | ≥85% | True positives / (TP + FP + Missed) |
| Validated Detection Rate | ≥90% | BAS scenarios actually detected |
| ATT&CK Coverage (Validated) | ≥80% | Only count what's been tested |
| Automation Ratio | ≥60% | Automated responses / total responses |

Notice what's missing? Alert volume. Raw MTTD. Compliance checkboxes. Those are activity metrics, not efficacy metrics.

## The IBM Reality Check

The 2025 IBM Cost of Data Breach Report has some interesting data points:

- Global average breach lifecycle: **241 days** (improved from 277 in 2024)
- Organizations using AI/automation: **161 days** (80-day improvement)
- Cost per breach: **$4.88 million** average
- Healthcare: **$10.93 million** per breach

That 80-day detection improvement from AI and automation? That's real money. Every day of earlier detection saves roughly $18,750 in breach costs.

## What I Tell My Clients

When I'm doing vCISO work, here's the conversation I have:

**First 30 days:**
- Map current detections to MITRE ATT&CK
- Deploy Atomic Red Team, test top 20 techniques
- Document what you actually detect vs. what you think you detect

**Next 60 days:**
- Deploy BAS platform (or at minimum, schedule monthly purple team exercises)
- Move detection rules to Git
- Import Sigma rules for your threat profile

**Ongoing:**
- Weekly BAS validation runs
- Monthly purple team exercises
- Quarterly detection coverage reviews
- Board reporting on efficacy metrics, not activity metrics

Is it more work than checking compliance boxes? Yes. Does it actually improve your security posture? Also yes.

## The Bottom Line

Detection has failed because we measured activity instead of efficacy. We counted alerts instead of validating detections. We trusted vendor claims instead of testing them.

The fix isn't buying more tools. It's asking the hard question: **"If this technique is used against us, what's the probability we catch it?"**

If you can't answer that question with data, you're flying blind. And 194 days is a long time to have someone in your network.

---

**What's your detection validation strategy? Hit me up on LinkedIn or Bluesky - I'm genuinely curious how others are tackling this.**

---

**Follow 0K:**
- Bluesky: [@kelvinlomboy.bsky.social](https://bsky.app/profile/kelvinlomboy.bsky.social)
- LinkedIn: [@kelvinlomboy](https://linkedin.com/in/kelvinlomboy)
- GitHub: [@0K-cool](https://github.com/0K-cool)

---

**Disclaimer:** This article represents my professional opinion based on industry research and consulting experience. Your mileage may vary depending on your organization's specific threat landscape, tooling, and maturity level. The tools and vendors mentioned are examples - always evaluate against your own requirements.

---

**Sources:**
- Caleb Sima, ["Why Detection Has Failed"](https://www.linkedin.com/posts/calebsima_why-detection-has-failed-activity-7418019184703352832-D458) - Bay Area CISO Group presentation
- [IBM Cost of Data Breach Report 2025](https://www.ibm.com/reports/data-breach)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Gartner CTEM Research](https://www.gartner.com/)
- [SANS SOC Performance Research](https://expel.com/sans-institute-operational-security-maturity/)
