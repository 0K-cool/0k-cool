# 0K Blog - Changelog (December 10, 2025)

**Project:** 0k-cool Hugo Blog
**Domain:** https://0k.cool
**Deployment:** Cloudflare Pages
**Date:** December 10, 2025
**Author:** Vex 🦖⚡

---

## 📋 Summary

Complete setup and deployment of 0K Weekly Threat Intelligence Briefing blog from local development to production with custom domain, automated formatting workflow, and TL;DR feature.

---

## 🎯 Major Milestones

1. ✅ Fixed blog formatting and styling issues
2. ✅ Deployed to Cloudflare Pages
3. ✅ Configured custom domain (0k.cool)
4. ✅ Created automation skill for future briefs
5. ✅ Added TL;DR feature for mobile readers

---

## 📁 File Structure

```
/Users/kelvinlomboy/Projects/0k-cool/
├── content/
│   └── briefme/
│       ├── _index.md
│       ├── weekly-threat-intel-dec-2-9-2025.md (main report)
│       └── weekly-threat-intel-dec-2-9-2025-tldr.md (NEW - mobile version)
├── static/
│   └── images/
│       └── briefme/
│           └── react2shell-critical-alert.jpg (hero image)
├── layouts/
│   └── partials/
│       └── extra-head.html (custom CSS)
├── hugo.toml (menu configuration)
├── MENU-SECTIONS.md (documentation)
└── .gitignore

GitHub Repository: 0K-cool/0k-cool
Remote: https://github.com/0K-cool/0k-cool.git
```

---

## 🎨 1. Styling & Formatting Fixes

### A. Code Block Styling (`layouts/partials/extra-head.html`)

**Created:** `/Users/kelvinlomboy/Projects/0k-cool/layouts/partials/extra-head.html`

**Purpose:** Custom CSS for terminal-style code blocks and 0K branding

**Key Changes:**
- Old-school terminal aesthetic (sharp corners, no shadows)
- Flat design (no rounded borders, no box-shadow)
- Monospace font: Courier New, 16px
- Dark background: #1e1e1e
- Preserved Chroma syntax highlighting (Monokai theme)
- 0K avatar HUD color for cursor: #00e5ff
- Fixed task list checkboxes (removed bullets)
- ASCII art boxes: transparent background, monospace preserved

**CSS Sections:**
```css
/* 0K Custom Styles */
.logo__cursor { background: #00e5ff !important; }

/* Fix task list checkboxes */
.post-content ul li[class*="task-list"] { list-style: none !important; }

/* Terminal-style code blocks */
.highlight, .highlight pre {
  background-color: #1e1e1e !important;
  border: none !important;
  box-shadow: none !important;
}

/* ASCII art boxes */
.post-content > pre:not(.highlight pre) {
  background: transparent !important;
  border: none !important;
}
```

### B. Detection Rules Long Line Fixes

**File:** `content/briefme/weekly-threat-intel-dec-2-9-2025.md`

**Sigma Rules:**
- Used YAML folded block syntax (`>`) for long descriptions
- Used YAML folded block for multi-line conditions
- Target: ~70 characters per line

**Before:**
```yaml
description: Detects HTTP POST requests indicative of CVE-2025-55182 exploitation attempts against React Server Components via /api/* endpoints
```

**After:**
```yaml
description: >
  Detects HTTP POST requests indicative of CVE-2025-55182 exploitation
  attempts against React Server Components
```

**YARA Rules:**
- Used backslash continuation (`\`) for long lines
- Broke descriptions, references, and hex arrays
- Target: ~60 characters per line

**Before:**
```yara
description = "Detects Qilin/Qilin.B ransomware written in Rust with EDR evasion capabilities"
```

**After:**
```yara
description = "Detects Qilin/Qilin.B " \
              "ransomware written in Rust " \
              "with EDR evasion"
```

### C. ASCII Art Alignment

**File:** `content/briefme/weekly-threat-intel-dec-2-9-2025.md`

**MITRE ATT&CK Bars:**
- Abbreviated long technique names (e.g., "Priv Escalation" instead of "Privilege Escalation")
- Aligned all bars at same column position
- Ensured consistent spacing

**Box Headers:**
- Wrapped in `<pre>` tags (not code blocks)
- Transparent background (no dark background)
- Monospace font preserved

---

## 🧹 2. Content Cleanup

### A. Removed AI/Perplexity References

**File:** `content/briefme/weekly-threat-intel-dec-2-9-2025.md`

**Removed:**
- "perplexity" tag from frontmatter
- All mentions of "Perplexity AI" from content
- Direct AI tool attribution

**Kept:**
- AI security content (GitHub Copilot vulnerabilities, AI-powered development tools)

**File:** `content/briefme/_index.md`

**Before:**
```markdown
Threat intelligence briefs: curated daily/weekly summaries from Perplexity covering CVEs...
```

**After:**
```markdown
Threat intelligence briefs: curated daily/weekly summaries covering CVEs, threat actor activity, and security landscape updates.
```

### B. Source Citations Cleanup

**Removed bracketed reference numbers:**
- Pattern: `[3][4][8][76][81][85]`
- Kept source names, removed unlinked numbers

**Example:**
- Before: `The Hacker News, Unit 42, Wiz[3][4][8]`
- After: `The Hacker News, Unit 42, Wiz`

### C. Social Links Formatting

**File:** `content/briefme/weekly-threat-intel-dec-2-9-2025.md`

**Standardized format:**
```markdown
**Follow 0K:**
- Bluesky: [@kelvinlomboy.bsky.social](https://bsky.app/profile/kelvinlomboy.bsky.social)
- LinkedIn: [@kelvinlomboy](https://linkedin.com/in/kelvinlomboy)
- GitHub: [@0K-cool](https://github.com/0K-cool)
```

**Changed LinkedIn from:**
- Before: `[Kelvin Lomboy](https://linkedin.com/in/kelvinlomboy)`
- After: `[@kelvinlomboy](https://linkedin.com/in/kelvinlomboy)` (consistent @ format)

### D. Added Comprehensive Disclaimer

**File:** `content/briefme/weekly-threat-intel-dec-2-9-2025.md`

**Location:** After "Follow 0K" section

**Content:**
```markdown
---

**Disclaimer:**

**Threat Intelligence:** This report is based on open-source intelligence gathering and analysis current as of the reporting date. The threat landscape evolves rapidly, and information may become outdated. Organizations should conduct independent validation, correlate findings with internal telemetry, and consult additional authoritative sources before making security decisions. This report is for informational purposes only and is not a substitute for professional security services.

**Detection Rules:** All detection rules (Sigma, YARA, Snort/Suricata) and hunt queries are experimental and provided as starting points for threat detection. Organizations must validate all rules in test environments, assess false positive rates, and modify them to suit specific tools, environments, and operational requirements before production deployment.

0K assumes no liability for decisions made based on this report or the effectiveness and impacts of implementing these detection rules.
```

### E. Removed Redundant Metadata

**Removed from body:**
- "Report Generated" date (Hugo shows this automatically)
- "Next Report" date from body (kept in footer box only)

**Updated "Next Brief" date:**
- Changed to: December 12, 2025

---

## 🖼️ 3. Hero Image

**File:** `content/briefme/weekly-threat-intel-dec-2-9-2025.md`

**Added above Executive Summary:**
```markdown
<br>

![React2Shell CRITICAL Alert](/images/briefme/react2shell-critical-alert.jpg)

<br>
<br>

## Executive Summary
```

**Image specs:**
- Dark blue background
- "CRITICAL ALERT" header
- CVE-2025-55182 details
- CVSS 10.0 score
- Threat indicators
- 0K branding

**Location:** `/Users/kelvinlomboy/Projects/0k-cool/static/images/briefme/react2shell-critical-alert.jpg`

---

## 📱 4. TL;DR Feature (NEW)

**Created:** `/Users/kelvinlomboy/Projects/0k-cool/content/briefme/weekly-threat-intel-dec-2-9-2025-tldr.md`

**Purpose:** Mobile-optimized quick-read version (2-minute read)

**Frontmatter:**
```yaml
---
title: "TL;DR: Weekly Threat Intel | Dec 2-9, 2025"
date: 2025-12-02T00:01:00-04:00
draft: false
tags: ["threat-intel", "tldr", "quick-read"]
categories: ["briefme"]
description: "Quick 2-minute read: React2Shell CVSS 10.0, Qilin ransomware surge, China APT campaigns."
author: "0K (Kelvin)"
---
```

**Format:**
- ⏱️ 2-minute read indicator
- Link to full detailed version
- 🚨 Critical This Week (top 3 threats with CVSS scores)
- 📊 By The Numbers (key statistics)
- 🎯 Top MITRE ATT&CK Techniques (top 4 only)
- ✅ Action Items (immediate and weekly checklists)
- 🔗 Quick Links (full report, CISA KEV, patches)
- Social links (Bluesky, LinkedIn, GitHub)
- Simplified disclaimer

**Key Differences from Full Report:**
- ❌ NO social media posting content (private only)
- ✅ Emoji markers for visual scanning
- ✅ Condensed format for mobile
- ✅ Checklist-style action items
- ✅ Direct links to resources

**Link in Full Report:**
Added prominent link at top of full report:
```markdown
**⏱️ Short on time?** [Read the 2-minute TL;DR version →](../weekly-threat-intel-dec-2-9-2025-tldr/)
```

---

## 🗂️ 5. Menu Management

**File:** `hugo.toml`

**Purpose:** Hide empty menu sections

**Visible Section:**
```toml
[[menu.main]]
  identifier = "briefme"
  name = "briefme/"
  url = "/briefme/"
  weight = 1
```

**Hidden Sections (commented out):**
```toml
# [[menu.main]]
#   identifier = "showme"
#   name = "showme/"
#   url = "/showme/"
#   weight = 2

# [[menu.main]]
#   identifier = "freezeit"
#   name = "freezeit/"
#   url = "/freezeit/"
#   weight = 3

# ... (huntit, proveit, wtf)
```

**Documentation Created:** `/Users/kelvinlomboy/Projects/0k-cool/MENU-SECTIONS.md`

**Key Learning:**
- Hugo menu is **hardcoded in `hugo.toml`**, not auto-generated from content directories
- To hide a section: Comment out menu block in `hugo.toml`
- Moving directories or adding `draft: true` alone doesn't hide menu items

---

## 🚀 6. Deployment to Cloudflare Pages

### A. GitHub Repository Setup

**Created:** https://github.com/0K-cool/0k-cool

**Initial Commit:**
```
commit 4772041
Initial commit: 0K blog with threat intel briefing
```

**Files:**
- .gitignore (Hugo build artifacts: public/, resources/_gen/, .hugo_build.lock)
- All content, layouts, themes, config

### B. Cloudflare Pages Configuration

**Account:** Cloudflare (0K-cool)

**Project Setup:**
- Navigation: Compute & AI → Workers & Pages → Create application → Pages → Connect to Git
- Repository: 0K-cool/0k-cool (GitHub)
- Branch: main

**Build Settings:**
```
Framework preset: Hugo
Build command: hugo --gc --minify
Build output directory: /public
Environment variable: HUGO_VERSION = 0.152.2
```

**Deployment URL:** https://0k-cool.pages.dev

### C. Custom Domain Configuration

**Domain:** 0k.cool (purchased from Porkbun)

**DNS Transfer:**
1. Transferred nameservers from Porkbun to Cloudflare
2. Cloudflare nameservers:
   - alan.ns.cloudflare.com
   - wanda.ns.cloudflare.com

**Custom Domain Setup:**
1. Cloudflare Pages → 0k-cool → Custom domains
2. Added domain: 0k.cool (apex domain)
3. Cloudflare created CNAME: 0k-cool.pages.dev (with CNAME flattening)
4. SSL/TLS: Full (automatic HTTPS)

**DNS Issue & Fix:**
- **Problem:** Old Porkbun NS records conflicting with CNAME
- **Solution:** Deleted 4 NS records pointing to Porkbun nameservers:
  - salvador.porkbun.com
  - maceio.porkbun.com
  - fortaleza.porkbun.com
  - curitiba.porkbun.com
- **Result:** DNS propagated correctly, site went live

**Bot Management:**
- Enabled "AI Scrapers and Crawlers" to allow AI to scrape website

---

## 🧹 7. Post-Deployment Cleanup

### Removed Old Posts

**Deleted files:**
1. `weekly-threat-intel-2024-w50.md` (old post with draft: false)
2. `weekly-threat-intel-0001.md` (test post)
3. `weekly-threat-intel-dec-2-9-2025-tldr.md.bak` (backup file)
4. `temp.md` (temporary file)

**Commit:**
```
commit 5d9b6a8
chore: remove old posts and backup files
```

### Updated Commit Message

**Issue:** Commit message mentioned "Perplexity"

**Original commit:**
```
commit 2fd59d0
fix: remove Perplexity reference from briefme description
```

**Amended to:**
```
commit 2fd59d0
fix: update briefme section description
```

**Pushed with force:** Replaced commit history to remove Perplexity mention

---

## 🤖 8. Automation Skill Created

**File:** `/Users/kelvinlomboy/Personal_AI_Infrastructure/.claude/skills/weekly-brief-polish/skill.md`

**Purpose:** Automate revision workflow for future Weekly Threat Intelligence Briefings

**Workflow Steps:**
1. Generate Article Hero Image (using `art` skill)
2. **Generate TL;DR Version** (new)
   - Create `-tldr.md` file with same base name
   - Quick 2-minute read format
   - Top 3 threats, statistics, action items
   - Emoji markers for visual scanning
   - No social media content (private only)
3. Fix Long Lines in Code Blocks
   - Sigma rules: YAML folded blocks
   - YARA rules: Backslash continuation
   - KEY INSIGHT sections: Break paragraphs
4. ASCII Art Alignment
5. Remove AI/Research Tool References
6. Source Citations Cleanup
7. Social Links Formatting
8. Add Comprehensive Disclaimer
9. Remove Redundant Metadata
10. Code Block Styling Check
11. Final Checklist

**Usage:**
Drop a new Weekly Threat Intel markdown file and say:
- "Polish this weekly brief for publication"
- "Prepare this threat intel report"
- "Fix and format this weekly briefing"

**Updated Files:**
- `.claude/skills/weekly-brief-polish/skill.md` (added TL;DR generation as step 2)
- `.claude/skills/vex-core/skill.md` (added weekly-brief-polish to professional skills)
- `.claude/hooks/session-start.sh` (added emoji mapping: 📰)

---

## 📊 9. Git History

**Repository:** https://github.com/0K-cool/0k-cool

**Commit History:**
```
cbe8d9c feat: add TL;DR version of weekly threat intel
2fd59d0 fix: update briefme section description
5d9b6a8 chore: remove old posts and backup files
4772041 Initial commit: 0K blog with threat intel briefing
```

**Branch:** main

**Remote:** https://github.com/0K-cool/0k-cool.git

**Cloudflare Auto-Deploy:**
- Watches main branch
- Auto-rebuilds on push
- Deployment time: ~2-3 minutes

---

## 🎯 10. Final Checklist Completed

- [x] Hero image generated and placed
- [x] TL;DR version created with same base filename
- [x] All code blocks checked for long lines
- [x] Sigma rules use YAML folded blocks
- [x] YARA rules use backslash continuation
- [x] ASCII art alignment verified
- [x] AI tool references removed (kept AI security content)
- [x] Source citation numbers removed
- [x] Social links formatted with @ symbols
- [x] Comprehensive disclaimer added
- [x] Redundant metadata removed
- [x] "Next Brief" date updated (December 12, 2025)
- [x] draft: false in frontmatter
- [x] Deployed to Cloudflare Pages
- [x] Custom domain (0k.cool) configured
- [x] DNS propagated successfully
- [x] Blog is live and accessible

---

## 📝 Key Files & Locations

**Blog Project:**
```
/Users/kelvinlomboy/Projects/0k-cool/
├── content/briefme/weekly-threat-intel-dec-2-9-2025.md (main)
├── content/briefme/weekly-threat-intel-dec-2-9-2025-tldr.md (NEW)
├── layouts/partials/extra-head.html (CSS)
├── static/images/briefme/react2shell-critical-alert.jpg (hero image)
├── hugo.toml (menu config)
└── MENU-SECTIONS.md (documentation)
```

**Automation Skill:**
```
/Users/kelvinlomboy/Personal_AI_Infrastructure/
└── .claude/skills/weekly-brief-polish/skill.md
```

**Documentation:**
```
/Users/kelvinlomboy/Projects/0k-cool/
├── CHANGELOG-DEC-10-2025.md (this file)
└── MENU-SECTIONS.md (menu management guide)
```

---

## 🌐 Live Deployment

**Production URL:** https://0k.cool
**Staging URL:** https://0k-cool.pages.dev
**GitHub:** https://github.com/0K-cool/0k-cool
**Hosting:** Cloudflare Pages
**DNS:** Cloudflare DNS
**SSL:** Full (automatic HTTPS)

**Build Info:**
- Hugo Version: 0.152.2 extended
- Theme: Hello Friend NG (dark theme)
- Build Time: ~30 seconds
- Deploy Time: ~2-3 minutes

---

## 🔄 Future Workflow

**For next Weekly Threat Intel Brief:**

1. Drop new markdown file (e.g., `weekly-threat-intel-dec-10-17-2025.md`)
2. Say: "Polish this weekly brief for publication"
3. Vex will:
   - Generate hero image
   - Create TL;DR version
   - Fix all formatting
   - Add disclaimer
   - Clean references
   - Update social links
4. Commit and push to GitHub
5. Cloudflare Pages auto-rebuilds
6. Live in 2-3 minutes

**Automation Goal:** Transform raw threat intel into polished, publication-ready 0K-branded content in <5 minutes.

---

## 📚 Lessons Learned

1. **Hugo Menu Management:**
   - Menu is hardcoded in `hugo.toml`, not auto-generated
   - Must comment out menu blocks to hide sections

2. **Cloudflare Pages Navigation:**
   - New UI location: Compute & AI → Workers & Pages
   - Environment variables required: HUGO_VERSION

3. **DNS Conflicts:**
   - Old nameserver records can conflict with CNAME
   - Must delete conflicting NS records for proper propagation

4. **Code Block Styling:**
   - Chroma generates complex table structure for syntax highlighting
   - Must target all nested elements to remove borders/shadows
   - Use `<pre>` tags for ASCII art (not code blocks)

5. **Git Commit Hygiene:**
   - Can amend commit messages to remove unwanted references
   - Force push replaces remote history (use with caution)

6. **Blog Publishing Best Practices:**
   - Remove ALL AI tool references from content and commits
   - Comprehensive disclaimers protect against liability
   - TL;DR versions increase accessibility

---

**Changelog Complete:** December 10, 2025 at 12:15 PM AST
**Status:** ✅ Ready for future reference
**Next Session:** Use this document to recall all changes and continue from here

🦖⚡ Vex - Personal AI Infrastructure
