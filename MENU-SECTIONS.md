# Hugo Menu Section Management

## How to Hide/Show Menu Sections

The navigation menu in your Hugo blog is **hardcoded in `hugo.toml`**, not auto-generated from content directories.

### To Hide a Section from Menu

Edit `hugo.toml` and **comment out** the menu block:

```toml
# [[menu.main]]
#   identifier = "huntit"
#   name = "huntit/"
#   url = "/huntit/"
#   weight = 4
```

The content directory can stay in `content/huntit/` - it just won't appear in navigation.

### To Show a Section in Menu

Edit `hugo.toml` and **uncomment** the menu block:

```toml
[[menu.main]]
  identifier = "huntit"
  name = "huntit/"
  url = "/huntit/"
  weight = 4
```

Adjust the `weight` value to control menu order (lower numbers appear first).

### Current Setup (Dec 2025)

**Visible:**
- `briefme/` (weight: 1) - Weekly Threat Intelligence Briefings

**Hidden (but content exists):**
- `showme/` - Tutorials and walkthroughs
- `freezeit/` - Incident response writeups
- `proveit/` - Lab experiments and validation
- `huntit/` - Threat hunting content
- `wtf/` - Deep dives into weird findings

All hidden sections have `draft: true` in their `_index.md` files as an extra precaution.

### Adding New Content to Hidden Sections

1. Uncomment menu block in `hugo.toml`
2. Remove `draft: true` from `content/SECTION/_index.md`
3. Hugo will rebuild and show the section

---

**Remember:** Moving directories or adding `draft: true` alone doesn't hide menu items. You MUST edit `hugo.toml`.
