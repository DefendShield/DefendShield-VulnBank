#!/usr/bin/env python3
"""Build the STUDENT edition handbook — objectives + worksheet, with all
payloads / exploitation steps / results / fixes redacted.

Output: docs/Meridian-Trust-Lab-Handbook-STUDENT.pdf
Derived from the same markdown so it stays in sync with the instructor edition.
"""
import re
from pathlib import Path
import markdown
from weasyprint import HTML

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "Meridian-Trust-Lab-Handbook-STUDENT.pdf"
MD_EXT = ["tables", "fenced_code", "sane_lists", "attr_list"]

setup_md = (DOCS / "SETUP.md").read_text(encoding="utf-8")
findings_md = (DOCS / "FINDINGS.md").read_text(encoding="utf-8")
manual_md = (DOCS / "LAB-MANUAL.md").read_text(encoding="utf-8")


def md(text):
    return markdown.markdown(text, extensions=MD_EXT)


# --- Part 1: Setup (strip leading H1) -------------------------------------
setup_body = md(re.sub(r"^#\s.*\n", "", setup_md, count=1))

# --- Part 2: Proxy-setup / methodology (verbatim, non-spoiler) ------------
m0 = findings_md.index("## 0. Proxy setup")
mA = findings_md.index("## A01")
proxy_section = findings_md[m0:mA].rstrip().rstrip("-").rstrip()
proxy_body = md(proxy_section.replace("## 0. Proxy setup (do this once)", "", 1))

# --- Part 3: Challenge objectives (redacted) ------------------------------
# Keep only the finding heading + where-to-look; drop payloads/steps/fixes.
region = findings_md[findings_md.index("## A01"): findings_md.index("## Coverage note")]
group = None
groups = []  # list of (group_name, [ (vbid, objective, where) ])
for raw in region.splitlines():
    line = raw.rstrip()
    if line.startswith("## "):
        group = re.sub(r"[*`]", "", line[3:]).strip()
        groups.append((group, []))
    elif line.startswith("### ") and groups:
        h = re.sub(r"[*`]", "", line[4:]).strip()
        mid = re.match(r"(VB-\d+)\s+(.*)", h)
        vbid, obj = (mid.group(1), mid.group(2)) if mid else ("", h)
        groups[-1][1].append([vbid, obj, ""])
    elif line.startswith("- **Location:**") and groups and groups[-1][1]:
        span = re.search(r"`([^`]+)`", line)
        if span and not groups[-1][1][-1][2]:
            groups[-1][1][-1][2] = span.group(1)

rows_html = []
for gname, items in groups:
    if not items:
        continue
    rows = "".join(
        f"<tr><td>{vbid}</td><td>{obj}</td><td><code>{where or '&mdash; discover &mdash;'}</code></td>"
        f"<td style='width:16mm'>&#9744;</td></tr>"
        for vbid, obj, where in items
    )
    rows_html.append(
        f"<h2>{gname}</h2><table><thead><tr><th>ID</th><th>Objective — find &amp; exploit</th>"
        f"<th>Where to look</th><th>Done</th></tr></thead><tbody>{rows}</tbody></table>"
    )
challenges_body = "".join(rows_html)

# --- Part 4: Worksheet + rubric from the lab manual -----------------------
ws_start = manual_md.index("## Student worksheet")
manual_body = md(manual_md[ws_start:])

CSS = """
@page { size: A4; margin: 18mm 16mm 20mm 16mm;
  @top-right { content: "Meridian Trust — Student Lab Handbook"; font-size: 8pt; color: #888; }
  @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #888; }
  @bottom-left { content: "STUDENT EDITION"; font-size: 8pt; color: #127a63; } }
@page :first { @top-right { content: ""; } @bottom-left { content: ""; } @bottom-center { content: ""; } }
body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 9.5pt; line-height: 1.45; color: #1a1a1a; }
.cover { text-align: center; page-break-after: always; padding-top: 55mm; }
.cover .brandmark { font-size: 12pt; letter-spacing: 4px; color: #c9a227; font-weight: bold; }
.cover h1 { font-size: 30pt; color: #0a2540; margin: 4mm 0 3mm 0; border: 0; }
.cover .edition { display:inline-block; background:#127a63; color:#fff; font-weight:bold;
  padding:3mm 8mm; border-radius:20px; font-size:12pt; letter-spacing:2px; margin-bottom:16mm; }
.cover .sub { font-size: 12pt; color: #444; margin-bottom: 16mm; }
.cover .warn { display:inline-block; background:#b00020; color:#fff; font-weight:bold;
  padding:5mm 9mm; border-radius:4px; font-size:10.5pt; }
.cover .meta { margin-top: 18mm; font-size: 9pt; color: #666; }
.toc { page-break-after: always; padding-top: 10mm; }
.toc h2 { font-size:18pt; color:#0a2540; border-bottom:2px solid #0a2540; padding-bottom:2mm; }
.toc ol { list-style:none; padding:0; font-size:12pt; }
.toc li { padding:5mm 0; border-bottom:1px dotted #ccc; color:#0a2540; }
.toc li .n { display:inline-block; width:12mm; color:#c9a227; font-weight:bold; }
.divider { page-break-before: always; page-break-after: always; padding-top: 90mm; text-align: center; }
.divider .part { font-size:12pt; letter-spacing:3px; color:#c9a227; font-weight:bold; }
.divider h1 { font-size:26pt; color:#0a2540; border:0; margin:4mm auto 0; max-width:150mm; page-break-before:auto; }
.note { background:#e7f6f0; border:1px solid #c6eadd; color:#0f6a56; padding:4mm; border-radius:4px; margin:4mm 0; }
h1 { font-size:17pt; color:#0d3b66; border-bottom:2px solid #0d3b66; padding-bottom:2mm; margin-top:10mm;
  page-break-after:avoid; page-break-before:always; }
.section h1:first-of-type { page-break-before: avoid; }
h2 { font-size:13pt; color:#0d3b66; margin-top:7mm; page-break-after:avoid; }
h3 { font-size:11pt; color:#127a63; margin-top:5mm; page-break-after:avoid; }
code { font-family:"DejaVu Sans Mono", monospace; font-size:8.5pt; background:#f0f2f5;
  padding:0.5mm 1mm; border-radius:2px; color:#0a2540; }
pre { background:#1e2733; color:#e6e6e6; padding:3mm; border-radius:4px; font-size:8pt;
  white-space:pre-wrap; word-wrap:break-word; page-break-inside:avoid; }
table { border-collapse:collapse; width:100%; margin:3mm 0; font-size:8.5pt; page-break-inside:avoid; }
th, td { border:1px solid #ccc; padding:1.6mm 2mm; text-align:left; vertical-align:top; }
th { background:#0d3b66; color:#fff; }
tr:nth-child(even) td { background:#f6f8fa; }
a { color:#0d3b66; text-decoration:none; } hr { border:0; border-top:1px solid #ddd; margin:6mm 0; }
"""

COVER = """
<div class="cover">
  <div class="brandmark">MERIDIAN TRUST</div>
  <h1>Web Security Training Handbook</h1>
  <div class="edition">STUDENT EDITION</div>
  <div class="sub">OWASP Top 10 Penetration-Testing Lab<br>
    Setup · Testing Methodology · Challenges · Worksheet</div>
  <div class="warn">⚠ INTENTIONALLY VULNERABLE — TEACHING USE ONLY — DO NOT DEPLOY ⚠</div>
  <div class="meta">Discover and exploit each objective yourself.<br>
    Payloads, exploitation steps, and fixes are withheld — ask your instructor for the solution edition.</div>
</div>
"""

TOC = """
<div class="toc"><h2>Contents</h2><ol>
  <li><span class="n">Part 1</span> Setup &amp; Safety</li>
  <li><span class="n">Part 2</span> Testing Methodology &amp; Proxy Setup</li>
  <li><span class="n">Part 3</span> Challenge Objectives (find &amp; exploit)</li>
  <li><span class="n">Part 4</span> Worksheet &amp; Grading</li>
</ol></div>
"""

REDACT_NOTE = """
<div class="note"><b>How to use this edition.</b> Each objective names a vulnerability class and where to
start looking. The <i>how</i> — payloads, exploitation steps, and remediation — is intentionally omitted.
Use your proxy (Burp Suite / OWASP ZAP), test methodically, and record your evidence in the worksheet.</div>
"""


def part(n, title, body):
    return (f'<div class="divider"><div class="part">PART {n}</div><h1>{title}</h1></div>'
            f'<div class="section">{body}</div>')


full_html = (
    "<html><head><meta charset='utf-8'><style>" + CSS + "</style></head><body>"
    + COVER + TOC
    + part("1", "Setup &amp; Safety", setup_body)
    + part("2", "Testing Methodology &amp; Proxy Setup", proxy_body)
    + part("3", "Challenge Objectives", REDACT_NOTE + challenges_body)
    + part("4", "Worksheet &amp; Grading", manual_body)
    + "</body></html>"
)
HTML(string=full_html, base_url=str(ROOT)).write_pdf(str(OUT))
print(f"wrote {OUT}")
