#!/usr/bin/env python3
"""Combine all Meridian Trust lab docs into one printable PDF handout.

Output: docs/Meridian-Trust-Lab-Handbook.pdf
Order:  Cover -> Contents -> Setup -> Implementation Plan -> Findings -> Lab Manual
"""
import re
from pathlib import Path
import markdown
from weasyprint import HTML

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
OUT = DOCS / "Meridian-Trust-Lab-Handbook.pdf"

# (part number, title, filename) in reading order.
PARTS = [
    ("1", "Setup &amp; Safety", "SETUP.md"),
    ("2", "Implementation Plan &amp; Vulnerability Catalogue", "IMPLEMENTATION-PLAN.md"),
    ("3", "Findings &amp; Exploitation Writeup", "FINDINGS.md"),
    ("4", "Instructor Lab Manual &amp; Student Checklist", "LAB-MANUAL.md"),
]

MD_EXT = ["tables", "fenced_code", "toc", "sane_lists", "attr_list"]


def render_doc(fname):
    text = (DOCS / fname).read_text(encoding="utf-8")
    # Strip the doc's own leading H1 (the divider page shows the part title).
    text = re.sub(r"^#\s.*\n", "", text, count=1)
    return markdown.markdown(text, extensions=MD_EXT)


CSS = """
@page {
  size: A4;
  margin: 18mm 16mm 20mm 16mm;
  @top-right { content: "Meridian Trust — Security Training Lab"; font-size: 8pt; color: #888; }
  @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #888; }
  @bottom-left { content: "INTERNAL — TEACHING LAB"; font-size: 8pt; color: #b00020; }
}
@page :first { @top-right { content: ""; } @bottom-left { content: ""; } @bottom-center { content: ""; } }

body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 9.5pt; line-height: 1.45; color: #1a1a1a; }

.cover { text-align: center; page-break-after: always; padding-top: 55mm; }
.cover .brandmark { font-size: 12pt; letter-spacing: 4px; color: #c9a227; font-weight: bold; }
.cover h1 { font-size: 32pt; color: #0a2540; margin: 4mm 0 6mm 0; border: 0; }
.cover .sub { font-size: 13pt; color: #444; margin-bottom: 18mm; }
.cover .warn { display: inline-block; background: #b00020; color: #fff; font-weight: bold;
  padding: 6mm 10mm; border-radius: 4px; font-size: 11pt; }
.cover .meta { margin-top: 22mm; font-size: 9pt; color: #666; }

.toc { page-break-after: always; padding-top: 10mm; }
.toc h2 { font-size: 18pt; color: #0a2540; border-bottom: 2px solid #0a2540; padding-bottom: 2mm; }
.toc ol { list-style: none; padding: 0; font-size: 12pt; }
.toc li { padding: 5mm 0; border-bottom: 1px dotted #ccc; color: #0a2540; }
.toc li .n { display: inline-block; width: 12mm; color: #c9a227; font-weight: bold; }

.divider { page-break-before: always; page-break-after: always; padding-top: 90mm; text-align: center; }
.divider .part { font-size: 12pt; letter-spacing: 3px; color: #c9a227; font-weight: bold; }
.divider h1 { font-size: 26pt; color: #0a2540; border: 0; margin: 4mm auto 0; max-width: 150mm;
  page-break-before: auto; }

h1 { font-size: 17pt; color: #0d3b66; border-bottom: 2px solid #0d3b66; padding-bottom: 2mm;
  margin-top: 10mm; page-break-after: avoid; page-break-before: always; }
.section h1:first-of-type { page-break-before: avoid; }
h2 { font-size: 13pt; color: #0d3b66; margin-top: 7mm; page-break-after: avoid; }
h3 { font-size: 11pt; color: #b00020; margin-top: 5mm; page-break-after: avoid; }
h1 + p, h2 + p, h3 + p { page-break-before: avoid; }
p, li { orphans: 3; widows: 3; }

code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt;
  background: #f0f2f5; padding: 0.5mm 1mm; border-radius: 2px; color: #b00020; }
pre { background: #1e2733; color: #e6e6e6; padding: 3mm; border-radius: 4px; font-size: 8pt;
  line-height: 1.35; white-space: pre-wrap; word-wrap: break-word; page-break-inside: avoid; }
pre code { background: transparent; color: #e6e6e6; padding: 0; }

table { border-collapse: collapse; width: 100%; margin: 3mm 0; font-size: 8.5pt; page-break-inside: avoid; }
th, td { border: 1px solid #ccc; padding: 1.5mm 2mm; text-align: left; vertical-align: top; }
th { background: #0d3b66; color: #fff; }
tr:nth-child(even) td { background: #f6f8fa; }

a { color: #0d3b66; text-decoration: none; }
hr { border: 0; border-top: 1px solid #ddd; margin: 6mm 0; }
strong { color: #111; }
"""

COVER = """
<div class="cover">
  <div class="brandmark">MERIDIAN TRUST</div>
  <h1>Web Security Training Handbook</h1>
  <div class="sub">OWASP Top 10 Penetration-Testing Lab<br>
    Complete edition: Setup · Catalogue · Exploitation · Lab Manual<br>
    <span style="font-size:9pt;color:#888">Security-training build · internal codename &quot;VulnBank&quot;</span></div>
  <div class="warn">⚠ INTENTIONALLY VULNERABLE — TEACHING USE ONLY — DO NOT DEPLOY ⚠</div>
  <div class="meta">Instructor edition · Burp Suite / OWASP ZAP steps · ~78 verified findings<br>
    Confidential training material</div>
</div>
"""

toc_items = "\n".join(
    f'<li><span class="n">Part {n}</span> {title}</li>' for n, title, _ in PARTS
)
TOC = f'<div class="toc"><h2>Contents</h2><ol>{toc_items}</ol></div>'

sections = []
for n, title, fname in PARTS:
    divider = f'<div class="divider"><div class="part">PART {n}</div><h1>{title}</h1></div>'
    body = f'<div class="section">{render_doc(fname)}</div>'
    sections.append(divider + body)

full_html = (
    "<html><head><meta charset='utf-8'><style>" + CSS + "</style></head><body>"
    + COVER + TOC + "".join(sections) + "</body></html>"
)
HTML(string=full_html, base_url=str(ROOT)).write_pdf(str(OUT))
print(f"wrote {OUT}")
