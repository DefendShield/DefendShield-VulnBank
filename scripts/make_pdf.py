#!/usr/bin/env python3
"""Render docs/FINDINGS.md to a printable PDF (docs/VulnBank-FINDINGS.pdf)."""
import re
from pathlib import Path
import markdown
from weasyprint import HTML

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "FINDINGS.md"
OUT = ROOT / "docs" / "Meridian-Trust-FINDINGS.pdf"

md_text = SRC.read_text(encoding="utf-8")

# Drop the leading H1 (we render our own cover title) to avoid duplication.
md_text = re.sub(r"^#\s.*Findings.*\n", "", md_text, count=1)

html_body = markdown.markdown(
    md_text,
    extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list"],
)

CSS = """
@page {
  size: A4;
  margin: 18mm 16mm 20mm 16mm;
  @top-right { content: "Meridian Trust — Exploitation Findings"; font-size: 8pt; color: #888; }
  @bottom-center { content: "Page " counter(page) " of " counter(pages); font-size: 8pt; color: #888; }
  @bottom-left { content: "INTERNAL — TEACHING LAB"; font-size: 8pt; color: #b00020; }
}
@page :first { @top-right { content: ""; } @bottom-left { content: ""; } @bottom-center { content: ""; } }

body { font-family: "DejaVu Sans", Arial, sans-serif; font-size: 9.5pt; line-height: 1.45; color: #1a1a1a; }

/* Cover */
.cover { text-align: center; page-break-after: always; padding-top: 60mm; }
.cover h1 { font-size: 30pt; color: #0d3b66; margin: 0 0 6mm 0; border: 0; }
.cover .sub { font-size: 13pt; color: #444; margin-bottom: 20mm; }
.cover .warn { display: inline-block; background: #b00020; color: #fff; font-weight: bold;
  padding: 6mm 10mm; border-radius: 4px; font-size: 11pt; }
.cover .meta { margin-top: 24mm; font-size: 9pt; color: #666; }

h1 { font-size: 17pt; color: #0d3b66; border-bottom: 2px solid #0d3b66; padding-bottom: 2mm;
  margin-top: 10mm; page-break-after: avoid; page-break-before: always; }
h2 { font-size: 13pt; color: #0d3b66; margin-top: 7mm; page-break-after: avoid; }
h3 { font-size: 11pt; color: #b00020; margin-top: 5mm; page-break-after: avoid; }
h1 + p, h2 + p, h3 + p { page-break-before: avoid; }

p, li { orphans: 3; widows: 3; }

code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt;
  background: #f0f2f5; padding: 0.5mm 1mm; border-radius: 2px; color: #b00020; }
pre { background: #1e2733; color: #e6e6e6; padding: 3mm; border-radius: 4px; font-size: 8pt;
  line-height: 1.35; white-space: pre-wrap; word-wrap: break-word; page-break-inside: avoid; }
pre code { background: transparent; color: #e6e6e6; padding: 0; }

table { border-collapse: collapse; width: 100%; margin: 3mm 0; font-size: 8.5pt;
  page-break-inside: avoid; }
th, td { border: 1px solid #ccc; padding: 1.5mm 2mm; text-align: left; vertical-align: top; }
th { background: #0d3b66; color: #fff; }
tr:nth-child(even) td { background: #f6f8fa; }

a { color: #0d3b66; text-decoration: none; }
hr { border: 0; border-top: 1px solid #ddd; margin: 6mm 0; }
strong { color: #111; }
"""

COVER = """
<div class="cover">
  <h1>Meridian Trust</h1>
  <div class="sub">Exploitation Findings &amp; Proxy-Tool Walkthrough<br>OWASP Top 10 Web Pentesting Lab<br><span style="font-size:9pt;color:#888">Security-training build · internal codename "VulnBank"</span></div>
  <div class="warn">⚠ INTENTIONALLY VULNERABLE — TEACHING USE ONLY — DO NOT DEPLOY ⚠</div>
  <div class="meta">Instructor edition · Burp Suite / OWASP ZAP steps · Verified findings<br>
  Confidential training material</div>
</div>
"""

full_html = f"<html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{COVER}{html_body}</body></html>"
HTML(string=full_html, base_url=str(ROOT)).write_pdf(str(OUT))
print(f"wrote {OUT}")
