"""Check the scan-report PDF rendering: logo, dates (no time), header text,
single logo on the last page, and the white cover background.

Run from Scanner-Backend/:  python scripts/test_logo_render.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.utils.generate_scan_report_pdf import (
    HERO_LOGO_PATH,
    RASTER_LOGO_PATH,
    COVER_BG,
    _load_logo,
    generate_domain_scan_report_pdf_bytes,
)

print(f"Logo path: {HERO_LOGO_PATH}")
print(f"Cover background: {COVER_BG}")

logo = _load_logo(HERO_LOGO_PATH, fallback=RASTER_LOGO_PATH)
if logo is None:
    print("FAIL: _load_logo returned None — logo will NOT appear in the PDF.")
    sys.exit(1)
print(f"OK: logo loaded as kind={logo.kind!r}, aspect={logo.aspect:.4f}")

# ── Sample data shaped like the real API payload ──
categories = [
    {
        "name": "Application Security",
        "findings": [
            {"rule": "Missing X-Content-Type-Options", "severity": "MEDIUM",
             "hosts": [{"subdomain": "www.example.com", "ip": "1.2.3.4", "port": 443}]},
            # This LOW finding must be filtered OUT of the PDF entirely.
            {"rule": "Low value test finding", "severity": "LOW",
             "hosts": [{"subdomain": "low.example.com", "ip": "1.2.3.5", "port": 80}]},
        ],
    },
    {
        "name": "Network Security",
        "findings": [
            # Mixed-severity rule: one HIGH host + one LOW host. The HIGH host
            # MUST survive (exactly the dashboard/PDF mismatch the user saw),
            # while the LOW host is dropped.
            {"rule": "Open port 22", "severity": "HIGH",
             "hosts": [
                 {"subdomain": "high.example.com", "ip": "1.2.3.4", "port": 22, "severity": "HIGH"},
                 {"subdomain": "mail2.example.com", "ip": "1.2.3.6", "port": 22, "severity": "LOW"},
             ]},
        ],
    },
    {"name": "IP Reputation", "isIpRep": True, "findings": []},
]
ip_reps = [{"ip": "1.2.3.4", "abuseConfidenceScore": 12, "totalReports": 3, "isp": "Example ISP"}]

pdf_bytes = generate_domain_scan_report_pdf_bytes(
    domain="example.com",
    score=72,
    grade_label="B",
    categories=categories,
    ip_reps=ip_reps,
)

out = Path(tempfile.gettempdir()) / "test_logo_report.pdf"
out.write_bytes(pdf_bytes)
print(f"OK: generated {out} ({len(pdf_bytes)} bytes)")
assert len(pdf_bytes) > 5000, "suspiciously small PDF — logo likely missing"

# ── Inspect pages with PyMuPDF ──
import fitz  # noqa: E402

pdf = fitz.open(stream=pdf_bytes, filetype="pdf")
print(f"pages: {len(pdf)}")

all_text = "\n".join(p.get_text() for p in pdf)

# 1. Date labels show date only — no time component (HH:MM).
import re  # noqa: E402

assert "Date: 10 Aug 2026" in all_text or "Report generated on 10 Aug 2026" in all_text, "FAIL: date label missing"
time_patterns = re.findall(r"\b\d{1,2}:\d{2}\b", all_text)
assert not time_patterns, f"FAIL: time still present in a date label: {time_patterns}"
print("OK: dates show date only (no time)")

# 2. The header brand line no longer says 'iSecurify Scan Report'
assert "iSecurify Scan Report" not in all_text, "FAIL: header still says 'iSecurify Scan Report'"
print("OK: header does not say 'iSecurify Scan Report'")

# 3. Exactly ONE logo on the last (back cover) page.
# The logo renders as a vector drawing on a small white card. The page
# background is also white now, so exclude full-page fills and count only
# the small card-sized drawings.
last_page = pdf[-1]
white_cards = [
    d for d in last_page.get_drawings()
    if d.get("fill") is not None
    and all(c > 0.9 for c in d["fill"])
    and d["rect"].width < 300
    and d["rect"].height < 300
]
print(f"last page white logo cards: {len(white_cards)}")
assert len(white_cards) == 1, f"FAIL: expected 1 logo card on last page, found {len(white_cards)}"
print("OK: last page has exactly ONE logo")

# 4. Cover background is white
cover = pdf[0]
bg_rects = [d for d in cover.get_drawings() if d["rect"].width > 500 and d["rect"].height > 800]
assert bg_rects, "FAIL: cover background rect not found"
r, g, b = bg_rects[0]["fill"]
print(f"cover bg rgb: ({r:.3f}, {g:.3f}, {b:.3f})")
assert r > 0.98 and g > 0.98 and b > 0.98, "FAIL: cover bg not white"
print("OK: cover background is white")

# 5. Score shown
assert "Score: 72 / 100" in all_text, "FAIL: score not shown correctly"
print("OK: score shows 72 / 100")

# 6. Logo appears on the cover page (page 0). The SVG wordmark renders as
# vector paths, so the cover must contain logo-sized drawings on top of the
# background rects and decorative bands. The width filter (< 400pt) excludes
# the 30mm bottom band (~516pt wide), so only the logo itself can match.
cover = pdf[0]
cover_logo_drawings = [
    d for d in cover.get_drawings()
    if d["rect"].height > 20 and d["rect"].height < 150 and d["rect"].width < 400
]
assert cover_logo_drawings, "FAIL: cover page has no logo drawing"
print(f"OK: cover page has {len(cover_logo_drawings)} logo-sized drawings")

# 7. The Report Overview page (page 1) must NOT contain a second large logo:
# the running page header already shows it. Only the small header logo
# (height ~0.26in) is allowed there.
overview = pdf[1]
big_drawings = [
    d for d in overview.get_drawings()
    if d["rect"].width > 300 and d["rect"].height > 50
]
assert not big_drawings, f"FAIL: duplicate logo still on overview page ({len(big_drawings)} drawings)"
print("OK: no duplicate logo on the Report Overview page")

# 8. LOW severity appears ONLY in the Severity Breakdown table (title-cased
# "Low") — it must never appear in the detail tables (uppercase "LOW") or as a
# finding rule/host.
uppercase_low = re.findall(r"\bLOW\b", all_text)
assert not uppercase_low, f"FAIL: LOW still appears in a detail table: {uppercase_low}"
title_low = re.findall(r"\bLow\b", all_text)
assert len(title_low) == 1, f"FAIL: expected 'Low' only in the Severity Breakdown, found {title_low}"
assert "Low value test finding" not in all_text, "FAIL: LOW finding still listed in a detail table"
assert "Total findings" in all_text, "FAIL: total findings row missing"
print("OK: LOW shown only in the Severity Breakdown table")

# 9. Dashboard parity: a rule with mixed-severity hosts (HIGH + LOW) must keep
# the HIGH host in the PDF — previously the whole rule vanished when the last
# host was LOW. The LOW host itself must still be filtered out.
assert "high.example.com" in all_text, "FAIL: HIGH host disappeared from the PDF"
assert "mail2.example.com" not in all_text, "FAIL: LOW host still appears in the PDF"
print("OK: HIGH host survives mixed-severity rule; LOW host dropped")

print("RESULT: ALL PASS")
