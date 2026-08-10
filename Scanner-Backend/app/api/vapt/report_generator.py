"""
iSecurify VAPT PDF report generator — v2 (enterprise redesign)
=================================================================

Rebuilt from scratch to look like a report produced by a professional
security consultancy (Tenable / Qualys / Rapid7 / Invicti style) rather
than a generic template. Same public entry point and data contract as
the previous generator, so it is a drop-in replacement:

    generate_vapt_report_pdf(record, client_name=..., ...) -> bytes

Design goals (see redesign brief):
  - Purple brand identity (#800080), enterprise severity colors.
  - One professional typeface, tight and consistent spacing.
  - Compact, information-dense layout — a small assessment should land
    in the 10-20 page range, not 100+.
  - Cover + back cover with real brand logos (falls back to a vector
    mark if the asset isn't found on disk).
  - Auto-generated Table of Contents with dotted leaders.
  - Executive dashboard: stat cards + donut / bar / pie charts + a
    data-driven 5x5 risk matrix, all on one to two pages.
  - Findings shown as compact multi-per-page cards (not one page per
    finding), with evidence capped to a short, readable snippet.
  - Remediation roadmap + concise appendix.

Layout, in order:
  1.  Cover                      (separate full-bleed canvas page)
  2.  Table of Contents
  3.  Assessment Information
  4.  Executive Summary          (stat cards + charts + risk matrix)
  5.  Findings Summary           (compact table, every reported finding)
  6.  Detailed Findings          (compact cards, several per page)
  7.  Remediation Roadmap
  8.  Appendix                   (scanner info, CVSS, references, glossary)
  9.  Back cover                 (separate full-bleed canvas page)

Informational-severity entries are filtered out of every findings-bearing
section, exactly as before — only Critical / High / Medium / Low are
"reportable" — but the raw informational count is still surfaced once,
for transparency, on the executive dashboard.
"""

import os
from datetime import datetime, timezone
from io import BytesIO
from types import SimpleNamespace
from xml.sax.saxutils import escape as _xml_escape

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    HRFlowable,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

# ─────────────────────────────────────────────────────────────────────────
# Brand palette
# ─────────────────────────────────────────────────────────────────────────
PRIMARY = HexColor("#800080")
PRIMARY_DARK = HexColor("#5A005A")
PRIMARY_MED = HexColor("#A64CA6")
PRIMARY_LIGHT = HexColor("#EEDAF3")
BG = HexColor("#FAFAFA")
CARD_BG = colors.white
BORDER = HexColor("#E5E7EB")
INK = HexColor("#1F2937")
MUTED = HexColor("#6B7280")
FAINT = HexColor("#9CA3AF")

SEVERITY_COLORS = {
    "critical": HexColor("#B91C1C"),
    "high": HexColor("#EA580C"),
    "medium": HexColor("#D97706"),
    "low": HexColor("#2563EB"),
    "info": HexColor("#6B7280"),
    "none": HexColor("#6B7280"),
}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_CVSS_RANGE = {
    "critical": "9.0 – 10.0",
    "high": "7.0 – 8.9",
    "medium": "4.0 – 6.9",
    "low": "0.1 – 3.9",
}
SEVERITY_TIMELINE = {"critical": "24 Hours", "high": "7 Days", "medium": "30 Days", "low": "90 Days"}
_REPORTED_SEVERITIES = {"critical", "high", "medium", "low"}

_TOOL_LABELS = {"nessus": "Nessus", "openvas": "OpenVAS", "qualys": "Qualys", "generic": "Generic"}


def _tool_label(tool):
    return _TOOL_LABELS.get((tool or "").lower(), tool or "—")


PAGE_W, PAGE_H = A4
MARGIN = 16 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# ─────────────────────────────────────────────────────────────────────────
# Fonts — single professional family, DejaVu Sans as the portable default
# (renders like Source Sans / Helvetica-class text; falls back to system
# Arial/Segoe on Windows, Helvetica everywhere else).
# ─────────────────────────────────────────────────────────────────────────
_FONT_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "arial.ttf"),
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "arialbd.ttf"),
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "segoeui.ttf"),
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "segoeuib.ttf"),
    "/Library/Fonts/Arial.ttf",
    "/Library/Fonts/Arial Bold.ttf",
]

_REGISTERED_FONT = None
_BOLD_FONT = None


def _register_fonts():
    global _REGISTERED_FONT, _BOLD_FONT
    if _REGISTERED_FONT:
        return
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    normal = bold = None
    for path in _FONT_PATHS:
        if not os.path.exists(path):
            continue
        try:
            name = os.path.splitext(os.path.basename(path))[0]
            safe_name = f"Vapt{name.replace(' ', '')}"
            pdfmetrics.registerFont(TTFont(safe_name, path))
            if "Bold" in name or "bd" in name:
                if bold is None:
                    bold = safe_name
            else:
                if normal is None:
                    normal = safe_name
        except Exception:
            continue
    if normal and bold:
        _REGISTERED_FONT, _BOLD_FONT = normal, bold


def _font(style="normal") -> str:
    _register_fonts()
    if style == "bold":
        return _BOLD_FONT or _REGISTERED_FONT or "Helvetica-Bold"
    return _REGISTERED_FONT or "Helvetica"


def _latin1_safe(text: str) -> str:
    if _REGISTERED_FONT:
        return text
    return text.encode("latin-1", "replace").decode("latin-1")


def _esc(text) -> str:
    return _xml_escape(_latin1_safe(str(text if text is not None else "")))


def _darker(color, factor=0.72):
    return colors.Color(max(0, color.red * factor), max(0, color.green * factor), max(0, color.blue * factor))


# ─────────────────────────────────────────────────────────────────────────
# Logo handling — real asset if present on disk, vector mark as fallback
# ─────────────────────────────────────────────────────────────────────────

def _find_logo(explicit_path, candidates):
    for path in [explicit_path] + list(candidates):
        if path and os.path.exists(path):
            return path
    return None


def _draw_image_fit(c, path, cx, top_y, max_w, max_h, anchor="top"):
    """Draw an image centered horizontally at cx, preserving aspect ratio,
    fit within max_w x max_h. anchor='top' positions the image's top edge
    at top_y; anchor='center' centers it vertically on top_y."""
    img = ImageReader(path)
    iw, ih = img.getSize()
    scale = min(max_w / iw, max_h / ih)
    w, h = iw * scale, ih * scale
    x = cx - w / 2
    y = (top_y - h) if anchor == "top" else (top_y - h / 2)
    c.drawImage(img, x, y, width=w, height=h, mask="auto", preserveAspectRatio=True)
    return w, h


def _mark(c, cx, cy, size, fg=colors.white, bg=PRIMARY):
    """Vector shield + 'i' monogram — used only when no logo file is found."""
    p = c.beginPath()
    w, h = size, size * 1.14
    p.moveTo(cx, cy + h / 2)
    p.lineTo(cx + w / 2, cy + h / 2 - w * 0.32)
    p.lineTo(cx + w / 2, cy - h * 0.12)
    p.curveTo(cx + w / 2, cy - h * 0.46, cx + w * 0.22, cy - h / 2, cx, cy - h / 2)
    p.curveTo(cx - w * 0.22, cy - h / 2, cx - w / 2, cy - h * 0.46, cx - w / 2, cy - h * 0.12)
    p.lineTo(cx - w / 2, cy + h / 2 - w * 0.32)
    p.close()
    c.setFillColor(bg)
    c.drawPath(p, fill=1, stroke=0)
    c.setFillColor(fg)
    c.setFont(_font("bold"), size * 0.62)
    c.drawCentredString(cx, cy - size * 0.22, "i")


def _wordmark(c, x, y, size, color=INK):
    c.setFillColor(color)
    c.setFont(_font("bold"), size)
    c.drawString(x, y, "iSecurify")


# ─────────────────────────────────────────────────────────────────────────
# Styles
# ─────────────────────────────────────────────────────────────────────────

def _build_styles():
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle("cover_title", parent=base["Title"], fontName=_font("bold"),
                                       fontSize=26, textColor=INK, leading=32, alignment=TA_CENTER),
        "cover_sub": ParagraphStyle("cover_sub", parent=base["Normal"], fontName=_font(),
                                     fontSize=11, textColor=MUTED, leading=16, alignment=TA_CENTER),
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontName=_font("bold"),
                              fontSize=17, textColor=PRIMARY_DARK, leading=21,
                              spaceBefore=0, spaceAfter=8),
        "toc_title": ParagraphStyle("toc_title", parent=base["Heading1"], fontName=_font("bold"),
                                     fontSize=17, textColor=PRIMARY_DARK, leading=21,
                                     spaceBefore=0, spaceAfter=8),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontName=_font("bold"),
                              fontSize=13, textColor=INK, spaceBefore=10, spaceAfter=5, leading=16),
        "h3": ParagraphStyle("h3", parent=base["Heading3"], fontName=_font("bold"),
                              fontSize=10.5, textColor=PRIMARY_DARK, spaceBefore=4, spaceAfter=3, leading=13),
        "body": ParagraphStyle("body", parent=base["Normal"], fontName=_font(),
                                fontSize=9, textColor=INK, leading=13, alignment=TA_LEFT),
        "body_small": ParagraphStyle("body_small", parent=base["Normal"], fontName=_font(),
                                      fontSize=8, textColor=MUTED, leading=11.5),
        "label": ParagraphStyle("label", parent=base["Normal"], fontName=_font("bold"),
                                 fontSize=7, textColor=PRIMARY, leading=10),
        "kv_key": ParagraphStyle("kv_key", parent=base["Normal"], fontName=_font("bold"),
                                  fontSize=8, textColor=MUTED, leading=12),
        "kv_val": ParagraphStyle("kv_val", parent=base["Normal"], fontName=_font(),
                                  fontSize=8.5, textColor=INK, leading=12),
        "mono": ParagraphStyle("mono", parent=base["Code"], fontName="Courier", fontSize=7,
                                leading=10, textColor=INK, backColor=HexColor("#F3F4F6"),
                                borderPadding=5),
        "table_head": ParagraphStyle("table_head", parent=base["Normal"], fontName=_font("bold"),
                                      fontSize=8, textColor=colors.white, leading=11),
        "table_cell": ParagraphStyle("table_cell", parent=base["Normal"], fontName=_font(),
                                      fontSize=8, textColor=INK, leading=11),
        "stat_num": ParagraphStyle("stat_num", parent=base["Normal"], fontName=_font("bold"),
                                    fontSize=17, textColor=INK, alignment=TA_CENTER, leading=19),
        "stat_label": ParagraphStyle("stat_label", parent=base["Normal"], fontName=_font("bold"),
                                      fontSize=6.4, textColor=MUTED, alignment=TA_CENTER, leading=8),
        "toc0": ParagraphStyle("toc0", fontName=_font("bold"), fontSize=10, textColor=INK, leading=16),
        "card_title": ParagraphStyle("card_title", parent=base["Normal"], fontName=_font("bold"),
                                      fontSize=9.5, textColor=colors.white, leading=12),
        "card_sub": ParagraphStyle("card_sub", parent=base["Normal"], fontName=_font(),
                                    fontSize=7.5, textColor=colors.white, leading=10),
        "back_note": ParagraphStyle("back_note", parent=base["Normal"], fontName=_font(),
                                     fontSize=9.5, textColor=MUTED, alignment=TA_CENTER, leading=14),
    }


# ─────────────────────────────────────────────────────────────────────────
# Small building blocks
# ─────────────────────────────────────────────────────────────────────────

class Chip(Flowable):
    """Compact rounded severity / status badge."""

    def __init__(self, text, bg, width=None, height=4.6 * mm, font_size=6.6,
                 text_color=colors.white, uppercase=True, max_len=28):
        super().__init__()
        raw = text.upper() if uppercase else text
        if max_len and len(raw) > max_len:
            raw = raw[: max_len - 1].rstrip() + "…"
        self.text = raw
        self.bg = bg
        self.font_size = font_size
        self.text_color = text_color
        self.height = height
        self.width = width or max(height + 1.6 * mm, font_size * len(self.text) * 0.6 + 5.6 * mm)

    def wrap(self, availWidth, availHeight):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.setFillColor(self.bg)
        c.roundRect(0, 0, self.width, self.height, self.height / 2, stroke=0, fill=1)
        c.setFillColor(self.text_color)
        c.setFont(_font("bold"), self.font_size)
        c.drawCentredString(self.width / 2, self.height / 2 - self.font_size * 0.35, self.text)


def _hr(color=BORDER, thickness=0.6, space_before=2, space_after=6):
    return HRFlowable(width="100%", thickness=thickness, color=color,
                       spaceBefore=space_before, spaceAfter=space_after)


def _kv_table(rows, styles, key_w=34 * mm):
    data = [[Paragraph(_esc(k), styles["kv_key"]), Paragraph(str(v), styles["kv_val"])] for k, v in rows]
    t = Table(data, colWidths=[key_w, None], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, HexColor("#F1F5F9")),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _card(inner_flowables, border_color=BORDER, bg=CARD_BG, pad=7, accent=None):
    """Wrap flowables in a bordered, lightly padded card (rounded corners)."""
    t = Table([[inner_flowables]], colWidths=[CONTENT_W - 2 * pad * mm / mm if False else None])
    style = [
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.7, border_color),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
        ("LEFTPADDING", (0, 0), (-1, -1), pad * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), pad * mm),
        ("TOPPADDING", (0, 0), (-1, -1), pad * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), pad * mm),
    ]
    if accent:
        style.append(("LINEBEFORE", (0, 0), (0, -1), 2.6, accent))
    t.setStyle(TableStyle(style))
    return t


def _section_heading(story, styles, text, level="h1"):
    """Section heading that also registers a Table-of-Contents entry."""
    story.append(Paragraph(_esc(text), styles[level]))
    if level == "h1":
        story.append(_hr(color=PRIMARY_LIGHT, thickness=1.1, space_before=0, space_after=7))


# ─────────────────────────────────────────────────────────────────────────
# Charts (reportlab Drawing, hand-built so colors match the brand exactly)
# ─────────────────────────────────────────────────────────────────────────
from reportlab.graphics.shapes import ArcPath, Drawing, Rect, String


def _donut_severity(dist, size=40 * mm):
    total = sum((dist or {}).values()) or 1
    d = Drawing(size, size)
    cx = cy = size / 2.0
    r = size / 2.0 - 4.5 * mm
    stroke = 4.2 * mm

    def arc(a0, a1, col):
        p = ArcPath()
        p.strokeColor = col
        p.strokeWidth = stroke
        p.fillColor = None
        p.strokeLineCap = 1
        p.addArc(cx, cy, r, a0, a1)
        return p

    d.add(arc(90, 450, BORDER))
    start = 90.0
    for label in SEVERITY_ORDER:
        count = (dist or {}).get(label, 0)
        if count <= 0:
            continue
        sweep = 360.0 * count / total
        d.add(arc(start, start + sweep, SEVERITY_COLORS[label]))
        start += sweep
    d.add(String(cx, cy + 4, str(total), fontName=_font("bold"), fontSize=17, fillColor=INK, textAnchor="middle"))
    d.add(String(cx, cy - 8, "FINDINGS", fontName=_font("bold"), fontSize=5.6, fillColor=MUTED, textAnchor="middle"))
    return d


def _bar_categories(cat_dist, width=90 * mm, row_h=5.4 * mm, max_rows=6):
    pairs = sorted((cat_dist or {}).items(), key=lambda kv: -kv[1])[:max_rows]
    if not pairs:
        return None
    max_count = max(c for _, c in pairs) or 1
    label_w = 30 * mm
    bar_area = width - label_w - 10 * mm
    height = row_h * len(pairs) + 2 * mm
    d = Drawing(width, height)
    y = height - row_h
    for label, count in pairs:
        d.add(String(0, y + row_h * 0.28, (label[:20] + "…") if len(label) > 20 else label,
                      fontName=_font(), fontSize=6.6, fillColor=INK))
        bw = bar_area * (count / max_count)
        d.add(Rect(label_w, y + row_h * 0.12, max(bw, 1.2 * mm), row_h * 0.62,
                    fillColor=PRIMARY, strokeColor=None, rx=1.2, ry=1.2))
        d.add(String(label_w + bw + 2 * mm, y + row_h * 0.28, str(count),
                      fontName=_font("bold"), fontSize=6.6, fillColor=MUTED))
        y -= row_h
    return d


def _pie_remediation(status_dist, size=40 * mm):
    order = ["remediated", "in_progress", "open"]
    pie_colors = {"remediated": HexColor("#16A34A"), "in_progress": HexColor("#D97706"), "open": HexColor("#B91C1C")}
    labels = {"remediated": "Remediated", "in_progress": "In Progress", "open": "Open"}
    total = sum(status_dist.values()) or 1
    d = Drawing(size, size)
    cx = cy = size / 2.0
    r = size / 2.0 - 4 * mm

    start = 90.0
    from reportlab.graphics.shapes import Path
    for key in order:
        count = status_dist.get(key, 0)
        if count <= 0:
            continue
        sweep = 360.0 * count / total
        p = Path(fillColor=pie_colors[key], strokeColor=colors.white, strokeWidth=0.8)
        p.moveTo(cx, cy)
        import math
        steps = max(2, int(sweep / 6))
        p.lineTo(cx + r * math.cos(math.radians(start)), cy + r * math.sin(math.radians(start)))
        for i in range(1, steps + 1):
            a = start + sweep * i / steps
            p.lineTo(cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a)))
        p.closePath()
        d.add(p)
        start += sweep
    return d, [(labels[k], pie_colors[k], status_dist.get(k, 0)) for k in order]


def _risk_matrix(findings, styles, cell=15 * mm):
    """Data-driven 5x5 likelihood x impact heat map. Impact = severity
    rank; likelihood = CVSS bucket (falls back to severity rank when a
    finding has no CVSS score)."""
    grid = [[0] * 5 for _ in range(5)]  # grid[impact-1][likelihood-1]
    for f in findings:
        sev = (f.get("severity_label") or "").lower()
        if sev not in SEVERITY_RANK:
            continue
        impact = SEVERITY_RANK[sev] - 1  # 0..4 (info excluded upstream so 1..4 really, but keep general)
        impact = min(4, max(0, impact))
        cvss = f.get("cvss_score")
        if isinstance(cvss, (int, float)):
            likelihood = min(4, max(0, int((cvss) // 2)))
        else:
            likelihood = impact
        grid[impact][likelihood] += 1

    size = cell * 5
    d = Drawing(size + 14 * mm, size + 10 * mm)
    ox, oy = 12 * mm, 8 * mm  # origin offset for axis labels

    for row in range(5):        # impact, bottom(0)=lowest -> top
        for col in range(5):    # likelihood, left(0)=lowest -> right
            zone = row + col    # 0..8
            if zone >= 7:
                zc = SEVERITY_COLORS["critical"]
            elif zone >= 5:
                zc = SEVERITY_COLORS["high"]
            elif zone >= 3:
                zc = SEVERITY_COLORS["medium"]
            else:
                zc = SEVERITY_COLORS["low"]
            # lighten for a wash rather than a solid block
            wash = colors.Color(zc.red, zc.green, zc.blue, alpha=0.22)
            x = ox + col * cell
            y = oy + row * cell
            d.add(Rect(x, y, cell - 1, cell - 1, fillColor=wash, strokeColor=colors.white, strokeWidth=1))
            count = grid[row][col]
            if count:
                d.add(String(x + cell / 2, y + cell / 2 - 3, str(count), fontName=_font("bold"),
                              fontSize=11, fillColor=_darker(zc, 0.85), textAnchor="middle"))
    # axis labels
    d.add(String(ox + size / 2, 1.5 * mm, "Likelihood (CVSS-derived)", fontName=_font("bold"),
                  fontSize=6.6, fillColor=MUTED, textAnchor="middle"))
    d.add(String(3 * mm, oy + size / 2, "Impact", fontName=_font("bold"), fontSize=6.6,
                  fillColor=MUTED, textAnchor="middle", angle=90))
    return d


# ─────────────────────────────────────────────────────────────────────────
# Cover & back cover — full-bleed, drawn directly on their own canvas pages
# ─────────────────────────────────────────────────────────────────────────

def _build_cover_pdf(record, client_name, report_title, version, assessment_date, cover_logo_path):
    buf = BytesIO()
    c = pdfcanvas.Canvas(buf, pagesize=A4)

    c.setFillColor(colors.white)
    c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

    # thin brand rule across the top
    c.setFillColor(PRIMARY)
    c.rect(0, PAGE_H - 3 * mm, PAGE_W, 3 * mm, stroke=0, fill=1)

    cx = PAGE_W / 2
    logo_top = PAGE_H - 46 * mm

    def _fallback_lockup():
        mark_size = 12 * mm
        word_size = 17
        word_w = c.stringWidth("iSecurify", _font("bold"), word_size)
        gap = 4 * mm
        total_w = mark_size + gap + word_w
        mx = cx - total_w / 2 + mark_size / 2
        _mark(c, mx, logo_top - mark_size * 0.5, mark_size)
        _wordmark(c, mx + mark_size / 2 + gap, logo_top - mark_size * 0.5 - word_size * 0.32, word_size, color=INK)

    if cover_logo_path:
        try:
            _draw_image_fit(c, cover_logo_path, cx, logo_top, max_w=70 * mm, max_h=28 * mm, anchor="top")
        except Exception:
            _fallback_lockup()
    else:
        _fallback_lockup()

    # title block, vertically centered on the page
    title_y = PAGE_H * 0.52
    c.setFillColor(INK)
    c.setFont(_font("bold"), 26)
    c.drawCentredString(cx, title_y, report_title)
    c.setFont(_font(), 11.5)
    c.setFillColor(MUTED)
    c.drawCentredString(cx, title_y - 9 * mm, "Vulnerability Assessment & Penetration Testing")

    c.setStrokeColor(PRIMARY_LIGHT)
    c.setLineWidth(1)
    c.line(cx - 30 * mm, title_y - 16 * mm, cx + 30 * mm, title_y - 16 * mm)

    meta_y = title_y - 30 * mm
    meta_rows = [("Prepared for", client_name), ("Assessment date", assessment_date), ("Report version", version)]
    for label, value in meta_rows:
        c.setFont(_font("bold"), 8.5)
        c.setFillColor(PRIMARY)
        c.drawCentredString(cx, meta_y, label.upper())
        c.setFont(_font(), 11)
        c.setFillColor(INK)
        c.drawCentredString(cx, meta_y - 5.6 * mm, _latin1_safe(str(value)))
        meta_y -= 15 * mm

    # confidential badge, bottom of page
    badge_w, badge_h = 46 * mm, 9 * mm
    bx, by = cx - badge_w / 2, 26 * mm
    c.setFillColor(PRIMARY_LIGHT)
    c.roundRect(bx, by, badge_w, badge_h, badge_h / 2, stroke=0, fill=1)
    c.setFillColor(PRIMARY_DARK)
    c.setFont(_font("bold"), 8.5)
    c.drawCentredString(cx, by + badge_h / 2 - 3, "CONFIDENTIAL")

    c.setFont(_font(), 7.5)
    c.setFillColor(FAINT)
    c.drawCentredString(cx, 14 * mm, "This document contains confidential and proprietary information.")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf


def _build_back_cover_pdf(back_logo_path, version, assessment_date):
    buf = BytesIO()
    c = pdfcanvas.Canvas(buf, pagesize=A4)
    c.setFillColor(colors.white)
    c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
    c.setFillColor(PRIMARY)
    c.rect(0, 0, PAGE_W, 3 * mm, stroke=0, fill=1)

    cx = PAGE_W / 2
    logo_center = PAGE_H * 0.56
    if back_logo_path:
        try:
            _draw_image_fit(c, back_logo_path, cx, logo_center, max_w=60 * mm, max_h=26 * mm, anchor="center")
        except Exception:
            _mark(c, cx, logo_center, 13 * mm)
    else:
        _mark(c, cx, logo_center, 13 * mm)

    c.setFillColor(INK)
    c.setFont(_font("bold"), 15)
    c.drawCentredString(cx, logo_center - 24 * mm, "End of Report")
    c.setFont(_font(), 10)
    c.setFillColor(MUTED)
    c.drawCentredString(cx, logo_center - 32 * mm, "Confidential Security Assessment")

    c.setFont(_font(), 8.5)
    c.setFillColor(FAINT)
    c.drawCentredString(cx, logo_center - 42 * mm, f"Report version {version}  •  {assessment_date}")

    c.showPage()
    c.save()
    buf.seek(0)
    return buf


# ─────────────────────────────────────────────────────────────────────────
# Header / footer for interior pages
# ─────────────────────────────────────────────────────────────────────────

def _make_header_footer(report_title, client_name, version, assessment_date):
    def _draw(canvas_, doc):
        canvas_.saveState()
        # header
        canvas_.setStrokeColor(BORDER)
        canvas_.setLineWidth(0.6)
        canvas_.line(MARGIN, PAGE_H - 13 * mm, PAGE_W - MARGIN, PAGE_H - 13 * mm)
        _mark(canvas_, MARGIN + 2.4 * mm, PAGE_H - 9.6 * mm, 4.6 * mm)
        canvas_.setFont(_font("bold"), 8.5)
        canvas_.setFillColor(INK)
        canvas_.drawString(MARGIN + 7 * mm, PAGE_H - 10.6 * mm, report_title)
        canvas_.setFont(_font(), 8)
        canvas_.setFillColor(MUTED)
        canvas_.drawRightString(PAGE_W - MARGIN, PAGE_H - 10.6 * mm, client_name)

        # footer
        canvas_.setStrokeColor(BORDER)
        canvas_.line(MARGIN, 13 * mm, PAGE_W - MARGIN, 13 * mm)
        canvas_.setFont(_font(), 7.3)
        canvas_.setFillColor(FAINT)
        canvas_.drawString(MARGIN, 9.5 * mm, "CONFIDENTIAL")
        canvas_.drawCentredString(PAGE_W / 2, 9.5 * mm, f"v{version}  •  {assessment_date}")
        canvas_.drawRightString(PAGE_W - MARGIN, 9.5 * mm, f"Page {canvas_.getPageNumber()}")
        canvas_.restoreState()

    return _draw


# ─────────────────────────────────────────────────────────────────────────
# TOC-aware document template
# ─────────────────────────────────────────────────────────────────────────

class _ReportDoc(BaseDocTemplate):
    def __init__(self, filename, header_footer_fn, **kwargs):
        BaseDocTemplate.__init__(self, filename, **kwargs)
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="body")
        self.addPageTemplates([PageTemplate(id="body", frames=[frame], onPage=header_footer_fn)])

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and flowable.style.name == "H1":
            text = flowable.getPlainText()
            key = f"toc-{self.page}-{id(flowable)}"
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(text, key, level=0, closed=False)
            self.notify("TOCEntry", (0, text, self.page, key))


def _build_toc(styles):
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(name="TOCLevel0", fontName=_font("bold"), fontSize=10, leading=17,
                        textColor=INK, spaceBefore=3, leftIndent=0, dotWidth=0.7),
    ]
    toc.dotsMinLevel = 0
    return toc


# ─────────────────────────────────────────────────────────────────────────
# Section: Assessment Information
# ─────────────────────────────────────────────────────────────────────────

def _section_assessment_info(record, styles, *, assessment_type, methodology, testing_window,
                              scope, standards):
    story = []
    _section_heading(story, styles, "Assessment Information")
    left = _kv_table([
        ("Assessment Type", assessment_type),
        ("Testing Window", testing_window),
        ("Target Assets", f"{record.unique_hosts} host(s)"),
    ], styles, key_w=30 * mm)
    right = _kv_table([
        ("Methodology", methodology),
        ("Scope", scope),
        ("Standards", standards),
    ], styles, key_w=26 * mm)
    two_col = Table([[left, right]], colWidths=[CONTENT_W * 0.5 - 3 * mm, CONTENT_W * 0.5 - 3 * mm], hAlign="LEFT")
    two_col.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(_card(two_col, pad=6))
    story.append(Spacer(1, 10))
    return story


# ─────────────────────────────────────────────────────────────────────────
# Section: Executive Summary (stat cards + charts + risk matrix)
# ─────────────────────────────────────────────────────────────────────────

def _stat_card(value, label, accent, styles):
    inner = Table([[Paragraph(_esc(str(value)), styles["stat_num"])],
                    [Paragraph(label.upper(), styles["stat_label"])]], colWidths=[None])
    inner.setStyle(TableStyle([
        ("TOPPADDING", (0, 0), (-1, -1), 1), ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    box = Table([[inner]], colWidths=[None])
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.6, BORDER),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
        ("LINEABOVE", (0, 0), (-1, 0), 2, accent),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 2), ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    return box


def _section_executive_summary(record, raw_info_count, styles):
    story = []
    _section_heading(story, styles, "Executive Summary")

    dist = record.severity_distribution or {}
    sev_color = SEVERITY_COLORS.get((record.severity or "none").lower(), SEVERITY_COLORS["info"])
    stats = [
        (record.unique_hosts, "Assets Tested", PRIMARY),
        (record.total_findings, "Total Findings", INK),
        (dist.get("critical", 0), "Critical", SEVERITY_COLORS["critical"]),
        (dist.get("high", 0), "High", SEVERITY_COLORS["high"]),
        (dist.get("medium", 0), "Medium", SEVERITY_COLORS["medium"]),
        (dist.get("low", 0), "Low", SEVERITY_COLORS["low"]),
        (raw_info_count, "Informational", SEVERITY_COLORS["info"]),
        (f"{record.risk_score}/100", "Overall Risk", sev_color),
    ]
    cells = [_stat_card(v, l, a, styles) for v, l, a in stats]
    row1 = Table([cells[:4]], colWidths=[CONTENT_W / 4] * 4, hAlign="LEFT")
    row2 = Table([cells[4:]], colWidths=[CONTENT_W / 4] * 4, hAlign="LEFT")
    for row in (row1, row2):
        row.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 2), ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                                  ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    story.append(row1)
    story.append(Spacer(1, 4))
    story.append(row2)
    story.append(Spacer(1, 10))

    if record.total_findings == 0:
        summary_text = ("No reportable vulnerabilities were identified during this assessment. "
                         "The environment reflects a strong baseline security posture at the time of testing.")
    else:
        crit, high = dist.get("critical", 0), dist.get("high", 0)
        if crit or high:
            summary_text = (f"This assessment identified <b>{record.total_findings}</b> reportable "
                             f"finding(s) across <b>{record.unique_hosts}</b> host(s), including "
                             f"<b>{crit}</b> critical and <b>{high}</b> high-severity issue(s) that "
                             "require prompt remediation. See the Remediation Roadmap for the "
                             "recommended response timeline.")
        else:
            summary_text = (f"This assessment identified <b>{record.total_findings}</b> reportable "
                             f"finding(s) across <b>{record.unique_hosts}</b> host(s), all Medium or "
                             "Low severity. No critical or high-severity issues were detected.")
    story.append(Paragraph(summary_text, styles["body"]))
    story.append(Spacer(1, 10))

    # ── charts row: donut + category bars, side by side ──
    donut = _donut_severity(dist)
    donut_cell = Table([[donut], [Paragraph("Severity Distribution", styles["body_small"])]], colWidths=[None])
    donut_cell.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 1), (-1, 1), 2)]))

    bars = _bar_categories(record.category_distribution)
    right_col = [Paragraph("Findings by Category", styles["h3"])]
    if bars:
        right_col.append(bars)
    else:
        right_col.append(Paragraph("No category data available.", styles["body_small"]))

    charts_row = Table([[donut_cell, right_col]], colWidths=[46 * mm, CONTENT_W - 46 * mm - 6 * mm], hAlign="LEFT")
    charts_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (1, 0), (1, 0), 8 * mm),
    ]))
    story.append(_card(charts_row, pad=6))
    story.append(Spacer(1, 8))

    # ── risk matrix ──
    matrix = _risk_matrix(record.findings or [], styles)
    matrix_wrap = Table([[matrix]], colWidths=[None], hAlign="LEFT")
    matrix_wrap.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 0)]))
    matrix_block = [
        Paragraph("Risk Matrix", styles["h3"]),
        Paragraph("Findings plotted by severity (impact) against a CVSS-derived likelihood band. "
                  "Darker zones indicate higher combined risk.", styles["body_small"]),
        Spacer(1, 3),
        matrix_wrap,
    ]
    story.append(KeepTogether(matrix_block))
    story.append(Spacer(1, 10))
    return story


# ─────────────────────────────────────────────────────────────────────────
# Section: Findings Summary (compact table)
# ─────────────────────────────────────────────────────────────────────────

def _section_findings_summary(record, styles):
    story = []
    _section_heading(story, styles, "Findings Summary")
    findings = record.findings or []
    if not findings:
        story.append(Paragraph("No reportable findings were identified.", styles["body"]))
        return story

    data = [[Paragraph("ID", styles["table_head"]), Paragraph("Vulnerability", styles["table_head"]),
             Paragraph("Severity", styles["table_head"]), Paragraph("Asset(s)", styles["table_head"]),
             Paragraph("CVSS", styles["table_head"]), Paragraph("Status", styles["table_head"])]]
    for f in findings:
        sev = (f.get("severity_label") or "info").lower()
        color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
        hosts = f.get("affected_hosts") or []
        asset_text = hosts[0] if len(hosts) == 1 else f"{f.get('host_count', len(hosts))} hosts"
        status = (f.get("remediation_status") or "Open").replace("_", " ").title()
        data.append([
            Paragraph(_esc(f.get("id", "")), styles["table_cell"]),
            Paragraph(_esc(f.get("title", "")), styles["table_cell"]),
            Chip(sev, color, height=4.4 * mm, font_size=6.2),
            Paragraph(_esc(asset_text), styles["table_cell"]),
            Paragraph(_esc(str(f.get("cvss_score") or "—")), styles["table_cell"]),
            Paragraph(_esc(status), styles["table_cell"]),
        ])
    t = Table(data, colWidths=[10 * mm, None, 20 * mm, 26 * mm, 14 * mm, 20 * mm], repeatRows=1, hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), HexColor("#FAFAFA")))
    t.setStyle(TableStyle(style))
    story.append(t)
    story.append(Spacer(1, 6))
    return story


# ─────────────────────────────────────────────────────────────────────────
# Section: Detailed Findings — compact multi-per-page cards
# ─────────────────────────────────────────────────────────────────────────

def _clip(text, max_chars):
    """Word-boundary truncation so a single field can never blow the card
    past one page's height."""
    text = (text or "").strip()
    if len(text) <= max_chars:
        return text
    cut = text[:max_chars].rsplit(" ", 1)[0]
    return cut + "…"


def _clip_line(line, max_len=130):
    line = line.rstrip()
    return line if len(line) <= max_len else line[: max_len - 1] + "…"


def _finding_card(finding, index, styles):
    sev = (finding.get("severity_label") or "info").lower()
    color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    dark = _darker(color)

    # header band
    header_left = Paragraph(f"F{index:03d}", styles["card_sub"])
    title = Paragraph(_esc(_clip(finding.get("title") or "Untitled finding", 140)), styles["card_title"])
    host_count = finding.get("host_count") or 0
    sub_bits = [sev.title()]
    if finding.get("cvss_score") is not None:
        sub_bits.append(f"CVSS {finding['cvss_score']}")
    sub_bits.append(f"{host_count} host{'s' if host_count != 1 else ''}")
    if finding.get("category"):
        sub_bits.append(finding["category"])
    sub = Paragraph(_esc(" · ".join(sub_bits)), styles["card_sub"])
    header = Table([[header_left, [title, sub]]], colWidths=[13 * mm, None], hAlign="LEFT")
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), dark),
        ("BACKGROUND", (1, 0), (1, 0), color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("LEFTPADDING", (1, 0), (1, 0), 8), ("RIGHTPADDING", (1, 0), (1, 0), 8),
        ("TOPPADDING", (0, 0), (-1, 0), 5), ("BOTTOMPADDING", (0, 0), (-1, 0), 5),
    ]))

    # metadata (left) + narrative (right)
    meta_rows = [("CVSS", str(finding.get("cvss_score") or "—")),
                 ("Severity", sev.title())]
    if finding.get("cwe"):
        meta_rows.append(("CWE", finding["cwe"]))
    if finding.get("owasp_category"):
        meta_rows.append(("OWASP", finding["owasp_category"]))
    hosts = finding.get("affected_hosts") or []
    meta_rows.append(("Asset(s)", ", ".join(hosts[:3]) + (f" +{len(hosts) - 3}" if len(hosts) > 3 else "") or "—"))
    if finding.get("port") is not None:
        meta_rows.append(("Port", str(finding["port"])))
    status = (finding.get("remediation_status") or "Open").replace("_", " ").title()
    meta_rows.append(("Status", status))
    meta_table = _kv_table(meta_rows, styles, key_w=20 * mm)

    narrative = []
    desc = _clip(finding.get("description") or finding.get("synopsis"), 420)
    if desc:
        narrative.append(Paragraph(f"<b>Description</b> — {_esc(desc)}", styles["body"]))
    impact = _clip(finding.get("business_impact"), 240)
    if impact:
        narrative.append(Spacer(1, 3))
        narrative.append(Paragraph(f"<b>Business Impact</b> — {_esc(impact)}", styles["body"]))
    solution = _clip(finding.get("solution"), 320)
    if solution:
        narrative.append(Spacer(1, 3))
        narrative.append(Paragraph(f"<b>Recommendation</b> — {_esc(solution)}", styles["body"]))
    dev_notes = _clip(finding.get("developer_notes"), 200)
    if dev_notes:
        narrative.append(Spacer(1, 3))
        narrative.append(Paragraph(f"<b>Developer Notes</b> — {_esc(dev_notes)}", styles["body_small"]))
    soc_notes = _clip(finding.get("soc_notes"), 200)
    if soc_notes:
        narrative.append(Spacer(1, 3))
        narrative.append(Paragraph(f"<b>SOC Notes</b> — {_esc(soc_notes)}", styles["body_small"]))
    if not narrative:
        narrative.append(Paragraph("No description was captured for this finding in the export.", styles["body_small"]))

    body_row = Table([[meta_table, narrative]], colWidths=[40 * mm, CONTENT_W - 40 * mm - 20 * mm - 6 * mm],
                      hAlign="LEFT")
    body_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (1, 0), (1, 0), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    parts = [header, Spacer(1, 6), body_row]

    # evidence — short snippet only, hard-capped on total lines AND line
    # length so a verbose HTTP request/response/payload can never push the
    # card past a single page.
    evidence_bits = []
    lines_budget = 10
    for key, label in (("payload", "Payload"), ("request", "Request"), ("response", "Response")):
        if lines_budget <= 0:
            break
        val = (finding.get(key) or "").strip()
        if not val:
            continue
        take = max(1, min(4, lines_budget))
        raw_lines = val.splitlines()[:take]
        lines = [_clip_line(l) for l in raw_lines]
        lines_budget -= len(lines)
        evidence_bits.append(f"{label}:\n" + "\n".join(lines))
    if not evidence_bits:
        raw_evidence = (finding.get("evidence") or "").strip()
        if raw_evidence:
            raw_lines = raw_evidence.splitlines()[:8]
            lines = [_clip_line(l) for l in raw_lines]
            evidence_bits.append("\n".join(lines))
    if evidence_bits:
        parts.append(Spacer(1, 5))
        mono_text = "<br/>".join(_esc(line) for block in evidence_bits for line in block.splitlines())
        parts.append(Paragraph(mono_text, styles["mono"]))

    # references / CVEs, compact single line, capped
    cves = (finding.get("cves") or [])[:8]
    refs = [f'<link href="https://nvd.nist.gov/vuln/detail/{_esc(cve)}" color="#800080">{_esc(cve)}</link>'
            for cve in cves]
    if len(finding.get("cves") or []) > 8:
        refs.append(f"+{len(finding['cves']) - 8} more")
    if refs:
        parts.append(Spacer(1, 4))
        parts.append(Paragraph("<b>CVE</b> — " + ", ".join(refs), styles["body_small"]))

    return KeepTogether(_card(parts, pad=0, border_color=BORDER))


def _section_detailed_findings(record, styles):
    story = []
    _section_heading(story, styles, "Detailed Findings")
    findings = record.findings or []
    if not findings:
        story.append(Paragraph("No reportable findings were identified during this assessment.", styles["body"]))
        return story
    story.append(Paragraph(
        f"The following {len(findings)} finding(s) are ordered by severity, most critical first.",
        styles["body_small"]))
    story.append(Spacer(1, 6))
    for i, f in enumerate(findings, start=1):
        story.append(_finding_card(f, i, styles))
        story.append(Spacer(1, 6))
    return story


# ─────────────────────────────────────────────────────────────────────────
# Section: Remediation Roadmap
# ─────────────────────────────────────────────────────────────────────────

_OWNER_KEYWORDS = [
    (("web", "app", "sql", "xss", "injection"), "Application Security Team"),
    (("network", "firewall", "port", "dns"), "Network/Infra Team"),
    (("tls", "ssl", "cert"), "Infrastructure Team"),
    (("mail", "smtp"), "IT/Email Admin"),
]


def _owner_for(category):
    cat = (category or "").lower()
    for keywords, owner in _OWNER_KEYWORDS:
        if any(k in cat for k in keywords):
            return owner
    return "Security Team"


def _section_remediation_roadmap(record, styles):
    story = []
    _section_heading(story, styles, "Remediation Roadmap")
    dist = record.severity_distribution or {}
    story.append(Paragraph(
        "Remediation should proceed in severity order. The table below sets the target "
        "response window for each priority tier.", styles["body"]))
    story.append(Spacer(1, 6))

    data = [[Paragraph("Priority", styles["table_head"]), Paragraph("Findings", styles["table_head"]),
             Paragraph("Target Timeline", styles["table_head"]), Paragraph("Owner", styles["table_head"]),
             Paragraph("Status", styles["table_head"])]]
    # representative owner per severity, based on most common category at that severity
    findings = record.findings or []
    for sev in SEVERITY_ORDER:
        count = dist.get(sev, 0)
        cats = [f.get("category") for f in findings if (f.get("severity_label") or "").lower() == sev]
        owner = _owner_for(cats[0]) if cats else "Security Team"
        color = SEVERITY_COLORS[sev]
        data.append([
            Chip(sev, color, height=4.6 * mm, font_size=6.6),
            Paragraph(str(count), styles["table_cell"]),
            Paragraph(SEVERITY_TIMELINE[sev], styles["table_cell"]),
            Paragraph(_esc(owner), styles["table_cell"]),
            Paragraph("Pending" if count else "—", styles["table_cell"]),
        ])
    t = Table(data, colWidths=[24 * mm, 22 * mm, 30 * mm, None, 22 * mm], hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), HexColor("#FAFAFA")))
    t.setStyle(TableStyle(style))
    story.append(t)
    story.append(Spacer(1, 8))
    return story


# ─────────────────────────────────────────────────────────────────────────
# Section: Appendix
# ─────────────────────────────────────────────────────────────────────────

def _section_appendix(record, styles):
    story = []
    _section_heading(story, styles, "Appendix")
    findings = record.findings or []

    story.append(Paragraph("Scanner Information", styles["h3"]))
    story.append(_kv_table([
        ("Source Tool", _tool_label(record.source_tool)),
        ("File Format", (record.file_format or "—").upper()),
        ("Raw Entries Parsed", str((record.summary or {}).get("raw_findings_parsed") or "—")),
    ], styles, key_w=40 * mm))
    story.append(Spacer(1, 6))

    story.append(Paragraph("CVSS Scoring", styles["h3"]))
    story.append(Paragraph(
        "Severity is derived from the Common Vulnerability Scoring System (CVSS) base "
        "score: Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9. The overall "
        "risk index (0–100) weighs the worst single finding alongside the density of "
        "high-severity issues.", styles["body_small"]))
    story.append(Spacer(1, 6))

    cve_map = {}
    for f in findings:
        for cve in f.get("cves", []) or []:
            cve_map.setdefault(cve, []).append(f.get("id", ""))
    if cve_map:
        story.append(Paragraph("CVE Register", styles["h3"]))
        lines = []
        for cve, ids in sorted(cve_map.items())[:30]:
            link = f'<link href="https://nvd.nist.gov/vuln/detail/{_esc(cve)}" color="#800080">{_esc(cve)}</link>'
            lines.append(f"• {link} — {_esc(', '.join(ids))}")
        story.append(Paragraph("<br/>".join(lines), styles["body_small"]))
        story.append(Spacer(1, 6))

    refs = []
    for f in findings:
        for ref in f.get("references", []) or []:
            if ref and ref.startswith(("http://", "https://")) and ref not in refs:
                refs.append(ref)
    if refs:
        story.append(Paragraph("References", styles["h3"]))
        story.append(Paragraph("<br/>".join(
            f'• <link href="{_esc(r)}" color="#800080">{_esc(r[:95])}</link>' for r in refs[:20]),
            styles["body_small"]))
        if len(refs) > 20:
            story.append(Paragraph(f"… and {len(refs) - 20} more.", styles["body_small"]))
        story.append(Spacer(1, 6))

    story.append(Paragraph("Glossary", styles["h3"]))
    story.append(_kv_table([
        ("Critical", "CVSS 9.0–10.0 — remediate immediately."),
        ("High", "CVSS 7.0–8.9 — remediate urgently."),
        ("Medium", "CVSS 4.0–6.9 — schedule remediation."),
        ("Low", "CVSS 0.1–3.9 — remediate opportunistically."),
        ("CVSS", "Common Vulnerability Scoring System."),
        ("CVE", "Common Vulnerabilities and Exposures identifier."),
        ("CWE", "Common Weakness Enumeration — underlying weakness class."),
        ("Risk Index", "0–100 composite score combining worst severity and finding density."),
    ], styles, key_w=26 * mm))
    return story


# ─────────────────────────────────────────────────────────────────────────
# Record filtering (unchanged behavior — informational entries excluded)
# ─────────────────────────────────────────────────────────────────────────

def _reported_only(record):
    findings = [f for f in (record.findings or [])
                if (f.get("severity_label") or "").lower() in _REPORTED_SEVERITIES]
    findings.sort(key=lambda f: (-SEVERITY_RANK.get((f.get("severity_label") or "").lower(), 0),
                                  -(f.get("cvss_score") or 0)))
    hosts = sorted({h for f in findings for h in f.get("affected_hosts", [])})
    return SimpleNamespace(
        import_id=record.import_id,
        org_id=getattr(record, "org_id", ""),
        file_name=record.file_name,
        file_format=record.file_format,
        source_tool=record.source_tool,
        status=getattr(record, "status", ""),
        total_findings=len(findings),
        unique_hosts=len(hosts),
        risk_score=record.risk_score,
        severity=record.severity,
        severity_distribution={k: (record.severity_distribution or {}).get(k, 0) for k in SEVERITY_ORDER},
        category_distribution=record.category_distribution,
        summary=record.summary,
        findings=findings,
        created_at=record.created_at,
    )


# ─────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────

_DEFAULT_COVER_LOGO_CANDIDATES = [
    "ShieldStat-Frontend/src/assets/iSecurify Logo - Full Colour - Transparent (2).png",
    "assets/isecurify-logo.png",
]
_DEFAULT_BACK_LOGO_CANDIDATES = [
    "ShieldStat-Frontend/src/assets/Allianz logo.png",
    "assets/allianz-logo.png",
]


def generate_vapt_report_pdf(
    record,
    client_name: str = None,
    client_location: str = None,
    engagement_start: str = None,
    engagement_end: str = None,
    contact_email: str = "info@isecurify.co",
    contact_phone: str = "+91 99252 00624",
    contact_website: str = "www.isecurify.co",
    *,
    version: str = "1.0",
    assessment_type: str = None,
    methodology: str = None,
    scope: str = None,
    cover_logo_path: str = None,
    back_logo_path: str = None,
) -> bytes:
    """Build the full VAPT PDF report for a stored import and return raw bytes.

    Signature-compatible with the previous generator. New keyword-only
    arguments (version, assessment_type, methodology, scope, and the two
    logo paths) are optional and default to sensible values, so existing
    call sites keep working unchanged.
    """
    raw_info_count = (record.severity_distribution or {}).get("info", 0)
    record = _reported_only(record)
    _register_fonts()
    styles = _build_styles()

    created = record.created_at or datetime.now(timezone.utc)
    client_name = client_name or getattr(record, "org_id", None) or "the client"
    engagement_start = engagement_start or created.strftime("%d %b %Y")
    engagement_end = engagement_end or created.strftime("%d %b %Y")
    assessment_date = created.strftime("%d %b %Y")
    report_title = "VAPT Security Report"

    assessment_type = assessment_type or "External & Internal Vulnerability Assessment and Penetration Testing"
    methodology = methodology or ("Grey-box testing aligned with the OWASP Testing Guide, PTES, "
                                   "and NIST SP 800-115")
    scope = scope or (client_location or "As defined in the engagement Statement of Work")
    testing_window = f"{engagement_start} – {engagement_end}"
    standards = "OWASP · CVSS · PTES · NIST"

    cover_logo = _find_logo(cover_logo_path, _DEFAULT_COVER_LOGO_CANDIDATES)
    back_logo = _find_logo(back_logo_path, _DEFAULT_BACK_LOGO_CANDIDATES)

    # ── body: TOC + all interior sections (TOC needs a two-pass build) ──
    body_buf = BytesIO()
    header_footer = _make_header_footer(report_title, client_name, version, assessment_date)
    doc = _ReportDoc(
        body_buf, header_footer, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN, topMargin=20 * mm, bottomMargin=18 * mm,
        title=f"VAPT Security Report — {record.file_name}", author="iSecurify",
    )

    story = []
    story.append(Paragraph("Table of Contents", styles["toc_title"]))
    story.append(_hr(color=PRIMARY_LIGHT, thickness=1.1, space_before=0, space_after=6))
    story.append(_build_toc(styles))
    story.append(PageBreak())

    story += _section_assessment_info(
        record, styles, assessment_type=assessment_type, methodology=methodology,
        testing_window=testing_window, scope=scope, standards=standards)
    story += _section_executive_summary(record, raw_info_count, styles)
    story += _section_findings_summary(record, styles)
    story.append(PageBreak())
    story += _section_detailed_findings(record, styles)
    story.append(PageBreak())
    story += _section_remediation_roadmap(record, styles)
    story += _section_appendix(record, styles)

    doc.multiBuild(story)
    body_buf.seek(0)

    # ── full-bleed cover + back cover, drawn separately, then merged ──
    cover_buf = _build_cover_pdf(record, client_name, report_title, version, assessment_date, cover_logo)
    back_buf = _build_back_cover_pdf(back_logo, version, assessment_date)

    writer = PdfWriter()
    for reader in (PdfReader(cover_buf), PdfReader(body_buf), PdfReader(back_buf)):
        for page in reader.pages:
            writer.add_page(page)

    out = BytesIO()
    writer.write(out)
    return out.getvalue()