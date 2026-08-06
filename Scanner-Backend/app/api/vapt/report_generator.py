"""
Professional VAPT PDF report generation (reportlab) — modern, brand-consistent
layout covering the full professional report structure:

1. Cover page               — brand mark, title, risk gauge, metadata, notice
2. Executive summary        — stat boxes, overall risk score gauge, severity
                              distribution charts (donut + bars), transparency,
                              most-critical findings
3. Scan information         — full import/scan metadata
4. Asset summary            — hosts, operating systems, finding counts
5. Vulnerability summary    — severity + category breakdown, top findings
6. Findings register        — severity chips, hosts & CVSS columns
7. Detailed findings        — severity banner, metadata, host chips,
                              Description / Solution / Resources /
                              Proof of Concept (evidence)
8. Recommended remediations — prioritized, consolidated remediation plan
9. Appendix                 — CVE register, external references, glossary
10. Methodology & compliance

Informational entries are filtered out upstream by the normalizer; all real
findings (Critical / High / Medium / Low) are included so even a clean scan
produces a meaningful report.
"""

import os
from datetime import datetime, timezone
from io import BytesIO
from types import SimpleNamespace
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.graphics.shapes import ArcPath, Drawing, String
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ─── Palette ──────────────────────────────────────────────────────────────────
PRIMARY = colors.HexColor("#4f46e5")       # indigo-600
INK = colors.HexColor("#0f172a")           # slate-900
MUTED = colors.HexColor("#64748b")         # slate-500
FAINT = colors.HexColor("#94a3b8")         # slate-400
LINE = colors.HexColor("#e2e8f0")          # slate-200
SOFT = colors.HexColor("#f8fafc")          # slate-50
CHIP_INK = colors.HexColor("#334155")      # slate-700

# Severities that appear in the PDF (informational entries never reach the
# stored report). The generator re-filters at render time (see _reported_only)
# so older stored imports render consistently with new ones.
_REPORTED_SEVERITIES = {"critical", "high", "medium", "low"}

SEVERITY_COLORS = {
    "critical": colors.HexColor("#b91c1c"),
    "high": colors.HexColor("#c2410c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#15803d"),
    "info": colors.HexColor("#64748b"),
    "none": colors.HexColor("#64748b"),
}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

_TOOL_LABELS = {"nessus": "Nessus", "openvas": "OpenVAS", "qualys": "Qualys", "generic": "Generic"}


def _tool_label(tool):
    """Human label for the detected source tool (falls back to the raw value)."""
    return _TOOL_LABELS.get((tool or "").lower(), tool or "—")

PAGE_W, PAGE_H = A4

# ─── Fonts ────────────────────────────────────────────────────────────────────
# Prefer a Unicode TrueType font (DejaVu is bundled with most Linux distros,
# Arial/Segoe UI exist on Windows); fall back to built-in Helvetica with
# latin-1 sanitization so exotic characters never crash the build.

_FONT_PATHS = [
    # DejaVu (Linux / Docker)
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
    # Windows
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "arial.ttf"),
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "arialbd.ttf"),
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "segoeui.ttf"),
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts", "segoeuib.ttf"),
    # macOS
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
    """Replace characters the built-in Helvetica font cannot render."""
    if _REGISTERED_FONT:
        return text
    return text.encode("latin-1", "replace").decode("latin-1")


def _esc(text) -> str:
    """XML-escape arbitrary finding text for Paragraphs."""
    return _xml_escape(_latin1_safe(str(text or "")))


def _darker(color, factor=0.72):
    return colors.Color(
        max(0, color.red * factor),
        max(0, color.green * factor),
        max(0, color.blue * factor),
    )


# ─── Custom flowables ─────────────────────────────────────────────────────────

class Chip(Flowable):
    """Rounded severity / host pill. Text is truncated so the pill never
    grows wider than the page frame."""

    def __init__(self, text, bg, width=None, height=5.6 * mm, font_size=7,
                 text_color=colors.white, uppercase=True, max_len=26):
        super().__init__()
        raw = (text.upper() if uppercase else text)
        if max_len and len(raw) > max_len:
            raw = raw[: max_len - 1].rstrip() + "…"
        self.text = raw
        self.bg = bg
        self.font_size = font_size
        self.text_color = text_color
        self.height = height
        self.width = width or max(height + 2 * mm, font_size * len(self.text) * 0.62 + 7 * mm)

    def wrap(self, availWidth, availHeight):
        return (self.width, self.height)

    def draw(self):
        c = self.canv
        c.setFillColor(self.bg)
        c.roundRect(0, 0, self.width, self.height, self.height / 2, stroke=0, fill=1)
        c.setFillColor(self.text_color)
        c.setFont(_font("bold"), self.font_size)
        c.drawCentredString(self.width / 2, self.height / 2 - self.font_size * 0.36, self.text)


def _risk_gauge(score, color, size=56 * mm):
    """270° donut gauge showing the 0-100 risk index."""
    d = Drawing(size, size)
    cx = cy = size / 2.0
    r = size / 2.0 - 6 * mm
    stroke = 4.2 * mm

    def arc(a0, a1, col):
        p = ArcPath()
        p.strokeColor = col
        p.strokeWidth = stroke
        p.fillColor = None
        p.strokeLineCap = 1
        p.addArc(cx, cy, r, a0, a1)
        return p

    d.add(arc(300, 600, LINE))
    s = min(100, max(0, int(score or 0)))
    if s > 0:
        d.add(arc(300, 300 + 300 * s / 100.0, color))
    d.add(String(cx, cy + 5, str(s), fontName=_font("bold"), fontSize=30,
                 fillColor=INK, textAnchor="middle"))
    d.add(String(cx, cy - 10, "RISK INDEX", fontName=_font("bold"), fontSize=7,
                 fillColor=MUTED, textAnchor="middle"))
    return d


def _severity_donut(dist, size=46 * mm):
    """360° donut chart of the severity distribution with a center total."""
    total = sum((dist or {}).values()) or 1
    d = Drawing(size, size)
    cx = cy = size / 2.0
    r = size / 2.0 - 5 * mm
    stroke = 4.6 * mm

    def arc(a0, a1, col):
        p = ArcPath()
        p.strokeColor = col
        p.strokeWidth = stroke
        p.fillColor = None
        p.strokeLineCap = 1
        p.addArc(cx, cy, r, a0, a1)
        return p

    d.add(arc(90, 450, LINE))
    start = 90.0
    for label in SEVERITY_ORDER:
        count = (dist or {}).get(label, 0)
        if count <= 0:
            continue
        sweep = 360.0 * count / total
        d.add(arc(start, start + sweep, SEVERITY_COLORS.get(label)))
        start += sweep
    d.add(String(cx, cy + 6, str(total), fontName=_font("bold"), fontSize=22,
                 fillColor=INK, textAnchor="middle"))
    d.add(String(cx, cy - 9, "FINDINGS", fontName=_font("bold"), fontSize=6.5,
                 fillColor=MUTED, textAnchor="middle"))
    return d


# ─── Header / footer ──────────────────────────────────────────────────────────

def _draw_header_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.6)
    canvas.line(18 * mm, PAGE_H - 14 * mm, PAGE_W - 18 * mm, PAGE_H - 14 * mm)

    canvas.setFont(_font("bold"), 8)
    canvas.setFillColor(PRIMARY)
    canvas.drawString(18 * mm, PAGE_H - 12 * mm, "iSecurify · VAPT Security Report")
    canvas.setFont(_font(), 8)
    canvas.setFillColor(FAINT)
    canvas.drawRightString(PAGE_W - 18 * mm, PAGE_H - 12 * mm, "Authorized Use Only")

    canvas.setStrokeColor(LINE)
    canvas.line(18 * mm, 15 * mm, PAGE_W - 18 * mm, 15 * mm)
    canvas.setFont(_font(), 8)
    canvas.setFillColor(FAINT)
    canvas.drawString(18 * mm, 11.5 * mm, "Generated by iSecurify")
    canvas.drawRightString(PAGE_W - 18 * mm, 11.5 * mm, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


# ─── Styles ───────────────────────────────────────────────────────────────────

def _build_styles():
    base = getSampleStyleSheet()
    styles = {
        "brand": ParagraphStyle(
            "brand", parent=base["Normal"], fontName=_font("bold"),
            fontSize=13, textColor=PRIMARY, leading=16,
        ),
        "cover_subtitle": ParagraphStyle(
            "cover_subtitle", parent=base["Normal"], fontName=_font(),
            fontSize=10.5, textColor=MUTED, leading=16,
        ),
        "cover_title": ParagraphStyle(
            "cover_title", parent=base["Title"], fontName=_font("bold"),
            fontSize=34, textColor=INK, leading=40,
            spaceBefore=6, spaceAfter=8,
        ),
        "cover_meta_key": ParagraphStyle(
            "cover_meta_key", parent=base["Normal"], fontName=_font("bold"),
            fontSize=9, textColor=PRIMARY, leading=15,
        ),
        "cover_meta_value": ParagraphStyle(
            "cover_meta_value", parent=base["Normal"], fontName=_font(),
            fontSize=9, textColor=MUTED, leading=15,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontName=_font("bold"),
            fontSize=16, textColor=INK, spaceBefore=4,
            spaceAfter=4, leading=20,
        ),
        "h3": ParagraphStyle(
            "h3", parent=base["Heading3"], fontName=_font("bold"),
            fontSize=11, textColor=CHIP_INK, spaceBefore=8,
            spaceAfter=4, leading=15,
        ),
        "h4": ParagraphStyle(
            "h4", parent=base["Heading4"], fontName=_font("bold"),
            fontSize=9.5, textColor=PRIMARY, spaceBefore=6,
            spaceAfter=3, leading=13,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName=_font(),
            fontSize=9.5, textColor=colors.HexColor("#1e293b"), leading=14.5,
            alignment=TA_LEFT,
        ),
        "body_small": ParagraphStyle(
            "body_small", parent=base["Normal"], fontName=_font(),
            fontSize=8.5, textColor=MUTED, leading=12.5,
        ),
        "section_label": ParagraphStyle(
            "section_label", parent=base["Normal"], fontName=_font("bold"),
            fontSize=8, textColor=PRIMARY, leading=12,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Code"], fontName="Courier", fontSize=7.6,
            leading=11, textColor=INK,
            backColor=colors.HexColor("#f1f5f9"),
            borderPadding=6, spaceBefore=2, spaceAfter=2,
        ),
        "center": ParagraphStyle(
            "center", parent=base["Normal"], fontName=_font(), fontSize=8.5,
            textColor=MUTED, alignment=TA_CENTER,
        ),
        "big_number": ParagraphStyle(
            "big_number", parent=base["Normal"], fontName=_font("bold"),
            fontSize=20, textColor=INK, alignment=TA_CENTER, leading=24,
        ),
        "stat_label": ParagraphStyle(
            "stat_label", parent=base["Normal"], fontName=_font("bold"),
            fontSize=7, textColor=MUTED, alignment=TA_CENTER, leading=10,
        ),
    }
    return styles


# ─── Building blocks ──────────────────────────────────────────────────────────

def _section_header(story, styles, label, title):
    story.append(Spacer(1, 6))
    story.append(Paragraph(label.upper(), styles["section_label"]))
    story.append(Paragraph(_esc(title), styles["h2"]))
    story.append(HRFlowable(width="100%", thickness=1, color=LINE,
                            spaceBefore=0, spaceAfter=8))


def _kv_table(rows, styles, first_col_width=46 * mm):
    data = [[Paragraph(_esc(k), styles["cover_meta_key"]),
             Paragraph(_esc(v), styles["cover_meta_value"])] for k, v in rows]
    table = Table(data, colWidths=[first_col_width, None], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),  # indigo-50
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, SOFT]),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#f1f5f9")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _notice_box(story, styles, text, bg="#fef2f2", border="#fca5a5"):
    box = Table(
        [[Paragraph(text, styles["body_small"])]],
        colWidths=[PAGE_W - 50 * mm],
    )
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg)),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor(border)),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(box)


# ─── 1. Cover page ────────────────────────────────────────────────────────────

def _cover_story(record, styles):
    story = []
    story.append(Spacer(1, 24 * mm))

    story.append(Paragraph("ISECURIFY", styles["brand"]))
    story.append(Spacer(1, 3))
    story.append(Paragraph(
        "Vulnerability Assessment &amp; Penetration Testing",
        styles["cover_subtitle"],
    ))
    story.append(Spacer(1, 22))

    story.append(Paragraph("VAPT Security Report", styles["cover_title"]))
    story.append(Paragraph(
        "Normalized vulnerability findings imported from a scanner export — "
        "Critical to Low risk, scored and prioritized for remediation.",
        styles["cover_subtitle"],
    ))
    story.append(Spacer(1, 20))

    # Risk panel: gauge + severity snapshot
    summary = record.summary or {}
    severity_label = (record.severity or "none").lower()
    sev_color = SEVERITY_COLORS.get(severity_label, SEVERITY_COLORS["info"])
    snapshot = Table([
        [Paragraph(_esc(f"Overall {record.severity.title() if record.severity else '—'} risk"),
                   ParagraphStyle("snap_t", parent=styles["body"], fontName=_font("bold"),
                                  fontSize=13, textColor=sev_color, leading=16))],
        [Paragraph(f"<b>{record.total_findings}</b> findings across "
                   f"<b>{record.unique_hosts}</b> hosts",
                   styles["cover_subtitle"])],
        [Paragraph(f"{summary.get('raw_findings_parsed', 0)} raw entries parsed",
                   styles["body_small"])],
    ], colWidths=[72 * mm])
    snapshot.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 16),
        ("RIGHTPADDING", (0, 0), (-1, -1), 16),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, sev_color),
    ]))

    risk_panel = Table(
        [[_risk_gauge(record.risk_score, sev_color), snapshot]],
        colWidths=[62 * mm, None],
        hAlign="CENTER",
    )
    risk_panel.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(risk_panel)
    story.append(Spacer(1, 22))

    story.append(_kv_table([
        ("Import ID", str(record.import_id)[:8]),
        ("Source File", record.file_name),
        ("Format", f"{_tool_label(record.source_tool)} · {record.file_format.upper()}"),
        ("Import Date", record.created_at.strftime("%d %b %Y, %H:%M UTC") if record.created_at else "—"),
        ("Reported Findings", str(record.total_findings)),
        ("Unique Hosts", str(record.unique_hosts)),
        ("Risk Score", f"{record.risk_score} / 100"),
        ("Overall Severity", (record.severity or "—").title()),
        ("Raw Entries Parsed", str(summary.get("raw_findings_parsed") or 0)),
        ("Info Excluded", str(summary.get("excluded_info_findings") or 0)),
    ], styles))
    story.append(Spacer(1, 20))

    _notice_box(story, styles,
        "<b>Authorized Use Only</b><br/>This report contains confidential "
        "information about your organization's security posture and is "
        "intended solely for authorized personnel. Do not distribute "
        "outside your organization without written approval. Findings are "
        "normalized from an existing scanner export; iSecurify performed no "
        "active testing.")
    story.append(PageBreak())
    return story


# ─── Shared components ────────────────────────────────────────────────────────

def _stat_boxes(record, styles):
    summary = record.summary or {}
    severity_label = (record.severity or "none").lower()
    sev_color = SEVERITY_COLORS.get(severity_label, SEVERITY_COLORS["info"])
    boxes = [
        (record.total_findings, "Findings", sev_color),
        (record.unique_hosts, "Unique hosts", PRIMARY),
        ((record.severity or "—").title(), "Overall severity", CHIP_INK),
        (summary.get("raw_findings_parsed") or 0, "Raw entries parsed", FAINT),
    ]
    cells = []
    for value, label, color in boxes:
        inner = Table([
            [Paragraph(_esc(str(value)), styles["big_number"])],
            [Paragraph(label.upper(), styles["stat_label"])],
        ], colWidths=[None])
        inner.setStyle(TableStyle([
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        cells.append(inner)
    table = Table([cells], colWidths=[None, None, None, None], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SOFT),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEABOVE", (0, 0), (0, 0), 2.2, sev_color),
        ("LINEABOVE", (1, 0), (1, 0), 2.2, PRIMARY),
        ("LINEABOVE", (2, 0), (2, 0), 2.2, CHIP_INK),
        ("LINEABOVE", (3, 0), (3, 0), 2.2, FAINT),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    return table


def _severity_bars(dist, styles):
    rows = []
    total = sum((dist or {}).values()) or 1
    for label in SEVERITY_ORDER:
        count = (dist or {}).get(label, 0)
        color = SEVERITY_COLORS.get(label)
        pct = round(100 * count / total)
        name = Paragraph(_esc(label.title()), styles["body_small"])
        bar_w = max(0, int(96 * mm * count / total))
        fill = Table([[""]], colWidths=[bar_w or 0.1, ])
        fill.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("TOPPADDING", (0, 0), (-1, -1), 3.6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.6),
        ]))
        rest = Table([[""]], colWidths=[max(0.1, 96 * mm - bar_w), ])
        rest.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SOFT),
            ("TOPPADDING", (0, 0), (-1, -1), 3.6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.6),
        ]))
        count_style = ParagraphStyle(
            "count", parent=styles["body_small"], fontName=_font("bold"),
            alignment=TA_RIGHT, textColor=CHIP_INK,
        )
        row = Table([[name, fill, rest, Paragraph(f"{count}  ({pct}%)", count_style)]],
                    colWidths=[24 * mm, None, None, 26 * mm])
        row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ]))
        rows.append(row)
    return Table([[r] for r in rows], hAlign="LEFT")


def _chart_caption(styles, text):
    return Paragraph(text, ParagraphStyle(
        "cap", parent=styles["body_small"], alignment=TA_CENTER,
        fontSize=7.5, textColor=FAINT, spaceBefore=2,
    ))


def _top_findings_table(findings, styles, limit=5):
    rows = []
    for f in findings[:limit]:
        sev = (f.get("severity_label") or "info").lower()
        col = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
        rows.append([
            Chip(sev, col, height=5 * mm, font_size=6.5),
            Paragraph(f'<b>{_esc(f.get("title") or "Untitled")}</b>'
                      f'<br/><font color="#94a3b8" size="7.5">'
                      f'{f.get("host_count", 0)} host(s)'
                      f'{" · CVSS " + str(f.get("cvss_score")) if f.get("cvss_score") is not None else ""}'
                      f'</font>', styles["body_small"]),
        ])
    table = Table(rows, colWidths=[24 * mm, None], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


# ─── 2. Executive summary ─────────────────────────────────────────────────────

def _executive_summary(record, styles):
    story = []
    _section_header(story, styles, "Executive Summary", "Summary")
    summary = record.summary or {}
    dist = record.severity_distribution or {}
    findings = record.findings or []

    story.append(Paragraph(
        f"This report presents <b>{record.total_findings}</b> confirmed "
        f"vulnerabilit{'y' if record.total_findings == 1 else 'ies'} across "
        f"<b>{record.unique_hosts}</b> unique host{'s' if record.unique_hosts != 1 else ''} "
        f"extracted from <b>{_esc(record.file_name)}</b>. Informational entries "
        "are excluded automatically so the report focuses on real, actionable "
        "risk.", styles["body"],
    ))
    story.append(Spacer(1, 12))
    story.append(_stat_boxes(record, styles))
    story.append(Spacer(1, 16))

    # Overall risk score + severity distribution charts
    severity_label = (record.severity or "none").lower()
    sev_color = SEVERITY_COLORS.get(severity_label, SEVERITY_COLORS["info"])
    gauge_cell = [_risk_gauge(record.risk_score, sev_color),
                  _chart_caption(styles, "Overall risk score (0–100)")]
    donut_cell = [_severity_donut(dist),
                  _chart_caption(styles, "Severity distribution")]
    charts = Table([[gauge_cell, donut_cell]], colWidths=[None, None], hAlign="CENTER")
    charts.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(charts)
    story.append(Spacer(1, 14))
    story.append(Paragraph("Severity distribution — detail", styles["h3"]))
    story.append(_severity_bars(dist, styles))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Transparency", styles["h3"]))
    story.append(Paragraph(
        f"<b>{summary.get('raw_findings_parsed', 0)}</b> raw entries were "
        f"parsed; <b>{summary.get('excluded_info_findings', 0)}</b> "
        f"informational findings were excluded; <b>{len(findings)}</b> real "
        "findings remain.", styles["body"],
    ))

    critical = [f for f in findings if (f.get("severity_label") or "").lower() == "critical"][:5]
    if not critical:
        critical = findings[:5]
    if critical:
        story.append(Spacer(1, 8))
        story.append(Paragraph("Most critical findings", styles["h3"]))
        story.append(_top_findings_table(critical, styles))

    story.append(PageBreak())
    return story


# ─── 3. Scan information ──────────────────────────────────────────────────────

def _scan_information(record, styles):
    story = []
    _section_header(story, styles, "Scan Information", "Scan Information")
    summary = record.summary or {}
    generated = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")

    left = _kv_table([
        ("Import ID", str(record.import_id)[:8]),
        ("Source File", record.file_name),
        ("File Format", record.file_format.upper()),
        ("Source Tool", _tool_label(record.source_tool)),
        ("Import Date", record.created_at.strftime("%d %b %Y, %H:%M UTC") if record.created_at else "—"),
        ("Report Generated", generated),
    ], styles, first_col_width=40 * mm)

    right = _kv_table([
        ("Reported Findings", str(record.total_findings)),
        ("Unique Hosts", str(record.unique_hosts)),
        ("Raw Entries Parsed", str(summary.get("raw_findings_parsed") or 0)),
        ("Info Entries Excluded", str(summary.get("excluded_info_findings") or 0)),
        ("Overall Risk Score", f"{record.risk_score} / 100"),
        ("Overall Severity", (record.severity or "—").title()),
    ], styles, first_col_width=46 * mm)

    grid = Table([[left, right]], colWidths=[None, None], hAlign="LEFT")
    grid.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 10),
    ]))
    story.append(grid)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Scope &amp; method", styles["h3"]))
    story.append(Paragraph(
        "This report is generated from a scanner export file that was uploaded "
        "to iSecurify. Every finding was parsed, normalized (severity mapping "
        "and auto-categorization), and scored. The same issue found on "
        "multiple hosts is consolidated into one entry listing all affected "
        "addresses. No active scanning or external data collection is "
        "performed by this engine.", styles["body"],
    ))
    story.append(PageBreak())
    return story


# ─── 4. Asset summary (hosts + operating systems) ─────────────────────────────

def _host_assets(record) -> list[dict]:
    """Return [{host, os, finding_count}] — from stored summary, falling back
    to deriving the list from the findings of older imports."""
    # Derived per-host counts from the consolidated findings.
    counts: dict[str, int] = {}
    for f in (record.findings or []):
        for host in f.get("affected_hosts", []):
            counts[host] = counts.get(host, 0) + 1

    assets: dict[str, dict] = {}
    summary_hosts = (record.summary or {}).get("hosts")
    stored = isinstance(summary_hosts, list) and bool(summary_hosts)
    if stored:
        # Stored counts are already correct for new imports; keep them as-is.
        for h in summary_hosts:
            if isinstance(h, dict) and h.get("host"):
                assets[h["host"]] = {
                    "host": h["host"],
                    "os": (h.get("os") or "").strip(),
                    "finding_count": int(h.get("finding_count") or counts.get(h["host"], 0)),
                }
    # Any host missing from the stored list (old imports, or defensive) gets a
    # derived count.
    for host in counts:
        if host not in assets:
            assets[host] = {"host": host, "os": "", "finding_count": counts[host]}
    return sorted(assets.values(), key=lambda a: (-a["finding_count"], a["host"].lower()))


def _asset_summary(record, styles):
    story = []
    _section_header(story, styles, "Assets", "Asset Summary")
    assets = _host_assets(record)

    if not assets:
        story.append(Paragraph("No host data was captured in the export.", styles["body"]))
        story.append(PageBreak())
        return story

    # OS breakdown chips/line
    os_counts: dict[str, int] = {}
    for a in assets:
        key = (a["os"] or "").strip() or "Unknown"
        os_counts[key] = os_counts.get(key, 0) + 1
    os_text = "&nbsp;·&nbsp;".join(
        f"<b>{_esc(k)}</b>: {v}" for k, v in
        sorted(os_counts.items(), key=lambda kv: -kv[1])
    )
    story.append(Paragraph(f"Operating systems — {os_text}", styles["body"]))
    story.append(Spacer(1, 8))

    data = [[Paragraph("<b>#</b>", styles["body_small"]),
             Paragraph("<b>Host / IP</b>", styles["body_small"]),
             Paragraph("<b>Operating System</b>", styles["body_small"]),
             Paragraph("<b>Findings</b>", styles["body_small"])]]
    for i, asset in enumerate(assets, start=1):
        data.append([
            Paragraph(_esc(str(i)), styles["body_small"]),
            Paragraph(_esc(asset["host"]), styles["body_small"]),
            Paragraph(_esc(asset["os"] or "Not reported"), styles["body_small"]),
            Paragraph(_esc(str(asset["finding_count"])), styles["body_small"]),
        ])
    table = Table(data, colWidths=[12 * mm, 52 * mm, None, 24 * mm], repeatRows=1,
                  hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(PageBreak())
    return story


# ─── 5. Vulnerability summary ─────────────────────────────────────────────────

def _vulnerability_summary(record, styles):
    story = []
    _section_header(story, styles, "Vulnerability Summary", "Vulnerability Summary")
    dist = record.severity_distribution or {}
    cat_dist = record.category_distribution or {}
    findings = record.findings or []

    def dist_table(pairs, value_label):
        total = sum(v for _, v in pairs) or 1
        data = [[Paragraph("<b>Category</b>", styles["body_small"]),
                 Paragraph(f"<b>{value_label}</b>", styles["body_small"]),
                 Paragraph("<b>Share</b>", styles["body_small"])]]
        for label, count in pairs:
            data.append([
                Paragraph(_esc(label), styles["body_small"]),
                Paragraph(_esc(str(count)), styles["body_small"]),
                Paragraph(f"{round(100 * count / total)}%", styles["body_small"]),
            ])
        t = Table(data, colWidths=[None, 24 * mm, 20 * mm], hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]))
        return t

    sev_pairs = [(s.title(), dist.get(s, 0)) for s in SEVERITY_ORDER]
    cat_pairs = sorted(cat_dist.items(), key=lambda kv: -kv[1])

    grid = Table(
        [[[Paragraph("By severity", styles["h3"]), dist_table(sev_pairs, "Findings")],
          [Paragraph("By category", styles["h3"]), dist_table(cat_pairs, "Findings")]]],
        colWidths=[None, None], hAlign="LEFT",
    )
    grid.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (0, 0), 0),
        ("RIGHTPADDING", (1, 0), (1, 0), 0),
        ("LEFTPADDING", (1, 0), (1, 0), 10),
    ]))
    story.append(grid)
    story.append(Spacer(1, 12))

    if findings:
        story.append(Paragraph("Top findings", styles["h3"]))
        story.append(_top_findings_table(findings, styles, limit=6))

    story.append(PageBreak())
    return story


# ─── 6. Findings register ─────────────────────────────────────────────────────

def _findings_register(record, styles):
    story = []
    _section_header(story, styles, "Findings", "Findings Register")
    findings = record.findings or []

    data = [[
        Paragraph("<b>#</b>", styles["body_small"]),
        Paragraph("<b>Severity</b>", styles["body_small"]),
        Paragraph("<b>Title</b>", styles["body_small"]),
        Paragraph("<b>Hosts</b>", styles["body_small"]),
        Paragraph("<b>CVSS</b>", styles["body_small"]),
        Paragraph("<b>Category</b>", styles["body_small"]),
    ]]
    for f in findings:
        sev = (f.get("severity_label") or "info").lower()
        color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
        data.append([
            Paragraph(_esc(f.get("id", "")), styles["body_small"]),
            Chip(sev, color, height=5 * mm, font_size=6.5),
            Paragraph(_esc(f.get("title", "")), styles["body_small"]),
            Paragraph(_esc(str(f.get("host_count", 0))), styles["body_small"]),
            Paragraph(_esc(str(f.get("cvss_score") or "—")), styles["body_small"]),
            Paragraph(_esc(f.get("category", "")), styles["body_small"]),
        ])

    table = Table(data, colWidths=[12 * mm, 24 * mm, None, 14 * mm, 16 * mm, 28 * mm],
                  repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(PageBreak())
    return story


# ─── 7. Detailed findings (with evidence) ─────────────────────────────────────

def _finding_banner(finding, index):
    sev = (finding.get("severity_label") or "info").lower()
    color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    dark = _darker(color)

    number = Paragraph(
        f"<b>F{index:03d}</b>",
        ParagraphStyle("n", fontName=_font("bold"), fontSize=15,
                       textColor=colors.white, alignment=TA_CENTER),
    )
    title = Paragraph(
        _esc(finding.get("title") or "Untitled finding"),
        ParagraphStyle("t", fontName=_font("bold"), fontSize=11,
                       leading=14, textColor=colors.white),
    )
    parts = [sev.title() + " risk"]
    host_count = finding.get("host_count") or 0
    parts.append(f"{host_count} host{'s' if host_count != 1 else ''}")
    if finding.get("cvss_score") is not None:
        parts.append(f"CVSS {finding['cvss_score']}")
    if finding.get("category"):
        parts.append(finding["category"])
    sub = Paragraph(
        _esc(" · ".join(parts)),
        ParagraphStyle("s", fontName=_font(), fontSize=8,
                       textColor=colors.HexColor("#fff7ed")),
    )

    banner = Table([[number, [title, sub]]], colWidths=[26 * mm, None], hAlign="LEFT")
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), dark),
        ("BACKGROUND", (1, 0), (1, 0), color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (1, 0), (1, 0), 12),
        ("RIGHTPADDING", (1, 0), (1, 0), 12),
        ("TOPPADDING", (1, 0), (1, 0), 8),
        ("BOTTOMPADDING", (1, 0), (1, 0), 8),
    ]))
    return banner


def _finding_detail(finding, index, styles):
    story = []
    story.append(_finding_banner(finding, index))
    story.append(Spacer(1, 12))

    # Deliberately kept lean: Risk, CVSS Score, Affected Hosts, Host Count,
    # Port (and Category in the banner) — CVSS Vector / Service / Protocol /
    # Plugin ID were removed from the table by request.
    metadata = [("Risk", (finding.get("severity_label") or "info").title())]
    cvss = finding.get("cvss_score")
    metadata.append(("CVSS Score", str(cvss) if cvss is not None else "—"))
    metadata.append(("Affected Hosts",
                     ", ".join(finding.get("affected_hosts", [])) or "—"))
    metadata.append(("Host Count", str(finding.get("host_count", 0))))
    if finding.get("port") is not None:
        metadata.append(("Port", str(finding["port"])))

    meta_table = _kv_table(metadata, styles)
    meta_table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)

    hosts = finding.get("affected_hosts", [])
    if hosts:
        story.append(Spacer(1, 8))
        chips = [Chip(h, CHIP_INK, height=5 * mm, font_size=6.5, max_len=20)
                 for h in hosts[:8]]
        if len(hosts) > 8:
            chips.append(Chip(f"+{len(hosts) - 8} more", FAINT, height=5 * mm,
                              font_size=6.5, max_len=None))
        host_row = Table([chips], colWidths=[None] * len(chips), hAlign="LEFT")
        host_row.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ]))
        story.append(host_row)

    story.append(Spacer(1, 8))
    story.append(Paragraph("Description", styles["h3"]))
    story.append(Paragraph(
        _esc(finding.get("description") or finding.get("synopsis")
             or "No description available."),
        styles["body"],
    ))

    solution = finding.get("solution")
    if solution:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Solution", styles["h3"]))
        story.append(Paragraph(_esc(solution), styles["body"]))

    references = []
    for cve in finding.get("cves", []):
        references.append(
            f'<link href="https://nvd.nist.gov/vuln/detail/{_esc(cve)}" color="#4f46e5">'
            f'{_esc(cve)}</link> (NVD)'
        )
    for ref in finding.get("references", []):
        if ref.startswith(("http://", "https://")):
            references.append(
                f'<link href="{_esc(ref)}" color="#4f46e5">{_esc(ref[:90])}</link>'
            )
        else:
            references.append(_esc(ref))
    if references:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Resources", styles["h3"]))
        story.append(Paragraph("<br/>".join(f"• {r}" for r in references), styles["body"]))

    evidence = (finding.get("evidence") or "").strip()
    if evidence:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Evidence", styles["h3"]))
        lines = evidence.splitlines()
        story.append(Paragraph(
            "<br/>".join(_esc(line) for line in lines[:60]),
            styles["mono"],
        ))
        if len(lines) > 60:
            story.append(Paragraph(
                f"… ({len(lines) - 60} more lines truncated)",
                styles["body_small"],
            ))
    else:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Evidence", styles["h3"]))
        story.append(Paragraph(
            "No scanner output was captured for this finding in the export.",
            styles["body_small"],
        ))
    return story


# ─── 8. Recommended remediations ──────────────────────────────────────────────

def _remediations(record, styles):
    story = []
    _section_header(story, styles, "Remediation", "Recommended Remediations")

    story.append(Paragraph(
        "Remediation should follow a risk-based approach: resolve <b>Critical</b> "
        "and <b>High</b> findings first, then Medium, then Low. The steps below "
        "are consolidated from the scanner's remediation guidance for the "
        "findings in this report.", styles["body"],
    ))
    story.append(Spacer(1, 10))

    by_sev: dict[str, list[tuple[str, str]]] = {}
    for f in (record.findings or []):
        sev = (f.get("severity_label") or "info").lower()
        if sev not in SEVERITY_ORDER:
            continue
        sol = (f.get("solution") or "").strip()
        if sol:
            by_sev.setdefault(sev, []).append(((f.get("title") or "").strip(), sol))

    any_plan = False
    for sev in SEVERITY_ORDER:
        items = by_sev.get(sev)
        if not items:
            continue
        seen: set[str] = set()
        unique: list[tuple[str, str]] = []
        for title, sol in items:
            key = sol.lower()[:200]
            if key in seen:
                continue
            seen.add(key)
            unique.append((title, sol))
        if not unique:
            continue
        any_plan = True

        color = SEVERITY_COLORS.get(sev)
        header = Table(
            [[Chip(f"{sev.title()} — {len(unique)} step{'s' if len(unique) != 1 else ''}",
                   color, height=5.6 * mm, font_size=7, max_len=42),
              Paragraph(
                  "Address these before moving to lower-severity items.",
                  styles["body_small"])]],
            colWidths=[None, None], hAlign="LEFT",
        )
        header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(header)
        story.append(Spacer(1, 4))

        for i, (title, sol) in enumerate(unique[:8], start=1):
            story.append(Paragraph(
                f"{i}. <b>{_esc(title)}</b>", styles["h4"],
            ))
            story.append(Paragraph(_esc(sol), styles["body"]))
            story.append(Spacer(1, 5))
        story.append(Spacer(1, 6))

    if not any_plan:
        story.append(Paragraph(
            "The source export did not include remediation guidance for any "
            "finding. Refer to the per-finding Solution sections, or re-export "
            "the scan with remediation details enabled.", styles["body"],
        ))

    story.append(PageBreak())
    return story


# ─── 9. Appendix (CVEs, references, glossary) ─────────────────────────────────

def _appendix(record, styles):
    story = []
    _section_header(story, styles, "Appendix", "Appendix")
    findings = record.findings or []

    # Appendix A — CVE register
    story.append(Paragraph("Appendix A — CVE Register", styles["h3"]))
    cve_map: dict[str, list[str]] = {}
    for f in findings:
        for cve in f.get("cves", []):
            cve_map.setdefault(cve, []).append(f.get("id", ""))
    if cve_map:
        data = [[Paragraph("<b>CVE</b>", styles["body_small"]),
                 Paragraph("<b>Linked Finding(s)</b>", styles["body_small"])]]
        for cve, ids in sorted(cve_map.items()):
            link = (f'<link href="https://nvd.nist.gov/vuln/detail/{_esc(cve)}" '
                    f'color="#4f46e5">{_esc(cve)}</link>')
            data.append([
                Paragraph(link, styles["body_small"]),
                Paragraph(_esc(", ".join(ids)), styles["body_small"]),
            ])
        table = Table(data, colWidths=[58 * mm, None], repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ]))
        story.append(table)
    else:
        story.append(Paragraph(
            "No CVE identifiers were included in the source export.",
            styles["body_small"],
        ))
    story.append(Spacer(1, 8))

    # Appendix B — External references
    story.append(Paragraph("Appendix B — External References", styles["h3"]))
    refs: list[str] = []
    for f in findings:
        for ref in f.get("references", []):
            if ref and ref.startswith(("http://", "https://")) and ref not in refs:
                refs.append(ref)
    if refs:
        story.append(Paragraph(
            "<br/>".join(
                f'• <link href="{_esc(r)}" color="#4f46e5">{_esc(r[:110])}</link>'
                for r in refs[:40]
            ), styles["body"],
        ))
        if len(refs) > 40:
            story.append(Paragraph(
                f"… and {len(refs) - 40} more.", styles["body_small"],
            ))
    else:
        story.append(Paragraph(
            "No external references were included in the source export.",
            styles["body_small"],
        ))
    story.append(Spacer(1, 8))

    # Appendix C — Glossary
    story.append(Paragraph("Appendix C — Glossary", styles["h3"]))
    story.append(_kv_table([
        ("Critical", "CVSS 9.0–10.0 — remotely or locally exploitable with severe "
                     "impact; remediate immediately."),
        ("High", "CVSS 7.0–8.9 — significant impact; prioritize for remediation."),
        ("Medium", "CVSS 4.0–6.9 — moderate risk; schedule remediation."),
        ("Low", "CVSS 0.1–3.9 — limited impact; remediate opportunistically."),
        ("CVSS", "Common Vulnerability Scoring System — the standardized 0–10 "
                 "base score for a vulnerability's severity."),
        ("CVE", "Common Vulnerabilities and Exposures — public identifiers for "
                "known vulnerabilities (e.g. CVE-2021-44228)."),
        ("Risk Index", "The report's 0–100 score: 18 × worst-severity rank plus "
                       "10 × average severity density, capped at 100."),
        ("Evidence", "Scanner output captured for a finding that demonstrates "
                     "the vulnerability (proof of concept)."),
        ("Consolidation", "The same issue found on multiple hosts is merged into "
                          "one entry listing all affected addresses."),
        ("Category", "Auto-classified area of the finding — Web App, TLS/SSL, "
                     "DNS, Network, Mail Security, OS/Host, Application."),
    ], styles))
    story.append(Spacer(1, 8))
    _notice_box(story, styles,
        "<b>Authorized Use Only</b> — Confidential. Distribution of this "
        "report outside your organization is prohibited without written "
        "approval.")
    story.append(PageBreak())
    return story


# ─── 10. Methodology & compliance ─────────────────────────────────────────────

def _methodology(record, styles):
    story = []
    _section_header(story, styles, "About", "Methodology & Compliance")

    story.append(Paragraph("How this report was produced", styles["h3"]))
    story.append(Paragraph(
        "The VAPT import engine passively reads a scanner export file (.nessus / "
        ".xml / .csv / .xlsx), normalizes every finding (severity mapping, "
        "auto-categorization), and excludes informational entries so the "
        "report focuses on real vulnerabilities. The same issue found on "
        "multiple hosts is consolidated into a single entry with a full list of "
        "affected addresses. No active scanning, probing, or external data "
        "collection is performed by this engine.", styles["body"],
    ))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Severity &amp; risk index", styles["h3"]))
    story.append(Paragraph(
        "Severity follows the CVSS-based scale (Critical / High / Medium / Low). "
        "The risk index (0-100) anchors to the worst severity present and "
        "increases with the density of high-severity findings.", styles["body"],
    ))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Compliance", styles["h3"]))
    story.append(Paragraph(
        "This report is intended to support internal remediation and compliance "
        "reporting (e.g. PCI-DSS, SOC 2, ISO 27001) but is <b>not</b> a formal "
        "compliance attestation. Retain the original scanner export for audit "
        "purposes.", styles["body"],
    ))
    story.append(Spacer(1, 8))

    _notice_box(story, styles,
        "<b>Authorized Use Only</b> — Confidential. Distribution of this "
        "report outside your organization is prohibited without written "
        "approval.")
    return story


# ─── Public entry point ───────────────────────────────────────────────────────

def _reported_only(record):
    """Return a record-like view limited to reported severities (C/H/M/L).

    Imports stored before the current filters may still contain informational
    findings in their JSON; this strips them for rendering so every PDF (old and
    new) shows only the reported severities.
    """
    findings = [
        f for f in (record.findings or [])
        if (f.get("severity_label") or "").lower() in _REPORTED_SEVERITIES
    ]
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
        severity_distribution={
            k: (record.severity_distribution or {}).get(k, 0)
            for k in SEVERITY_ORDER
        },
        category_distribution=record.category_distribution,
        summary=record.summary,
        findings=findings,
        created_at=record.created_at,
    )


def generate_vapt_report_pdf(record) -> bytes:
    """Build the full VAPT PDF report for a stored import and return raw bytes."""
    record = _reported_only(record)
    _register_fonts()
    styles = _build_styles()

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=22 * mm,
        bottomMargin=20 * mm,
        title=f"VAPT Security Report — {record.file_name}",
        author="iSecurify",
    )

    story = []
    story += _cover_story(record, styles)          # 1. Cover
    story += _executive_summary(record, styles)    # 2. Exec summary (risk + charts)
    story += _scan_information(record, styles)     # 3. Scan information
    story += _asset_summary(record, styles)        # 4. Asset summary (hosts + OS)
    story += _vulnerability_summary(record, styles)  # 5. Vulnerability summary
    story += _findings_register(record, styles)    # 6. Findings register
    for index, finding in enumerate(record.findings or [], start=1):
        story.append(PageBreak())
        story += _finding_detail(finding, index, styles)  # 7. Details + evidence
    story += _remediations(record, styles)         # 8. Recommended remediations
    story += _appendix(record, styles)             # 9. Appendix
    story += _methodology(record, styles)          # 10. Methodology & compliance

    doc.build(story, onFirstPage=_draw_header_footer, onLaterPages=_draw_header_footer)
    return buffer.getvalue()
