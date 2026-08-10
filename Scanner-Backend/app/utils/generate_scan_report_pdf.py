from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, inch
from reportlab.graphics import renderPDF
from reportlab.platypus import (
    BaseDocTemplate, Frame, Image, NextPageTemplate, PageTemplate,
    Paragraph, Spacer, Table, TableStyle, PageBreak,
)


_APP_ROOT = Path(__file__).resolve().parent.parent
HERO_LOGO_PATH = _APP_ROOT / "assets" / "logo.svg"
if not HERO_LOGO_PATH.exists():
    _REPO_ROOT = Path(__file__).resolve().parents[3]
    HERO_LOGO_PATH = _REPO_ROOT / "ShieldStat-Frontend" / "src" / "assets" / "logo.svg"

# Raster fallback used when the SVG can't be parsed (e.g. svglib missing).
RASTER_LOGO_PATH = _APP_ROOT / "assets" / "isecurify_logo.png"


# Brand palette, sampled from the iSecurify logo (the wordmark/icon are pure
# #800080). The cover/back pages use a clean white background with the same
# dark body text as the inner pages, so the whole report reads consistently.
BRAND_PURPLE = colors.HexColor("#800080")
BRAND_PURPLE_DARK = colors.HexColor("#5b005b")
COVER_BG = colors.HexColor("#FFFFFF")
INDIGO = BRAND_PURPLE
TEXT_COLOR = colors.HexColor("#16213E")
BODY_TEXT = colors.HexColor("#374151")
GRID = colors.HexColor("#e5e7eb")
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#dc2626"),
    "HIGH": colors.HexColor("#ea580c"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#16a34a"),
    "INFO": colors.HexColor("#4b5563"),
}
ROW_BACKGROUNDS = [colors.whitesmoke, colors.white]

LEFT = RIGHT = BOTTOM = 14 * mm
TOP = 15 * mm
KNOWN_CATEGORY_ORDER = [
    "Application Security",
    "Network Security",
    "TLS Security",
    "DNS Security",
    "Mail Security",
    "IP Reputation",
]


_BASE_STYLES = getSampleStyleSheet()
HEAD_STYLE = ParagraphStyle(
    "thead", parent=_BASE_STYLES["Normal"], fontName="Helvetica-Bold",
    fontSize=9, leading=11, textColor=colors.white,
)
CELL_STYLE = ParagraphStyle(
    "tcell", parent=_BASE_STYLES["Normal"], fontName="Helvetica",
    fontSize=9, leading=11, textColor=BODY_TEXT,
)


class _Logo:
    def __init__(self, kind: str, path: str, aspect: float):
        self.kind = kind          # "svg" or "raster"
        self.path = path
        self.aspect = aspect      # width / height

    def flowable(self, height: float):
        """A reportlab Flowable of this logo at the given height, for use
        directly in a Platypus story (e.g. the cover page)."""
        if self.kind == "svg":
            return _svg_drawing(self.path, height)
        return Image(self.path, width=height * self.aspect, height=height)

    def draw_on_canvas(self, canvas_obj, x: float, y: float, height: float):
        """Paint this logo directly on a canvas (used by the page-header /
        back-page onPage callbacks, which draw outside the story's frame)."""
        width = height * self.aspect
        if self.kind == "svg":
            drawing = _svg_drawing(self.path, height)
            canvas_obj.saveState()
            canvas_obj.translate(x, y)
            renderPDF.draw(drawing, canvas_obj, 0, 0)
            canvas_obj.restoreState()
        else:
            canvas_obj.drawImage(
                self.path, x, y, width=width, height=height,
                preserveAspectRatio=True, mask="auto",
            )
        return width


def _svg_drawing(path: str, height: float):
    from svglib.svglib import svg2rlg
    drawing = svg2rlg(path)
    scale = height / drawing.height
    drawing.width *= scale
    drawing.height = height
    drawing.scale(scale, scale)
    return drawing


def _load_logo(path: Path, fallback: Path | None = None) -> "_Logo | None":
    if not path.exists():
        return None

    if path.suffix.lower() == ".svg":
        try:
            from svglib.svglib import svg2rlg
            drawing = svg2rlg(str(path))
            if drawing and drawing.width and drawing.height:
                return _Logo("svg", str(path), drawing.width / drawing.height)
        except Exception:
            pass
        # Fall back to a raster logo (e.g. isecurify_logo.png next to the
        # SVG) if the SVG failed to load — better a working raster logo
        # than no logo at all. Recursion is safe: raster files take the
        # non-SVG branch below and never recurse again.
        if fallback is not None:
            raster = _load_logo(fallback)
            if raster:
                return raster
        for sibling in sorted(path.parent.iterdir()):
            if sibling == path or sibling.suffix.lower() not in (".png", ".jpg", ".jpeg"):
                continue
            raster = _load_logo(sibling)
            if raster:
                return raster
        return None

    try:
        from PIL import Image as PILImage
        with PILImage.open(path) as im:
            w, h = im.size
        return _Logo("raster", str(path), w / h)
    except Exception:
        return None


def _esc(value: Any) -> str:
    """Escape text so it is safe inside a reportlab Paragraph."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _style_table(
    rows: List[List[Any]],
    col_widths: List[float],
    header_bg: colors.Color = INDIGO,
    row_back_colors: List[colors.Color] = ROW_BACKGROUNDS,
    severity_col: int | None = None,
) -> Table:
    """Build a wrapped-cell table with styled header and optional row striping."""
    wrapped_rows = []
    for r_idx, row in enumerate(rows):
        style = HEAD_STYLE if r_idx == 0 else CELL_STYLE
        wrapped_rows.append([Paragraph(_esc(cell), style) for cell in row])

    table = Table(wrapped_rows, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, GRID),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), row_back_colors),
    ]

    if severity_col is not None:
        for r_idx, row in enumerate(rows[1:], start=1):
            if len(row) > severity_col:
                severity = str(row[severity_col] or "").upper()
                color = SEVERITY_COLORS.get(severity)
                if color:
                    commands.append(("TEXTCOLOR", (severity_col, r_idx), (severity_col, r_idx), color))
                    commands.append(("FONTNAME", (severity_col, r_idx), (severity_col, r_idx), "Helvetica-Bold"))

    table.setStyle(TableStyle(commands))
    return table


def _draw_cover_page(canvas_obj, doc, domain: str):
    """Background + decorative bars only. The logo and all text are real
    flowables in the story now, so this can never collide with them again."""
    canvas_obj.saveState()
    canvas_obj.setFillColor(COVER_BG)
    canvas_obj.rect(0, 0, A4[0], A4[1], stroke=0, fill=1)
    canvas_obj.setFillColor(BRAND_PURPLE_DARK)
    canvas_obj.rect(LEFT, 0, A4[0] - LEFT - RIGHT, 30 * mm, stroke=0, fill=1)
    canvas_obj.setFillColor(BRAND_PURPLE)
    canvas_obj.rect(0, 0, A4[0], 2.2 * mm, stroke=0, fill=1)
    canvas_obj.rect(0, A4[1] - 2.2 * mm, A4[0], 2.2 * mm, stroke=0, fill=1)
    canvas_obj.setFont("Helvetica-Bold", 9)
    canvas_obj.setFillColor(colors.whitesmoke)
    canvas_obj.drawString(LEFT + 4 * mm, 8 * mm, "CONFIDENTIAL — Authorized recipients only.")
    canvas_obj.restoreState()


def _draw_back_page(canvas_obj, doc, logo: "_Logo | None", domain: str):
    canvas_obj.saveState()
    canvas_obj.setFillColor(COVER_BG)
    canvas_obj.rect(0, 0, A4[0], A4[1], stroke=0, fill=1)
    if logo:
        logo_h = 22 * mm
        logo_w = logo_h * logo.aspect
        pad = 5 * mm
        card_w, card_h = logo_w + 2 * pad, logo_h + 2 * pad
        card_x, card_y = (A4[0] - card_w) / 2, A4[1] - 68 * mm
        canvas_obj.setFillColor(colors.white)
        canvas_obj.roundRect(card_x, card_y, card_w, card_h, 4, stroke=0, fill=1)
        logo.draw_on_canvas(canvas_obj, card_x + pad, card_y + pad, logo_h)
    canvas_obj.setFillColor(BRAND_PURPLE)
    canvas_obj.rect(LEFT, 14 * mm, A4[0] - LEFT - RIGHT, 4 * mm, stroke=0, fill=1)
    canvas_obj.restoreState()


def _draw_page_header(canvas_obj, doc, logo: "_Logo | None", domain: str):
    canvas_obj.saveState()
    if logo:
        header_h = 0.26 * inch
        header_w = logo.draw_on_canvas(canvas_obj, LEFT, A4[1] - header_h - 8, header_h)
        text_x = LEFT + header_w + 8
    else:
        text_x = LEFT

    canvas_obj.setFont("Helvetica-Bold", 11)
    canvas_obj.setFillColor(TEXT_COLOR)
    canvas_obj.drawString(text_x, A4[1] - 17, "")

    canvas_obj.setStrokeColor(BRAND_PURPLE)
    canvas_obj.setLineWidth(0.8)
    canvas_obj.line(LEFT, A4[1] - 28, A4[0] - RIGHT, A4[1] - 28)
    canvas_obj.line(LEFT, BOTTOM + 10, A4[0] - RIGHT, BOTTOM + 10)

    canvas_obj.setFont("Helvetica", 7.5)
    canvas_obj.setFillColor(BODY_TEXT)
    canvas_obj.drawString(LEFT, BOTTOM + 4, "CONFIDENTIAL REPORT — FOR AUTHORIZED USE ONLY")

    page_number = f"Page {doc.page}"
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.drawRightString(A4[0] - RIGHT, BOTTOM + 4, page_number)
    canvas_obj.restoreState()


def _count_severity_totals(categories: List[Dict[str, Any]]) -> tuple[Dict[str, int], int]:
    totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    total_findings = 0
    for cat in categories:
        if cat.get("isIpRep"):
            continue
        for finding in cat.get("findings") or []:
            hosts = finding.get("hosts") or []
            count = len(hosts)
            total_findings += count
            severity = str(finding.get("severity") or "INFO").upper()
            totals[severity] = totals.get(severity, 0) + count
    return totals, total_findings


def generate_domain_scan_report_pdf_bytes(
    domain: str,
    score: Any,
    grade_label: str,
    categories: List[Dict[str, Any]],
    ip_reps: List[Dict[str, Any]],
    generated_at: datetime | None = None,
) -> bytes:
    buf = io.BytesIO()
    logo = _load_logo(HERO_LOGO_PATH, fallback=RASTER_LOGO_PATH)
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=LEFT,
        rightMargin=RIGHT,
        topMargin=TOP,
        bottomMargin=BOTTOM,
        title="Security Scan Report",
    )
    frame = Frame(LEFT, BOTTOM, A4[0] - LEFT - RIGHT, A4[1] - TOP - BOTTOM, id="normal")
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[frame], onPage=lambda c, d: _draw_cover_page(c, d, domain)),
        PageTemplate(id="Body", frames=[frame], onPage=lambda c, d: _draw_page_header(c, d, logo, domain)),
        PageTemplate(id="Back", frames=[frame], onPage=lambda c, d: _draw_back_page(c, d, logo, domain)),
    ])

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("reportTitle", parent=styles["Normal"], fontSize=22, leading=26, textColor=TEXT_COLOR)
    detail_style = ParagraphStyle("detail", parent=styles["Normal"], fontSize=12, leading=20, textColor=TEXT_COLOR)
    exec_style = ParagraphStyle("exec", parent=styles["Normal"], fontSize=18, leading=22, textColor=TEXT_COLOR)
    section_style = ParagraphStyle("section", parent=styles["Normal"], fontSize=16, leading=20, textColor=TEXT_COLOR)

    cover_title_style = ParagraphStyle(
        "coverTitle", parent=styles["Normal"], fontSize=32, leading=38, alignment=1,
        textColor=TEXT_COLOR, spaceAfter=6 * mm,
    )
    cover_subtitle_style = ParagraphStyle(
        "coverSubtitle", parent=styles["Normal"], fontSize=16, leading=20, alignment=1,
        textColor=TEXT_COLOR, spaceAfter=4 * mm,
    )
    cover_note_style = ParagraphStyle(
        "coverNote", parent=styles["Normal"], fontSize=10, leading=14, alignment=1,
        textColor=BODY_TEXT,
    )
    back_cover_title_style = ParagraphStyle(
        "backCoverTitle", parent=styles["Normal"], fontSize=24, leading=30, alignment=1,
        textColor=TEXT_COLOR, spaceAfter=6 * mm,
    )
    back_cover_detail_style = ParagraphStyle(
        "backCoverDetail", parent=styles["Normal"], fontSize=11, leading=16, alignment=1,
        textColor=BODY_TEXT,
    )

    content_w = A4[0] - LEFT - RIGHT
    story: List[Any] = []

    generated_at = generated_at or datetime.now()
    generated_at_label = generated_at.strftime("%d %b %Y")  # date only — no time
    totals, total_findings = _count_severity_totals(categories)

    # ── Cover page ──
    # The logo is a real flowable (like everything else on the cover), so it
    # can never overlap the title/subtitle the way it did when the logo was
    # painted separately by the page-background canvas callback.
    story.append(Spacer(1, 30 * mm))
    if logo:
        logo_flowable = logo.flowable(height=24 * mm)
        logo_flowable.hAlign = "CENTER"
        story.append(logo_flowable)
        story.append(Spacer(1, 12 * mm))
    story.append(Paragraph("Domain Security Scan Report", cover_title_style))
    # NOTE: this used to also print a plain "iSecurify" line right under the
    # title — redundant with the logo above it (which already reads
    # "iSecurify"), so it read as the brand name appearing twice. Removed;
    # the domain line below is the one useful "who/what is this report
    # about" line, not a restatement of the company name.
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(_esc(domain or "Unknown"), cover_subtitle_style))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Score: {score} / 100", cover_subtitle_style))
    story.append(Paragraph(f"Grade: {_esc(grade_label)}", cover_subtitle_style))
    story.append(Paragraph(f"Date: {generated_at_label}", cover_subtitle_style))
    story.append(Spacer(1, 16 * mm))
    story.append(Paragraph("Public Domain Security Scan", cover_note_style))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Comprehensive analysis of your publicly exposed domain assets.", cover_note_style))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("This report is intended only for authorized recipients.", cover_note_style))
    story.append(NextPageTemplate("Body"))
    story.append(PageBreak())

    # ── Report Overview page ──
    # No logo flowable here: the running page header (drawn on the canvas)
    # already shows the iSecurify logo, so placing one again would duplicate it.
    story.append(Paragraph("Domain Security Scan Report", title_style))
    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(f"Domain: {_esc(domain or 'Unknown')}", detail_style))
    story.append(Paragraph(f"Date: {generated_at_label}", detail_style))
    story.append(Spacer(1, 12 * mm))

    story.append(Paragraph("Report Overview", section_style))
    story.append(Spacer(1, 2 * mm))
    overview_rows = [
        ["Metric", "Value"],
        ["Score", f"{score} / 100"],
        ["Grade", _esc(grade_label)],
        ["Total findings", str(total_findings)],
        ["IP addresses scanned", str(len(ip_reps or []))],
    ]
    story.append(_style_table(
        overview_rows, [content_w * 0.32, content_w * 0.68],
        header_bg=BRAND_PURPLE_DARK,
        row_back_colors=[colors.Color(0.97, 0.97, 0.98), colors.white],
    ))
    story.append(Spacer(1, 8 * mm))

    # Severity breakdown — `totals` was already being computed but never
    # actually shown anywhere in the original report; a reader had no way
    # to tell "57 findings" apart from "57 LOW findings" without opening
    # every table. Surface it explicitly, colour-coded like the detail rows.
    story.append(Paragraph("Severity Breakdown", section_style))
    story.append(Spacer(1, 2 * mm))
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    breakdown_rows = [["Severity", "Count"]] + [[s.title(), str(totals.get(s, 0))] for s in severity_order]
    story.append(_style_table(
        breakdown_rows, [content_w * 0.32, content_w * 0.68],
        header_bg=BRAND_PURPLE_DARK,
        row_back_colors=[colors.Color(0.97, 0.97, 0.98), colors.white],
        severity_col=0,
    ))
    story.append(Spacer(1, 10 * mm))

    # ── Executive Summary ──
    # Built directly from `categories` (in the order they were given) instead
    # of a hardcoded 5-item allowlist, so a category like "Mail Security" that
    # exists in the detail pages below can no longer go missing up here.
    story.append(Paragraph("Executive Summary", exec_style))
    story.append(Spacer(1, 4 * mm))
    summary_rows = [["Category", "Summary", "Findings"]]
    for cat in categories:
        name = cat.get("name") or "Unknown"
        if cat.get("isIpRep"):
            count = len(ip_reps or [])
            summary_rows.append([name, f"{count} IP{'s' if count != 1 else ''}", str(count)])
        else:
            count = sum(len(f.get("hosts") or []) for f in cat.get("findings") or [])
            summary_rows.append([name, f"{count} finding{'s' if count != 1 else ''}", str(count)])

    story.append(_style_table(summary_rows, [content_w * 0.4, content_w * 0.4, content_w * 0.2], header_bg=BRAND_PURPLE_DARK, row_back_colors=[colors.Color(0.97, 0.97, 0.98), colors.white]))
    story.append(Spacer(1, 12 * mm))

    # ── Per-category detail sections ──
    # Column widths were 5 equal columns before, which left "Finding Rule"
    # (the longest text, e.g. "Missing X-Content-Type-Options") too narrow
    # and forced ugly mid-word breaks. Widen it and Affected Host, and shrink
    # Port (usually 2-5 digits or "—").
    finding_col_widths = [content_w * 0.28, content_w * 0.26, content_w * 0.22, content_w * 0.10, content_w * 0.14]

    for cat in categories:
        name = cat.get("name") or "Unknown"
        story.append(Paragraph(_esc(name), section_style))
        story.append(Spacer(1, 3 * mm))

        if cat.get("isIpRep"):
            if not ip_reps:
                story.append(Paragraph("No IPs found.", styles["BodyText"]))
            else:
                rows = [["IP", "Abuse Score", "Total Reports", "ISP"]]
                for rep in ip_reps:
                    rows.append([
                        str(rep.get("ip") or "—"),
                        f"{rep.get('abuseConfidenceScore', 0)}%",
                        str(rep.get("totalReports") or 0),
                        str(rep.get("isp") or "N/A"),
                    ])
                story.append(_style_table(rows, [content_w * 0.25] * 4))
        else:
            findings = cat.get("findings") or []
            if not findings:
                story.append(Paragraph("No findings.", styles["BodyText"]))
            else:
                rows = [["Finding Rule", "Affected Host", "IP", "Port", "Severity"]]
                for finding in findings:
                    for host in finding.get("hosts") or []:
                        rows.append([
                            str(finding.get("rule") or "—"),
                            str(host.get("subdomain") or "—"),
                            str(host.get("ip") or "—"),
                            str(host.get("port") or "—"),
                            str(finding.get("severity") or "INFO").upper(),
                        ])
                story.append(_style_table(rows, finding_col_widths, severity_col=4))

        story.append(Spacer(1, 12 * mm))

    story.append(NextPageTemplate("Back"))
    story.append(PageBreak())
    story.append(Spacer(1, 70 * mm))
    story.append(Paragraph("End of Report", back_cover_title_style))
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(
        "Thank you for reviewing the Domain security scan report. "
        "Please address the highest-severity findings first and contact your security team for remediation guidance.",
        back_cover_detail_style,
    ))
    story.append(Spacer(1, 12 * mm))
    story.append(Paragraph(f"Report generated on {generated_at_label}", back_cover_detail_style))
    story.append(Spacer(1, 20 * mm))

    doc.build(story)
    return buf.getvalue()