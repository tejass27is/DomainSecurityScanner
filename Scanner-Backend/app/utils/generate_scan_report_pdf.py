from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, inch
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


_APP_ROOT = Path(__file__).resolve().parent.parent
HERO_LOGO_PATH = _APP_ROOT / "assets" / "isecurify_logo.png"
if not HERO_LOGO_PATH.exists():
    _REPO_ROOT = Path(__file__).resolve().parents[3]
    HERO_LOGO_PATH = _REPO_ROOT / "ShieldStat-Frontend" / "src" / "assets" / "isecurify_logo.png"


INDIGO = colors.HexColor("#4f46e5")       
TEXT_COLOR = colors.HexColor("#282828")   
BODY_TEXT = colors.HexColor("#374151")   
GRID = colors.HexColor("#e5e7eb")         # 

LEFT = RIGHT = BOTTOM = 14 * mm
TOP = 15 * mm
LOGO_SIZE = 40 * mm

SUMMARY_CATEGORIES = [
    "Application Security",
    "Network Security",
    "TLS Security",
    "DNS Security",
    "IP Reputation",
]


_BASE_STYLES = getSampleStyleSheet()
HEAD_STYLE = ParagraphStyle(
    "thead",
    parent=_BASE_STYLES["Normal"],
    fontName="Helvetica-Bold",
    fontSize=9,
    leading=11,
    textColor=colors.white,
)
CELL_STYLE = ParagraphStyle(
    "tcell",
    parent=_BASE_STYLES["Normal"],
    fontName="Helvetica",
    fontSize=9,
    leading=11,
    textColor=BODY_TEXT,
)


def _load_raster(path: Path):
    """Load a PNG/JPEG. Returns (source_path, aspect_ratio) or (None, None)."""
    if not path.exists():
        return None, None
    from PIL import Image as PILImage

    with PILImage.open(path) as im:
        w, h = im.size
    return str(path), w / h


def _esc(value: Any) -> str:
    """Escape text so it is safe inside a reportlab Paragraph."""
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _style_table(rows: List[List[Any]], col_widths: List[float]) -> Table:
    """Build a wrapped-cell table with an indigo header row (matches the logged-in report)."""
    wrapped_rows = []
    for r_idx, row in enumerate(rows):
        style = HEAD_STYLE if r_idx == 0 else CELL_STYLE
        wrapped_rows.append([Paragraph(_esc(cell), style) for cell in row])

    table = Table(wrapped_rows, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), INDIGO),
                ("GRID", (0, 0), (-1, -1), 0.25, GRID),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    return table


def _draw_page_header(canvas_obj, doc, logo_path: str | None, logo_aspect: float | None):
    canvas_obj.saveState()
    if logo_path and logo_aspect:
        logo_h = 0.3 * inch
        logo_w = logo_h * logo_aspect
        canvas_obj.drawImage(
            logo_path, LEFT, A4[1] - 10 - logo_h, width=logo_w, height=logo_h,
            preserveAspectRatio=True, mask="auto",
        )
        canvas_obj.setFont("Helvetica-Bold", 14)
        canvas_obj.setFillColor(TEXT_COLOR)
        canvas_obj.drawString(
            LEFT + logo_w + 8,
            A4[1] - 10 - logo_h + (logo_h - 10) * 0.55,
            "iSecurify",
        )
        canvas_obj.setStrokeColor(GRID)
        canvas_obj.line(LEFT, A4[1] - 38, A4[0] - RIGHT, A4[1] - 38)
    canvas_obj.restoreState()


def generate_domain_scan_report_pdf_bytes(
    domain: str,
    score: Any,
    grade_label: str,
    categories: List[Dict[str, Any]],
    ip_reps: List[Dict[str, Any]],
    generated_at: datetime | None = None,
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=LEFT,
        rightMargin=RIGHT,
        topMargin=TOP,
        bottomMargin=BOTTOM,
        title="Security Scan Report",
    )

    styles = getSampleStyleSheet()
    logo_path, logo_aspect = _load_raster(HERO_LOGO_PATH)

    title_style = ParagraphStyle(
        "reportTitle",
        parent=styles["Normal"],
        fontSize=22,
        leading=26,
        textColor=TEXT_COLOR,
        spaceBefore=0,
        spaceAfter=0,
    )

    detail_style = ParagraphStyle(
        "detail",
        parent=styles["Normal"],
        fontSize=12,
        leading=20,
        textColor=TEXT_COLOR,
        spaceBefore=0,
        spaceAfter=0,
    )

    exec_style = ParagraphStyle(
        "exec",
        parent=styles["Normal"],
        fontSize=18,
        leading=22,
        textColor=TEXT_COLOR,
        spaceBefore=0,
        spaceAfter=0,
    )

    section_style = ParagraphStyle(
        "section",
        parent=styles["Normal"],
        fontSize=16,
        leading=20,
        textColor=TEXT_COLOR,
        spaceBefore=0,
        spaceAfter=0,
    )

    content_w = A4[0] - LEFT - RIGHT
    story = []

    # ── Header: logo top-left, then title (same placement as the logged-in report) ──
    if logo_path and logo_aspect:
        story.append(Image(logo_path, width=LOGO_SIZE, height=LOGO_SIZE / logo_aspect, hAlign="LEFT"))
        story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Security Scan Report", title_style))
    story.append(Spacer(1, 7 * mm))

    story.append(Paragraph(f"Domain: {_esc(domain or 'Unknown')}", detail_style))
    story.append(Paragraph(f"Score: {score} / 100 ({_esc(grade_label)})", detail_style))
    story.append(Paragraph(f"Date: {(generated_at or datetime.now()).strftime('%d/%m/%Y')}", detail_style))
    story.append(Spacer(1, 18 * mm))

    # ── Executive summary — same fixed category order as the logged-in report ──
    summary_rows = [["Category", "Summary"]]
    for name in SUMMARY_CATEGORIES:
        cat = next((c for c in categories if (c.get("name") or "") == name), None)
        if cat is None:
            summary_rows.append([name, "0 findings"])
        elif cat.get("isIpRep"):
            summary_rows.append([name, f"{len(ip_reps or [])} IPs"])
        else:
            count = sum(len(f.get("hosts") or []) for f in cat.get("findings") or [])
            summary_rows.append([name, f"{count} finding{'s' if count != 1 else ''}"])

    story.append(Paragraph("Executive Summary", exec_style))
    story.append(Spacer(1, 4 * mm))
    story.append(_style_table(summary_rows, [content_w * 0.5, content_w * 0.5]))
    story.append(Spacer(1, 12 * mm))

    # ── Per-category detail sections ──
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
                story.append(_style_table(rows, [content_w * 0.2] * 5))

        story.append(Spacer(1, 12 * mm))

    doc.build(
        story,
        onFirstPage=lambda canvas, d: _draw_page_header(canvas, d, logo_path, logo_aspect),
        onLaterPages=lambda canvas, d: _draw_page_header(canvas, d, logo_path, logo_aspect),
    )
    return buf.getvalue()
