from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Logo assets, resolved relative to this file's location inside the repo:
#   ShieldStat-Frontend/src/assets/isecurify_logo.png  -> full colour logo with wordmark
#   ShieldStat-Frontend/src/assets/logo.svg            -> icon-only mark (vector)
_REPO_ROOT = Path(__file__).resolve().parents[3]
HERO_LOGO_PATH = _REPO_ROOT / "ShieldStat-Frontend" / "src" / "assets" / "isecurify_logo.png"
ICON_LOGO_PATH = _REPO_ROOT / "ShieldStat-Frontend" / "src" / "assets" / "logo.svg"


def _load_raster(path: Path):
    """Load a PNG/JPEG. Returns (source, aspect_ratio) or (None, None)."""
    if not path.exists():
        return None, None
    from PIL import Image as PILImage

    with PILImage.open(path) as im:
        w, h = im.size
    return str(path), w / h


def _load_svg(path: Path):
    """Rasterize an SVG via cairosvg. Returns (png_bytes, aspect_ratio) or (None, None)."""
    if not path.exists():
        return None, None
    try:
        import cairosvg
    except ImportError:
        return None, None

    png_bytes = cairosvg.svg2png(url=str(path), scale=4)
    from PIL import Image as PILImage

    with PILImage.open(io.BytesIO(png_bytes)) as im:
        w, h = im.size
    return png_bytes, w / h


def _style_table(rows: List[List[Any]], col_widths: List[float]) -> Table:
    table = Table(rows, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#374151")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def _icon_reader(png_bytes: bytes):
    from reportlab.lib.utils import ImageReader

    return ImageReader(io.BytesIO(png_bytes))


def _draw_report_header(canvas_obj, doc, icon_png_bytes, icon_aspect):
    # Small icon mark, top-left, on every page. Page 1 carries its own
    # large icon inline in the flowable story instead, so skip it here.
    canvas_obj.saveState()
    if canvas_obj.getPageNumber() > 1 and icon_png_bytes:
        h = 0.4 * inch
        w = h * icon_aspect
        canvas_obj.drawImage(
            _icon_reader(icon_png_bytes), 50, 745, width=w, height=h,
            preserveAspectRatio=True, mask="auto",
        )
        canvas_obj.setStrokeColor(colors.HexColor("#e5e7eb"))
        canvas_obj.line(50, 740, 550, 740)
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
        pagesize=letter,
        leftMargin=50,
        rightMargin=50,
        topMargin=80,
        bottomMargin=50,
        title="Security Scan Report",
    )

    styles = getSampleStyleSheet()
    story = []

    icon_png_bytes, icon_aspect = _load_svg(ICON_LOGO_PATH)
    # HERO_LOGO_PATH (full wordmark) is resolved but not drawn on this layout —
    # the page-1 header uses the icon mark only, per the approved design.
    # Kept available for other templates: _load_raster(HERO_LOGO_PATH)

    detail_style = styles["Normal"].clone("detail")
    detail_style.fontSize = 12
    detail_style.leading = 20
    detail_style.textColor = colors.HexColor("#1f2937")

    title_style = styles["Title"].clone("reportTitle")
    title_style.textColor = colors.HexColor("#111827")
    title_style.alignment = 0  # left
    title_style.spaceBefore = 0

    if icon_png_bytes:
        icon_w = 1.3 * inch
        icon_h = icon_w / icon_aspect
        story.append(Image(io.BytesIO(icon_png_bytes), width=icon_w, height=icon_h))
        story.append(Spacer(1, 0.3 * inch))

    story.append(Paragraph("Security Scan Report", title_style))
    story.append(Spacer(1, 0.22 * inch))
    story.append(Paragraph(f"Domain: {domain or 'Unknown'}", detail_style))
    story.append(Paragraph(f"Score: {score} / 100 ({grade_label})", detail_style))
    story.append(Paragraph(f"Date: {(generated_at or datetime.now()).strftime('%d/%m/%Y')}", detail_style))
    story.append(Spacer(1, 0.35 * inch))

    summary_rows = [["Category", "Summary"]]
    for cat in categories:
        name = cat.get("name") or "Unknown"
        if cat.get("isIpRep"):
            summary_rows.append([name, f"{len(cat.get('findings') or [])} IPs"])
        else:
            count = sum(len((f.get("hosts") or [])) for f in cat.get("findings") or [])
            summary_rows.append([name, f"{count} finding{'s' if count != 1 else ''}"])

    story.append(Paragraph("<font color='#4f46e5'><b>Executive Summary</b></font>", styles["Heading2"]))
    story.append(Spacer(1, 0.08 * inch))
    summary_table = _style_table(summary_rows, [2.8 * inch, 2.8 * inch])
    story.append(summary_table)
    story.append(Spacer(1, 0.25 * inch))

    for cat in categories:
        name = cat.get("name") or "Unknown"
        story.append(Paragraph(f"<font color='#4f46e5'><b>{name}</b></font>", styles["Heading2"]))
        story.append(Spacer(1, 0.06 * inch))

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
                story.append(_style_table(rows, [1.6 * inch, 1.3 * inch, 1.2 * inch, 2.0 * inch]))
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
                story.append(_style_table(rows, [2.0 * inch, 1.6 * inch, 1.3 * inch, 0.8 * inch, 0.9 * inch]))

        story.append(Spacer(1, 0.2 * inch))

    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Domain Scanner",
            styles["Normal"],
        )
    )

    doc.build(
        story,
        onFirstPage=lambda canvas, doc: _draw_report_header(canvas, doc, icon_png_bytes, icon_aspect),
        onLaterPages=lambda canvas, doc: _draw_report_header(canvas, doc, icon_png_bytes, icon_aspect),
    )
    return buf.getvalue()