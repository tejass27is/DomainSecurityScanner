"""ReportLab PDF rendering for completed cloud assessments."""

import html
import re
import unicodedata
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from typing import Any

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Circle, Drawing, Rect, String, Wedge
from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfgen import canvas
from svglib.svglib import svg2rlg

PRIMARY = colors.HexColor("#33143B")
PRIMARY_LIGHT = colors.HexColor("#4C1E5E")
ACCENT = colors.HexColor("#800080")
TEXT_MAIN = colors.HexColor("#37323C")
TEXT_MUTED = colors.HexColor("#6B6670")
BORDER_COLOR = colors.HexColor("#E8E2EC")
BG_LIGHT = colors.HexColor("#F9F8FB")
COLOR_CRITICAL = colors.HexColor("#DC2626")
BG_CRITICAL = colors.HexColor("#FEE2E2")
COLOR_HIGH = colors.HexColor("#EA580C")
BG_HIGH = colors.HexColor("#FFEDD5")
COLOR_MEDIUM = colors.HexColor("#D97706")
BG_MEDIUM = colors.HexColor("#FEF3C7")
COLOR_LOW = colors.HexColor("#2563EB")
BG_LOW = colors.HexColor("#DBEAFE")
COLOR_INFO = colors.HexColor("#475569")
BG_INFO = colors.HexColor("#F1F5F9")
COLOR_FAIL = colors.HexColor("#DC2626")
BG_FAIL = colors.HexColor("#FEE2E2")
COLOR_PASS = colors.HexColor("#16A34A")
BG_PASS = colors.HexColor("#DCFCE7")
COLOR_MUTED = colors.HexColor("#D97706")
BG_MUTED = colors.HexColor("#FEF3C7")
COLOR_RISK = colors.HexColor("#B91C1C")
BG_RISK = colors.HexColor("#FEE2E2")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
SEVERITY_COLORS = {
    "critical": (COLOR_CRITICAL, BG_CRITICAL),
    "high": (COLOR_HIGH, BG_HIGH),
    "medium": (COLOR_MEDIUM, BG_MEDIUM),
    "low": (COLOR_LOW, BG_LOW),
    "informational": (COLOR_INFO, BG_INFO),
}
SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1, "informational": 0}


class _NumberedCanvas(canvas.Canvas):
    """Render report branding and total page numbers in a second pass."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        page_count = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.saveState()
            if self._pageNumber > 1:
                self.setFillColor(colors.white)
                self.setStrokeColor(BORDER_COLOR)
                self.roundRect(36, 800, 523, 38, 8, fill=1, stroke=1)
                _logo_drawing().drawOn(self, 49, 805)
                self.setFont("Helvetica-Bold", 13)
                self.setFillColor(PRIMARY)
                self.drawRightString(545, 815, "Executive Security Report")
                self.setStrokeColor(BORDER_COLOR)
                self.setLineWidth(0.6)
                self.line(36, 792, 559, 792)
                self.line(36, 45, 559, 45)
                self.setFont("Helvetica", 8)
                self.drawString(36, 32, "iSecurify | Executive Security Report")
                self.drawRightString(559, 32, f"Page {self._pageNumber} of {page_count}")
            self.restoreState()
            super().showPage()
        super().save()


def _escape(value: Any) -> str:
    text = str(value or "")
    text = "".join(
        " " if character in "\r\t" else character
        for character in text
        if unicodedata.category(character) not in {"Cc", "Cf"} or character in "\r\t\n"
    )
    text = text.encode("cp1252", errors="replace").decode("cp1252")
    return html.escape(text, quote=False)


def _rich_text(value: Any) -> str:
    text = str(value or "")
    text = "".join(
        " " if character in "\r\t" else character
        for character in text
        if unicodedata.category(character) not in {"Cc", "Cf"} or character in "\r\t\n"
    )
    text = text.encode("cp1252", errors="replace").decode("cp1252")
    parts = re.split(r"(\*\*.*?\*\*|__.*?__|`[^`]*`)", text, flags=re.DOTALL)
    formatted = []
    for part in parts:
        if part.startswith("**") and part.endswith("**"):
            formatted.append(f"<b>{html.escape(part[2:-2], quote=False)}</b>")
        elif part.startswith("__") and part.endswith("__"):
            formatted.append(f"<b>{html.escape(part[2:-2], quote=False)}</b>")
        elif part.startswith("`") and part.endswith("`"):
            formatted.append(html.escape(part[1:-1], quote=False))
        else:
            formatted.append(html.escape(part.replace("*", ""), quote=False))
    return "".join(formatted).replace("\n", "<br/>")


def _wrap_safe(value: Any) -> str:
    return _escape(value)


def _status(finding: dict[str, Any]) -> str:
    return str(finding.get("status") or "").strip().upper().replace(" ", "_")


def _severity(finding: dict[str, Any]) -> str:
    value = str(finding.get("severity") or "informational").strip().lower()
    return value if value in SEVERITY_ORDER else "informational"


def _posture(findings: list[dict[str, Any]]) -> tuple[float | None, str]:
    total = 0
    passed = 0
    for finding in findings:
        status = _status(finding)
        if status not in {"PASS", "FAIL"}:
            continue
        weight = SEVERITY_WEIGHTS[_severity(finding)]
        total += weight
        if status == "PASS":
            passed += weight
    if not total:
        return None, "N/A"
    score = round(passed / total * 1000) / 10
    grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
    return score, grade


def _aggregate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for index, finding in enumerate(findings):
        service = str(finding.get("service") or "Not specified").strip()
        check_id = str(finding.get("check_id") or finding.get("title") or f"record-{index}").strip()
        grouped[(service.lower(), check_id.lower())].append(finding)

    severity_priority = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    aggregated = []
    for observations in grouped.values():
        statuses = [_status(item) for item in observations]
        status = (
            "FAIL" if "FAIL" in statuses else
            "MANUAL" if "MANUAL" in statuses else
            "PASS" if statuses and all(item == "PASS" for item in statuses) else
            next((item for item in statuses if item), "UNKNOWN")
        )
        severity = min(
            (_severity(item) for item in observations),
            key=severity_priority.__getitem__,
        )
        regions = sorted({str(item.get("region") or "").strip() for item in observations if item.get("region")})
        resources = sorted({
            str(item.get("resource_name") or item.get("resource_id") or item.get("resource_type") or "").strip()
            for item in observations
            if item.get("resource_name") or item.get("resource_id") or item.get("resource_type")
        })
        tags: dict[str, set[str]] = defaultdict(set)
        for item in observations:
            if isinstance(item.get("resource_tags"), dict):
                for key, value in item["resource_tags"].items():
                    tags[str(key)].add(str(value))
        first = observations[0]
        aggregated.append({
            **first,
            "service": str(first.get("service") or "Not specified"),
            "check_id": str(first.get("check_id") or ""),
            "title": str(first.get("title") or first.get("check_id") or "Untitled finding"),
            "status": status,
            "severity": severity,
            "regions": regions,
            "resources": resources,
            "resource_tags": {key: "; ".join(sorted(values)) for key, values in tags.items()},
            "occurrences": len(observations),
        })
    return aggregated


def _resource(finding: dict[str, Any]) -> str:
    return str(
        finding.get("resource_name")
        or finding.get("resource_id")
        or finding.get("resource_type")
        or "Not explicitly identified by scanner"
    )


def _framework_alignment(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    control_statuses: dict[tuple[str, str], set[str]] = defaultdict(set)
    for finding in findings:
        references = finding.get("compliance")
        if not isinstance(references, list):
            continue
        for raw_reference in references:
            for reference in str(raw_reference or "").split(" | "):
                framework, separator, controls = reference.partition(":")
                if not separator or not framework.strip():
                    continue
                for control in controls.split(","):
                    control = control.strip()
                    if control:
                        control_statuses[(framework.strip(), control)].add(_status(finding))

    frameworks: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "passed": 0, "failed": 0, "not_assessed": 0}
    )
    for (framework, _control), statuses in control_statuses.items():
        counts = frameworks[framework]
        counts["total"] += 1
        if "FAIL" in statuses:
            counts["failed"] += 1
        elif statuses == {"PASS"}:
            counts["passed"] += 1
        else:
            counts["not_assessed"] += 1

    result = []
    for framework, counts in sorted(frameworks.items()):
        assessed = counts["passed"] + counts["failed"]
        result.append({
            "framework": framework,
            **counts,
            "alignment": round(counts["passed"] / assessed * 100, 1) if assessed else None,
        })
    return result


@lru_cache(maxsize=1)
def _logo_drawing() -> Drawing:
    logo_path = Path(__file__).resolve().parents[2] / "assets" / "logo.svg"
    logo = svg2rlg(str(logo_path))
    scale = min(112 / logo.width, 28 / logo.height)
    logo.scale(scale, scale)
    logo.width *= scale
    logo.height *= scale
    return logo


def _posture_gauge(score: float | None, color: colors.Color) -> Drawing:
    drawing = Drawing(54, 54)
    if score is None:
        drawing.add(Circle(27, 27, 24, fillColor=BG_LIGHT, strokeColor=BORDER_COLOR, strokeWidth=4))
        drawing.add(String(27, 24, "N/A", fontName="Helvetica-Bold", fontSize=8,
                           textAnchor="middle", fillColor=TEXT_MUTED))
        return drawing

    drawing.add(Wedge(
        27, 27, 24, -90, 270, annular=True, radius1=18, yradius1=18,
        fillColor=colors.HexColor("#E6E3E8"), strokeColor=None,
    ))
    if score > 0:
        drawing.add(Wedge(
            27, 27, 24, -90, -90 + min(score, 100) * 3.6,
            annular=True, radius1=18, yradius1=18, fillColor=color, strokeColor=None,
        ))
    drawing.add(Circle(27, 27, 17, fillColor=colors.white, strokeColor=colors.white))
    drawing.add(String(27, 28, f"{score:g}%", fontName="Helvetica-Bold", fontSize=8,
                       textAnchor="middle", fillColor=PRIMARY))
    drawing.add(String(27, 19, "SCORE", fontName="Helvetica-Bold", fontSize=4.5,
                       textAnchor="middle", fillColor=TEXT_MUTED))
    return drawing


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "CloudCoverTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=19, leading=23, textColor=PRIMARY, alignment=TA_RIGHT, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "CloudCoverSubtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=8, leading=11, textColor=TEXT_MUTED, spaceAfter=5,
        ),
        "h1": ParagraphStyle(
            "CloudSectionH1", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=14, leading=18, textColor=PRIMARY, spaceBefore=10,
            spaceAfter=10, keepWithNext=True,
        ),
        "h2": ParagraphStyle(
            "CloudSectionH2", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=11, leading=14, textColor=PRIMARY_LIGHT, spaceBefore=8,
            spaceAfter=6, keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "CloudReportBody", parent=base["BodyText"], fontName="Helvetica",
            fontSize=9.5, leading=14, textColor=TEXT_MAIN, spaceAfter=6,
        ),
        "label": ParagraphStyle(
            "CloudMetaLabel", fontName="Helvetica-Bold", fontSize=8.5,
            leading=11, textColor=TEXT_MUTED,
        ),
        "value": ParagraphStyle(
            "CloudMetaValue", fontName="Helvetica", fontSize=9,
            leading=12, textColor=PRIMARY,
        ),
        "badge": ParagraphStyle(
            "CloudBadge", fontName="Helvetica-Bold", fontSize=8,
            leading=10, alignment=1,
        ),
        "small": ParagraphStyle(
            "CloudSmall", fontName="Helvetica", fontSize=8,
            leading=10, textColor=TEXT_MAIN,
        ),
        "header": ParagraphStyle(
            "CloudTableHeader", fontName="Helvetica-Bold", fontSize=8,
            leading=10, textColor=PRIMARY,
        ),
    }


def generate_cloud_assessment_pdf(scan: dict[str, Any]) -> bytes:
    """Generate the supplied executive report layout from a serialized cloud scan."""
    findings = [item for item in (scan.get("findings") or []) if isinstance(item, dict)]
    summary = scan.get("summary") if isinstance(scan.get("summary"), dict) else {}
    severity_counts = summary.get("severity_counts") if isinstance(summary.get("severity_counts"), dict) else {}
    severity_counts = {name: int(severity_counts.get(name, 0) or 0) for name in SEVERITY_ORDER}
    total = int(summary.get("total_checks", len(findings)) or 0)
    failed = int(summary.get("failed_checks", sum(_status(item) == "FAIL" for item in findings)) or 0)
    passed = int(summary.get("passed_checks", sum(_status(item) == "PASS" for item in findings)) or 0)
    if not summary.get("severity_counts"):
        for finding in findings:
            if _status(finding) == "FAIL":
                severity_counts[_severity(finding)] += 1
    report_findings = _aggregate_findings(findings)
    score, grade = _posture(report_findings)
    if score is None:
        posture = "Not Rated"
    elif score >= 90:
        posture = "Excellent"
    elif score >= 70:
        posture = "Good"
    elif score >= 50:
        posture = "Fair"
    elif score >= 30:
        posture = "Poor"
    else:
        posture = "Critical"
    provider = str(scan.get("provider") or "Cloud Infrastructure").upper()
    account = summary.get("account_id") or ", ".join(
        str(value) for value in (scan.get("scope") or {}).values()
        if value
    ) or "Default Scope"
    timestamp = scan.get("completed_at") or scan.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            pass

    passed_findings = [finding for finding in findings if _status(finding) == "PASS"]
    manual_findings = [finding for finding in findings if _status(finding) == "MANUAL"]
    framework_rows = _framework_alignment(findings)
    services: dict[str, int] = defaultdict(int)
    for finding in report_findings:
        if _status(finding) == "FAIL":
            services[str(finding.get("service") or "Not specified")] += 1
    top_services = sorted(services.items(), key=lambda item: (-item[1], item[0].lower()))[:5]
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=36, rightMargin=36,
        topMargin=52, bottomMargin=54,
        title=f"{provider} Cloud Security Assessment Report",
        author="iSecurify",
    )
    style = _styles()
    report_heading = Paragraph(
        "<b>Executive Security Report</b>",
        ParagraphStyle(
            "ExecutiveReportHeader", fontName="Helvetica-Bold", fontSize=13,
            leading=16, textColor=PRIMARY, alignment=TA_RIGHT,
        ),
    )
    cover_header = Table([[_logo_drawing(), report_heading]], colWidths=[210, 313])
    cover_header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.white), ("BOX", (0, 0), (-1, -1), 0.8, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    content = [
        cover_header,
        Spacer(1, 8),
    ]

    metadata = [
        [
            Paragraph("<b>TARGET ACCOUNT</b>", style["label"]),
            Paragraph("<b>CLOUD PROVIDER</b>", style["label"]),
            Paragraph("<b>CLIENT NAME</b>", style["label"]),
            Paragraph("<b>SCAN TIMESTAMP</b>", style["label"]),
        ],
        [
            Paragraph(_escape(account), style["value"]),
            Paragraph(_escape(provider), style["value"]),
            Paragraph(_escape(scan.get("client_name") or "Not provided"), style["value"]),
            Paragraph(_escape(timestamp), style["value"]),
        ],
    ]
    meta_table = Table(metadata, colWidths=[130.75] * 4)
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT), ("BOX", (0, 0), (-1, -1), 1, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR), ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    content.extend([meta_table, Spacer(1, 8)])

    score_color = COLOR_PASS if score is not None and score >= 70 else (
        COLOR_MEDIUM if score is not None and score >= 50 else COLOR_FAIL
    )
    score_bg = BG_PASS if score is not None and score >= 70 else (
        BG_MEDIUM if score is not None and score >= 50 else BG_CRITICAL
    )
    grade_badge = Table([[
        Paragraph(
            f"<font color='{score_color.hexval()}'><b>GRADE {grade}</b></font>",
            ParagraphStyle("PostureGrade", fontName="Helvetica-Bold", fontSize=6.5, alignment=1),
        ),
    ]], colWidths=[47])
    grade_badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), score_bg),
        ("BOX", (0, 0), (-1, -1), 0.6, score_color),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    posture_heading = Table([[
        Paragraph("<b>Security Posture Score</b>", ParagraphStyle(
            "PostureTitle", fontName="Helvetica-Bold", fontSize=8, textColor=TEXT_MAIN,
        )),
        grade_badge,
    ]], colWidths=[112, 47])
    posture_heading.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    posture_summary = Table([[
        _posture_gauge(score, score_color),
        Paragraph(f"<b>Posture: {posture}</b><br/>"
                  f"Evaluated across {total} automated checks. {failed} failed configurations require remediation.",
                  ParagraphStyle("PostureNarrative", fontSize=6.5, leading=8, textColor=TEXT_MAIN)),
    ]], colWidths=[54, 105])
    posture_summary.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    posture_panel = Table([[posture_heading], [posture_summary]], colWidths=[159])
    posture_panel.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    posture_card = Table([[
        posture_panel,
        *[
            [
                Paragraph(f"<font size=7 color='{TEXT_MUTED.hexval()}'><b>{label.upper()}</b></font>",
                          ParagraphStyle(f"KpiLabel{index}", alignment=1)),
                Paragraph(f"<font size=20 color='{color.hexval()}'><b>{count}</b></font>",
                          ParagraphStyle(f"KpiValue{index}", alignment=1)),
            ]
            for index, (label, count, color) in enumerate((
                ("Total Checks", total, PRIMARY),
                ("Passed Checks", passed, COLOR_PASS),
                ("Failed Checks", failed, COLOR_FAIL),
            ))
        ],
    ]], colWidths=[175, 116, 116, 116])
    posture_style = [
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (0, 0), 0.8, BORDER_COLOR),
        ("BOX", (1, 0), (1, 0), 0.8, BORDER_COLOR),
        ("BOX", (2, 0), (2, 0), 0.8, BORDER_COLOR),
        ("BOX", (3, 0), (3, 0), 0.8, BORDER_COLOR),
        ("BACKGROUND", (0, 0), (0, 0), colors.white),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]
    posture_card.setStyle(TableStyle(posture_style))
    content.extend([posture_card, Spacer(1, 8)])

    pie_drawing = Drawing(110, 140)
    pie = Pie()
    pie.x, pie.y, pie.width, pie.height = 2, 15, 100, 100
    pie_values = [severity_counts[name] for name in SEVERITY_ORDER]
    if sum(pie_values):
        pie.data = pie_values
        for index, severity in enumerate(SEVERITY_ORDER):
            pie.slices[index].fillColor = SEVERITY_COLORS[severity][0]
    else:
        pie.data = [1]
        pie.slices[0].fillColor = COLOR_PASS
    pie_drawing.add(pie)
    pie_drawing.add(Circle(52, 65, 29, fillColor=colors.white, strokeColor=colors.white))
    pie_drawing.add(String(52, 68, str(failed), fontSize=14, fontName="Helvetica-Bold",
                           textAnchor="middle", fillColor=COLOR_FAIL))
    pie_drawing.add(String(52, 55, "FAILED", fontSize=6, fontName="Helvetica-Bold",
                           textAnchor="middle", fillColor=TEXT_MUTED))
    legend_rows = []
    failed_severity_total = sum(severity_counts.values())
    for severity in SEVERITY_ORDER[:4]:
        swatch = Drawing(8, 8)
        swatch.add(Rect(0, 0, 8, 8, fillColor=SEVERITY_COLORS[severity][0], strokeColor=None))
        count = severity_counts[severity]
        percentage = count / failed_severity_total * 100 if failed_severity_total else 0
        legend_rows.append([
            swatch,
            Paragraph(severity.title(), ParagraphStyle(
                f"Legend{severity}", fontName="Helvetica", fontSize=7, textColor=TEXT_MAIN,
            )),
            Paragraph(str(count), ParagraphStyle(
                f"LegendCount{severity}", fontName="Helvetica-Bold", fontSize=7,
                textColor=TEXT_MAIN, alignment=1,
            )),
            Paragraph(f"{percentage:.1f}%", ParagraphStyle(
                f"LegendPct{severity}", fontName="Helvetica", fontSize=6.5,
                textColor=TEXT_MUTED, alignment=2,
            )),
        ])
    pie_legend = Table(legend_rows, colWidths=[11, 59, 20, 34])
    pie_legend.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 1), ("RIGHTPADDING", (0, 0), (-1, -1), 1),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    pie_content = Table([[pie_drawing, pie_legend]], colWidths=[112, 136])
    pie_content.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    bar_drawing = Drawing(260, 160)
    if top_services:
        chart = VerticalBarChart()
        chart.x, chart.y, chart.height, chart.width = 15, 25, 110, 225
        chart.data = [[count for _, count in top_services]]
        chart.categoryAxis.categoryNames = [name[:12].upper() for name, _ in top_services]
        chart.categoryAxis.labels.fontSize = 6.5
        chart.categoryAxis.labels.fontName = "Helvetica-Bold"
        chart.categoryAxis.labels.fillColor = PRIMARY_LIGHT
        chart.valueAxis.valueMin = 0
        highest = max(count for _, count in top_services)
        chart.valueAxis.valueMax = max(highest + 1, 3)
        chart.valueAxis.valueStep = max(1, highest // 5)
        chart.valueAxis.labels.fontSize = 7
        chart.valueAxis.labels.fillColor = TEXT_MUTED
        chart.valueAxis.visibleGrid = 1
        chart.valueAxis.gridStrokeColor = BORDER_COLOR
        chart.barWidth = 12
        chart.groupSpacing = 12
        chart.bars[0].fillColor = COLOR_FAIL
        bar_drawing.add(chart)
    else:
        bar_drawing.add(String(45, 80, "No Failed Services Found",
                               fontName="Helvetica-Bold", fontSize=9, fillColor=COLOR_PASS))

    chart_titles = [
        Paragraph("<b>Failure Severity Distribution</b><br/><font size=7>By risk priority level</font>", ParagraphStyle(
            "CloudChartTitle1", alignment=1, fontName="Helvetica-Bold", fontSize=10, textColor=PRIMARY,
        )),
        Paragraph("<b>Top Failing Services</b><br/><font size=7>Services with most failed checks</font>", ParagraphStyle(
            "CloudChartTitle2", alignment=1, fontName="Helvetica-Bold", fontSize=10, textColor=PRIMARY,
        )),
    ]
    charts = Table([chart_titles, [pie_content, bar_drawing]], colWidths=[260, 263])
    charts.setStyle(TableStyle([
        ("BOX", (0, 0), (0, 1), 1, BORDER_COLOR), ("BOX", (1, 0), (1, 1), 1, BORDER_COLOR),
        ("BACKGROUND", (0, 0), (-1, 0), BG_LIGHT), ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("ALIGN", (0, 1), (-1, 1), "CENTER"),
        ("VALIGN", (0, 1), (-1, 1), "MIDDLE"),
    ]))
    content.extend([charts, Spacer(1, 8), Paragraph("Findings by Severity", style["h2"])])
    severity_cards = []
    for index, severity in enumerate(("critical", "high", "medium", "low")):
        color, _ = SEVERITY_COLORS[severity]
        count = severity_counts[severity]
        percentage = round(count / failed_severity_total * 100, 1) if failed_severity_total else 0
        severity_cards.append([
            Paragraph(f"<font color='{color.hexval()}'><b>{severity.title()}</b></font>",
                      ParagraphStyle(
                          f"SeverityLabel{index}", fontName="Helvetica-Bold",
                          fontSize=8, leading=10,
                      )),
            Spacer(1, 3),
            Paragraph(f"<font size=15 color='{color.hexval()}'><b>{count}</b></font>",
                      ParagraphStyle(
                          f"SeverityCount{index}", fontName="Helvetica-Bold",
                          fontSize=15, leading=19, alignment=1,
                      )),
            Spacer(1, 2),
            Paragraph(f"{percentage}% of total failed findings",
                      ParagraphStyle(
                          f"SeverityPercent{index}", fontName="Helvetica",
                          fontSize=6.5, leading=8, textColor=TEXT_MUTED, alignment=1,
                      )),
        ])
    severity_table = Table([severity_cards], colWidths=[130.75] * 4)
    severity_styles = [
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    for index, severity in enumerate(("critical", "high", "medium", "low")):
        severity_styles.append(("BACKGROUND", (index, 0), (index, 0), SEVERITY_COLORS[severity][1]))
    severity_table.setStyle(TableStyle(severity_styles))
    content.extend([severity_table])
    content.append(Paragraph("Compliance Framework Coverage", style["h1"]))
    compliance_explanation = Table([[
        Paragraph(
            "<b>How to read this section</b><br/>"
            "Scanner findings are mapped to the framework references provided by the assessment. "
            "<b>Met</b> means the mapped check passed; <b>Security gaps</b> means it failed; "
            "<b>Not assessed</b> means no pass/fail result was available. "
            "<b>Pass rate</b> is calculated from met and failed controls only. "
            "This automated snapshot is not a compliance certification.",
            ParagraphStyle(
                "ComplianceExplanation", fontName="Helvetica", fontSize=8.5,
                leading=12, textColor=TEXT_MAIN,
            ),
        ),
    ]], colWidths=[523])
    compliance_explanation.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BG_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.7, BORDER_COLOR),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    content.extend([compliance_explanation, Spacer(1, 7)])
    if framework_rows:
        framework_table_data = [[
            Paragraph("<b>Framework</b>", style["header"]),
            Paragraph("<b>Mapped controls</b>", style["header"]),
            Paragraph(f"<font color='{COLOR_PASS.hexval()}'><b>Met</b></font>", style["header"]),
            Paragraph(f"<font color='{COLOR_FAIL.hexval()}'><b>Security gaps</b></font>", style["header"]),
            Paragraph("<b>Not assessed</b>", style["header"]),
            Paragraph("<b>Pass rate</b>", style["header"]),
        ]]
        framework_table_data.extend([
            [
                Paragraph(_escape(row["framework"]), style["small"]),
                Paragraph(str(row["total"]), style["small"]),
                Paragraph(str(row["passed"]), style["small"]),
                Paragraph(str(row["failed"]), style["small"]),
                Paragraph(str(row["not_assessed"]), style["small"]),
                Paragraph(
                    f'{row["alignment"]:.1f}%' if row["alignment"] is not None else "N/A",
                    style["small"],
                ),
            ]
            for row in framework_rows
        ])
        framework_table = Table(
            framework_table_data,
            colWidths=[126, 83, 62, 62, 103, 83],
            repeatRows=1,
        )
        framework_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.8, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 1), (-1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        content.append(framework_table)
    else:
        content.append(Paragraph(
            "The scanner did not return framework mappings for this assessment, so framework coverage "
            "could not be calculated.",
            style["body"],
        ))
    content.extend([
        PageBreak(),
        Paragraph("Finding Status Guide", style["h1"]),
    ])
    status_guide = [
        [Paragraph("<b>Status</b>", style["header"]),
         Paragraph("<b>What it means</b>", style["header"]),
         Paragraph("<b>Client-facing interpretation</b>", style["header"]),
         Paragraph("<b>Action</b>", style["header"])],
        ["PASS", "The tested configuration satisfies the check.",
         "The control passed this test.", "No remediation required."],
        ["FAIL", "The tested configuration does not satisfy the check.",
         "A security control gap was identified.", "Investigate and remediate according to risk."],
        ["MANUAL", "The scanner cannot conclusively determine the status automatically.",
         "Manual validation is required.", "Security / admin team must verify the control."],
        ["NOT APPLICABLE", "The control does not apply to the environment / resource.",
         "The control is outside the scope of this environment.", "Normally no action is required."],
    ]
    status_guide = [
        row if row_index == 0 else [
            Paragraph(f"<b>{_escape(cell)}</b>", style["small"]) if cell_index == 0
            else Paragraph(_escape(cell), style["small"])
            for cell_index, cell in enumerate(row)
        ]
        for row_index, row in enumerate(status_guide)
    ]
    guide_table = Table(status_guide, colWidths=[75, 145, 160, 143], repeatRows=1)
    guide_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BG_LIGHT), ("BACKGROUND", (0, 1), (0, -1), BG_INFO),
        ("BOX", (0, 0), (-1, -1), 0.8, BORDER_COLOR), ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 1), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    content.extend([
        guide_table,
        Spacer(1, 10),
        Paragraph("Security Findings Explorer", style["h1"]),
        Paragraph(
            f"Showing {failed} of {total} findings · Failures first, grouped by severity, service, and region",
            style["body"],
        ),
        PageBreak(),
    ])
    filtered_findings = [finding for finding in report_findings if _status(finding) == "FAIL"]
    ordered_findings = sorted(
        filtered_findings,
        key=lambda finding: (
            _status(finding) != "FAIL",
            SEVERITY_ORDER.index(_severity(finding)),
            str(finding.get("service") or ""),
            ", ".join(finding.get("regions") or [str(finding.get("region") or "Global")]),
            str(finding.get("check_id") or ""),
        ),
    )
    if not ordered_findings:
        content.append(Paragraph("<b>No findings matched the selected criteria.</b>", style["body"]))
    previous_severity = None
    previous_service = None
    previous_region = None
    for index, finding in enumerate(ordered_findings, 1):
        severity = _severity(finding)
        service = str(finding.get("service") or "Not specified")
        region_names = finding.get("regions") or ([finding.get("region")] if finding.get("region") else [])
        region = ", ".join(str(value) for value in region_names) or "Global"
        if severity != previous_severity:
            severity_count = sum(_severity(item) == severity for item in ordered_findings)
            severity_color, severity_bg = SEVERITY_COLORS[severity]
            severity_heading = Table([[
                Paragraph(f"<b>{severity.title()} Findings ({severity_count})</b>", ParagraphStyle(
                    f"SeverityGroup{index}", fontName="Helvetica-Bold", fontSize=10,
                    leading=13, textColor=severity_color,
                )),
                Paragraph(f"<b>{severity_count} failed checks</b>", ParagraphStyle(
                    f"SeverityCount{index}", fontName="Helvetica-Bold", fontSize=7,
                    leading=10, textColor=TEXT_MAIN, alignment=2,
                )),
            ]], colWidths=[400, 123])
            severity_heading.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), severity_bg),
                ("BOX", (0, 0), (-1, -1), 0.8, severity_color),
                ("LINEBEFORE", (0, 0), (0, -1), 4, severity_color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]))
            content.extend([severity_heading, Spacer(1, 4)])
            previous_severity = severity
            previous_service = None
            previous_region = None
        if service != previous_service:
            service_count = sum(
                _severity(item) == severity and str(item.get("service") or "Not specified") == service
                for item in ordered_findings
            )
            service_heading = Table([[
                Paragraph(f"<b>{_escape(service.upper())} ({service_count})</b>", ParagraphStyle(
                    f"ServiceGroup{index}", fontName="Helvetica-Bold", fontSize=8.5,
                    leading=11, textColor=PRIMARY_LIGHT,
                )),
                Paragraph(f"<b>{service_count} failed checks</b>", ParagraphStyle(
                    f"ServiceCount{index}", fontName="Helvetica-Bold", fontSize=7,
                    leading=10, textColor=TEXT_MAIN, alignment=2,
                )),
            ]], colWidths=[400, 123])
            service_heading.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FCECEF")),
                ("BOX", (0, 0), (-1, -1), 0.7, severity_color),
                ("LINEBEFORE", (0, 0), (0, -1), 3, severity_color),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            content.extend([service_heading, Spacer(1, 3)])
            previous_service = service
            previous_region = None
        if region != previous_region:
            region_count = sum(
                _severity(item) == severity
                and str(item.get("service") or "Not specified") == service
                and ", ".join(item.get("regions") or [str(item.get("region") or "Global")]) == region
                for item in ordered_findings
            )
            region_heading = Table([[
                Paragraph(f"<b>{_escape(region)}</b>", ParagraphStyle(
                    f"RegionGroup{index}", fontName="Helvetica-Bold", fontSize=7.5,
                    leading=10, textColor=ACCENT,
                )),
                Paragraph(f"<b>{region_count} failed checks</b>", ParagraphStyle(
                    f"RegionCount{index}", fontName="Helvetica-Bold", fontSize=6.5,
                    leading=9, textColor=TEXT_MAIN, alignment=2,
                )),
            ]], colWidths=[400, 123])
            region_heading.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EEF5FF")),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#BFD7FF")),
                ("LINEBEFORE", (0, 0), (0, -1), 3, ACCENT),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            content.extend([region_heading, Spacer(1, 3)])
            previous_region = region

        severity_color, severity_bg = SEVERITY_COLORS[severity]
        title_style = ParagraphStyle(
            f"FindingTitle{index}", fontName="Helvetica-Bold", fontSize=8.5,
            leading=11, textColor=PRIMARY,
        )
        status_badge = Paragraph(
            f"<font color='{COLOR_FAIL.hexval()}'><b>[FAIL]</b></font>",
            ParagraphStyle(f"FindingStatus{index}", fontName="Helvetica-Bold", fontSize=6.5, alignment=1),
        )
        severity_badge = Paragraph(
            f"<font color='{severity_color.hexval()}'><b>[{severity.upper()}]</b></font>",
            ParagraphStyle(f"FindingSeverity{index}", fontName="Helvetica-Bold", fontSize=6.5, alignment=1),
        )
        finding_meta = Paragraph(
            f"<b>Service:</b> {_escape(service.upper())} &nbsp; "
            f"<b>Region:</b> {_escape(region)} &nbsp; "
            f"<b>ID:</b> <font color='{ACCENT.hexval()}'>{_escape(finding.get('check_id'))}</font>",
            ParagraphStyle(f"FindingMeta{index}", fontName="Helvetica", fontSize=6.5, leading=9, textColor=TEXT_MAIN),
        )
        header = Table([
            [Paragraph(f"#{index}. {_escape(finding.get('title') or finding.get('check_id'))}", title_style), "", ""],
            [status_badge, severity_badge, finding_meta],
        ], colWidths=[52, 62, 405])
        header.setStyle(TableStyle([
            ("SPAN", (0, 0), (-1, 0)),
            ("BACKGROUND", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 1), (0, 1), BG_FAIL),
            ("BACKGROUND", (1, 1), (1, 1), severity_bg),
            ("BACKGROUND", (2, 1), (2, 1), BG_LIGHT),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))

        resource_names = finding.get("resources") or [_resource(finding)]
        body_rows = [[
            Paragraph("<b>AFFECTED RESOURCE / SCOPE</b>", style["label"]),
            Paragraph(f"<font face='Courier' size=7.5>{_wrap_safe(', '.join(resource_names))}</font>", style["small"]),
        ]]
        risk_row_index = None
        for field, heading, formatter in (
            ("status_extended", "STATUS DETAILS", lambda value: value),
            ("risk", "RISK IMPACT", lambda value: value),
            ("remediation", "REMEDIATION GUIDANCE", lambda value: value),
            ("resource_tags", "RESOURCE TAGS", lambda value: ", ".join(f"{key}={item}" for key, item in value.items()) if isinstance(value, dict) else value),
        ):
            value = finding.get(field)
            if not value:
                continue
            if field == "risk":
                risk_row_index = len(body_rows)
            body_rows.append([
                Paragraph(
                    f"<font color='{COLOR_RISK.hexval()}'><b>{heading}</b></font>"
                    if field == "risk"
                    else f"<b>{heading}</b>",
                    style["label"],
                ),
                Paragraph(
                    _rich_text(formatter(value)) if field in {"risk", "remediation", "status_extended"}
                    else _wrap_safe(formatter(value)),
                    ParagraphStyle(
                        f"FindingRisk{index}",
                        parent=style["small"],
                        textColor=COLOR_RISK if field == "risk" else TEXT_MAIN,
                    ),
                ),
            ])
        body_table = Table(body_rows, colWidths=[150, 369])
        body_table_styles = [
            ("BACKGROUND", (0, 0), (-1, -1), colors.white),
            ("LINEBELOW", (0, 0), (-1, -2), 0.35, BORDER_COLOR),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
        if risk_row_index is not None:
            body_table_styles.extend([
                ("BACKGROUND", (0, risk_row_index), (-1, risk_row_index), BG_RISK),
                ("LINEBEFORE", (1, risk_row_index), (1, risk_row_index), 2, COLOR_RISK),
            ])
        body_table.setStyle(TableStyle(body_table_styles))
        finding_content = Table([[header], [body_table]], colWidths=[519])
        finding_content.setStyle(TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        card = Table([["", finding_content]], colWidths=[4, 519])
        card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), severity_color),
            ("BOX", (0, 0), (-1, -1), 0.8, severity_color),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ]))
        content.extend([KeepTogether(card), Spacer(1, 8)])

    if manual_findings:
        content.extend([
            PageBreak(),
            Paragraph("5. Manual Verification Required", style["h1"]),
            Paragraph("The following checks require manual verification and cannot be fully evaluated automatically.", style["body"]),
            Spacer(1, 10),
        ])
        for finding in manual_findings:
            rows = [
                [Paragraph("<b>Check:</b>", style["label"]), Paragraph(f"<b>{_wrap_safe(finding.get('title'))}</b>", style["value"])],
                [Paragraph("<b>Service / Region:</b>", style["label"]), Paragraph(f"{_escape(str(finding.get('service') or '').upper())} / {_escape(finding.get('region'))}", style["value"])],
                [Paragraph("<b>Resource:</b>", style["label"]), Paragraph(f"<font face='Courier' size=8>{_wrap_safe(_resource(finding))}</font>", style["value"])],
                [Paragraph("<b>Details:</b>", style["label"]), Paragraph(_wrap_safe(finding.get("status_extended")), style["small"])],
            ]
            table = Table(rows, colWidths=[90, 433])
            table.setStyle(TableStyle([
                ("BOX", (0, 0), (-1, -1), 1, BORDER_COLOR), ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
                ("BACKGROUND", (0, 0), (0, -1), BG_INFO), ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            content.extend([KeepTogether(table), Spacer(1, 8)])

    if passed_findings:
        content.extend([
            PageBreak(),
            Paragraph("6. Passed Security Controls", style["h1"]),
            Paragraph("The following security controls successfully passed during the assessment.", style["body"]),
            Spacer(1, 10),
        ])
        rows = [[
            Paragraph("<b>Service</b>", style["header"]), Paragraph("<b>Check Title</b>", style["header"]),
            Paragraph("<b>Check ID</b>", style["header"]), Paragraph("<b>Region</b>", style["header"]),
            Paragraph("<b>Resource</b>", style["header"]),
        ]]
        for finding in passed_findings:
            rows.append([
                Paragraph(_escape(str(finding.get("service") or "").upper()), style["small"]),
                Paragraph(_wrap_safe(finding.get("title")), style["small"]),
                Paragraph(_wrap_safe(finding.get("check_id")), style["small"]),
                Paragraph(_escape(finding.get("region")), style["small"]),
                Paragraph(_wrap_safe(finding.get("resource_id") or "N/A"), style["small"]),
            ])
        table = Table(rows, colWidths=[60, 160, 100, 60, 143], repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BG_LIGHT), ("BOX", (0, 0), (-1, -1), 1, BORDER_COLOR),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR), ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        content.append(table)

    doc.build(content, canvasmaker=_NumberedCanvas)
    return buffer.getvalue()
