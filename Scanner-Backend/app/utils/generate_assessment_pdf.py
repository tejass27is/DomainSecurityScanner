from __future__ import annotations

import io
from datetime import datetime
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def generate_assessment_pdf_bytes(assessment: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=50,
        rightMargin=50,
        topMargin=50,
        bottomMargin=50,
        title="Cyber Security Assessment Report",
    )

    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("<b>Cyber Security Assessment Report</b>", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))

    summary = assessment.get("summary") or {}
    risk_level = summary.get("risk_level") or ""
    grade = summary.get("grade") or ""
    story.append(Paragraph(f"<b>Risk Level:</b> {risk_level}", styles["Heading2"]))
    story.append(Paragraph(f"<b>Grade:</b> {grade}", styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))

    # Overall summary
    story.append(Paragraph("<b>Overall Score Summary</b>", styles["Heading2"]))
    story.append(Spacer(1, 0.1 * inch))

    overall_rows = [
        ["Total Score", str(summary.get("score", ""))],
        ["Total Questions", str(summary.get("total_questions", ""))],
        ["Maximum Possible Score", str(summary.get("max_possible_score", ""))],
        ["Percentage", f'{summary.get("percentage", "")}%'],
    ]
    overall_table = Table(overall_rows, colWidths=[2.5 * inch, 3.0 * inch])
    overall_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#374151")),
                ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(overall_table)
    story.append(Spacer(1, 0.3 * inch))

    # Category-wise performance
    story.append(Paragraph("<b>Category-wise Performance</b>", styles["Heading2"]))
    story.append(Spacer(1, 0.1 * inch))

    cat_scores = assessment.get("category_scores") or []
    cat_rows = [["#", "Category", "Grade", "Risk", "Percentage"]]
    for i, cat in enumerate(cat_scores, start=1):
        cat_rows.append(
            [
                str(i),
                str(cat.get("category_name", "")),
                str(cat.get("grade", "")),
                str(cat.get("risk", "")),
                f'{cat.get("percentage", "")}%',
            ]
        )
    cat_table = Table(cat_rows, colWidths=[0.4 * inch, 2.8 * inch, 0.7 * inch, 1.0 * inch, 1.1 * inch])
    cat_table.setStyle(
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
    story.append(cat_table)
    story.append(Spacer(1, 0.3 * inch))

    # Q/A summary
    answers = assessment.get("answers") or []
    if len(answers) > 0:
        story.append(Paragraph("<b>Question &amp; Answer Summary</b>", styles["Heading2"]))
        story.append(Spacer(1, 0.1 * inch))
        for i, ans in enumerate(answers, start=1):
            q_text = ans.get("questionText") or ans.get("question") or ""
            sel = ans.get("selectedOption") or {}
            sel_text = sel.get("option_text") if isinstance(sel, dict) else None
            points = ans.get("pointsAwarded", "")
            story.append(Paragraph(f"<b>Q{i}. {q_text}</b>", styles["BodyText"]))
            story.append(Paragraph(f"Selected Answer: {sel_text or 'Not Answered'}", styles["BodyText"]))
            story.append(Paragraph(f"Points Awarded: {points}", styles["BodyText"]))
            story.append(Spacer(1, 0.15 * inch))

    # Footer
    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | CyberGuard Security System",
            styles["Normal"],
        )
    )

    doc.build(story)
    return buf.getvalue()

