"""Automated forensic reporting: turns an evidence record into a PDF report."""

import io
from html import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

from .scoring import BENIGN_MAX, SUSPICIOUS_MAX, TOOL_NAME

INK = colors.HexColor("#1B2430")
MUTED = colors.HexColor("#5B6573")
RULE = colors.HexColor("#D5DAE1")
HEAD_BG = colors.HexColor("#EEF1F5")
VERDICT_COLOURS = {"Benign": colors.HexColor("#2E7D4F"),
                   "Suspicious": colors.HexColor("#B7791F"),
                   "Malicious": colors.HexColor("#B42318")}

_base = getSampleStyleSheet()
S = {
    "title": ParagraphStyle("t", parent=_base["Title"], fontName="Helvetica-Bold", fontSize=17,
                            textColor=INK, alignment=TA_LEFT, spaceAfter=2),
    "sub": ParagraphStyle("s", parent=_base["Normal"], fontSize=9, textColor=MUTED, spaceAfter=10),
    "h2": ParagraphStyle("h2", parent=_base["Heading2"], fontName="Helvetica-Bold", fontSize=12,
                         textColor=INK, spaceBefore=12, spaceAfter=6),
    "body": ParagraphStyle("b", parent=_base["Normal"], fontSize=9, leading=12.5, textColor=INK),
    "cell": ParagraphStyle("c", parent=_base["Normal"], fontSize=8, leading=10, textColor=INK),
    "cellb": ParagraphStyle("cb", parent=_base["Normal"], fontName="Helvetica-Bold", fontSize=8,
                            leading=10, textColor=INK),
    "mono": ParagraphStyle("m", parent=_base["Normal"], fontName="Courier", fontSize=7.5,
                           leading=9.5, textColor=INK),
}


def _p(text, style="cell"):
    safe = escape(str(text if text not in (None, "") else "-"))
    return Paragraph(safe.encode("latin-1", "replace").decode("latin-1"), S[style])


def _kv_table(rows, widths=(55 * mm, 115 * mm)):
    body = [[_p(k, "cellb"), _p(v) if not isinstance(v, Paragraph) else v] for k, v in rows]
    t = Table(body, colWidths=widths)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("BACKGROUND", (0, 0), (0, -1), HEAD_BG),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


ACRONYMS = {"url": "URL", "tld": "TLD", "tls": "TLS", "cn": "CN", "org": "organisation",
            "san": "SAN", "sha256": "SHA-256", "utc": "UTC", "ca": "CA"}


def _pretty(key: str) -> str:
    words = [ACRONYMS.get(w, w) for w in key.split("_")]
    text = " ".join(words)
    return text[0].upper() + text[1:]


def _fmt(value):
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items()) or "-"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) or "-"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return value


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 10 * mm, f"{TOOL_NAME} - automated forensic triage report")
    canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(record: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=18 * mm,
                            title="URL Forensic Examination Report", author=record["case"]["examiner"])
    case, target, a = record["case"], record["target"], record["assessment"]
    story = []

    story.append(Paragraph("URL Forensic Examination Report", S["title"]))
    story.append(Paragraph(escape(f"{case['tool']}  |  Generated {case['finished_utc']} (UTC)"), S["sub"]))

    # Verdict banner
    colour = VERDICT_COLOURS[a["verdict"]]
    cls = a["classification"]
    banner = Table([[Paragraph(f"<font color='white'><b>{cls['threat_type'].upper()}</b><br/>"
                               f"<font size=9>Risk level: {a['verdict']}</font></font>",
                               ParagraphStyle("v", fontSize=15, leading=18)),
                     Paragraph(f"<font color='white'>Risk score <b>{a['score']}/100</b><br/>"
                               f"{a['risk_indicator_count']} risk indicator(s)</font>",
                               ParagraphStyle("v2", fontSize=10, leading=13))]],
                   colWidths=(85 * mm, 85 * mm))
    banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colour),
                                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    story += [banner, Spacer(1, 4)]
    if a.get("override"):
        story.append(Paragraph(escape(a["override"]), S["body"]))

    story.append(Paragraph(escape(cls["description"]), S["body"]))

    story.append(Paragraph("1. Threat classification", S["h2"]))
    story.append(_kv_table([
        ("Threat type", cls["threat_type"]),
        ("Confidence", cls["confidence"]),
        ("Phishing evidence score", f"{cls['phishing_score']}/100"),
        ("Malware evidence score", f"{cls['malware_score']}/100"),
        ("Backed by vendor labels", "Yes" if cls["vendor_backed"] else "No"),
    ]))
    if cls["evidence"]:
        rows = [[_p("Points to", "cellb"), _p("Source", "cellb"), _p("Evidence", "cellb"), _p("Weight", "cellb")]]
        rows += [[_p(e["type"]), _p(e["source"]), _p(e["reason"]), _p(e["points"])] for e in cls["evidence"]]
        t = Table(rows, colWidths=(28 * mm, 26 * mm, 100 * mm, 16 * mm), repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, RULE),
                               ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [Spacer(1, 4), t]

    story.append(Paragraph("2. Case information", S["h2"]))
    story.append(_kv_table([
        ("Case reference", case["case_reference"]), ("Examiner", case["examiner"]),
        ("Examination ID", case["examination_id"]), ("Started (UTC)", case["started_utc"]),
        ("Finished (UTC)", case["finished_utc"]), ("Duration", f"{case['duration_seconds']} s"),
        ("Tool", case["tool"]), ("Environment", case["environment"]),
    ]))

    story.append(Paragraph("3. Examined artifact", S["h2"]))
    story.append(_kv_table([
        ("Submitted input", target["submitted_input"]),
        ("Defanged URL", target["defanged_url"]),
        ("URL SHA-256", Paragraph(escape(target["url_sha256"]), S["mono"])),
    ] + ([("Redirect chain", " -> ".join(target["redirect_chain"])),
          ("Analyzed destination", target["analyzed_url"])] if len(target.get("redirect_chain") or []) > 1 else [])
      + ([("Redirect note", target["redirect_note"])] if target.get("redirect_note") else [])))

    story.append(Paragraph("4. Risk indicators", S["h2"]))
    rows = [[_p("Vector", "cellb"), _p("Indicator", "cellb"), _p("Detail", "cellb"),
             _p("Severity", "cellb"), _p("Points", "cellb")]]
    for f in a["indicators"]:
        rows.append([_p(f["vector"]), _p(f["check"]), _p(f["detail"]), _p(f["severity"]),
                     _p(f"{f['points']:+d}" if f["points"] else "0")])
    if len(rows) == 1:
        rows.append([_p("-"), _p("No indicators raised"), _p(""), _p(""), _p("0")])
    t = Table(rows, colWidths=(20 * mm, 38 * mm, 82 * mm, 16 * mm, 14 * mm), repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, RULE),
                           ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    story.append(Spacer(1, 4))
    story.append(Paragraph(escape(
        f"Scoring: points from all indicators are summed and clamped to 0-100. "
        f"0-{BENIGN_MAX} Benign, {BENIGN_MAX + 1}-{SUSPICIOUS_MAX} Suspicious, "
        f"{SUSPICIOUS_MAX + 1}-100 Malicious. Raw total: {a['raw_points']}. "
        f"Points by vector: " + ", ".join(f"{k} {v:+d}" for k, v in a['points_by_vector'].items())
    ), S["body"]))

    section = 5
    for vector, block in record["vectors"].items():
        rows = [("Status", block["status"])]
        for k, v in block["data"].items():
            if k in ("flagging_engines", "subject_alt_names") and v:
                v = _fmt(v)
            rows.append((_pretty(k), _fmt(v)))
        story.append(KeepTogether([Paragraph(f"{section}. {escape(vector)} analysis", S["h2"]),
                                   _kv_table(rows)]))
        section += 1

    story.append(Paragraph(f"{section}. Evidence integrity", S["h2"]))
    story.append(_kv_table([
        ("Algorithm", record["integrity"]["algorithm"]),
        ("Evidence hash", Paragraph(escape(record["integrity"]["evidence_hash"]), S["mono"])),
    ]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "The evidence hash is computed over the full JSON evidence record exported alongside this "
        "report (canonical form, keys sorted, excluding the integrity block). Re-hashing the JSON "
        "export must reproduce this value; any mismatch indicates the record was altered.", S["body"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Limitations: this is passive, static triage. Findings depend on third-party WHOIS and threat "
        "intelligence availability and do not include dynamic page execution. Results support, but "
        "do not replace, examiner judgement.", S["body"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
