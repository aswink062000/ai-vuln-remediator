"""
PDF Report Generator for vulnerability scan results.
Professional format similar to Burp Suite / OWASP ZAP reports.
Uses fpdf2 with Unicode font support.
"""

import io
import os
import logging
from datetime import datetime
from pathlib import Path
from fpdf import FPDF

logger = logging.getLogger(__name__)

# Download and cache DejaVu font for Unicode support
FONT_DIR = Path(__file__).parent / "fonts"
FONT_DIR.mkdir(exist_ok=True)


def _ensure_fonts():
    """Download DejaVuSans if not present (Unicode support)."""
    font_file = FONT_DIR / "DejaVuSans.ttf"
    bold_file = FONT_DIR / "DejaVuSans-Bold.ttf"

    if not font_file.exists():
        import requests
        base = "https://github.com/dejavu-fonts/dejavu-fonts/raw/main/ttf"
        for name, target in [("DejaVuSans.ttf", font_file), ("DejaVuSans-Bold.ttf", bold_file)]:
            try:
                r = requests.get(f"{base}/{name}", timeout=30)
                if r.status_code == 200:
                    target.write_bytes(r.content)
                    logger.info(f"Downloaded font: {name}")
            except Exception as e:
                logger.warning(f"Could not download {name}: {e}")

    return font_file.exists()


def _sanitize(text: str) -> str:
    """Replace problematic Unicode characters with ASCII equivalents."""
    if not text:
        return ""
    replacements = {
        '\u2014': '-',   # em dash
        '\u2013': '-',   # en dash
        '\u2018': "'",   # left single quote
        '\u2019': "'",   # right single quote
        '\u201c': '"',   # left double quote
        '\u201d': '"',   # right double quote
        '\u2026': '...', # ellipsis
        '\u2022': '*',   # bullet
        '\u00a0': ' ',   # non-breaking space
        '\u200b': '',    # zero-width space
        '\ufeff': '',    # BOM
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    # Remove any remaining non-latin1 characters
    return text.encode('latin-1', errors='replace').decode('latin-1')


class VulnerabilityReport(FPDF):
    """Professional vulnerability scan report."""

    def __init__(self):
        super().__init__()
        self.has_unicode = False

        # Try to load Unicode font
        if _ensure_fonts():
            font_file = FONT_DIR / "DejaVuSans.ttf"
            bold_file = FONT_DIR / "DejaVuSans-Bold.ttf"
            if font_file.exists():
                try:
                    self.add_font("DejaVu", "", str(font_file))
                    if bold_file.exists():
                        self.add_font("DejaVu", "B", str(bold_file))
                    self.has_unicode = True
                except Exception:
                    pass

    def _font(self, style="", size=10):
        if self.has_unicode:
            self.set_font("DejaVu", style, size)
        else:
            self.set_font("Helvetica", style, size)

    def header(self):
        # Header bar
        self.set_fill_color(30, 41, 59)  # slate-800
        self.rect(0, 0, 210, 28, "F")

        self._font("B", 16)
        self.set_text_color(255, 255, 255)
        self.set_y(6)
        self.cell(0, 8, "VULNERABILITY SCAN REPORT", align="C", new_x="LMARGIN", new_y="NEXT")

        self._font("", 9)
        self.set_text_color(180, 200, 220)
        self.cell(0, 5, "AI Vulnerability Remediator - Enterprise Security Platform", align="C", new_x="LMARGIN", new_y="NEXT")

        self.set_text_color(0, 0, 0)
        self.set_y(32)

    def footer(self):
        self.set_y(-15)
        self.set_fill_color(240, 240, 240)
        self.rect(0, self.get_y() - 2, 210, 20, "F")
        self._font("", 7)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  Page {self.page_no()}/{{nb}}  |  Confidential", align="C")


def generate_pdf_report(scan_data: dict) -> bytes:
    """Generate a professional PDF report from scan results."""
    pdf = VulnerabilityReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    # --- Executive Summary ---
    _section_title(pdf, "EXECUTIVE SUMMARY")

    status = scan_data.get("status", "unknown")
    total = scan_data.get("total_findings", 0)
    repo = scan_data.get("repo", "")
    summary = scan_data.get("scan_summary", {})
    project_info = scan_data.get("project_info", {})

    # Summary table
    _info_row(pdf, "Target Repository", _sanitize(repo or "N/A"))
    _info_row(pdf, "Scan Status", status.upper())
    _info_row(pdf, "Total Vulnerabilities", str(total))

    if project_info:
        langs = ", ".join(project_info.get("languages", []))
        frameworks = ", ".join(project_info.get("frameworks", []))
        _info_row(pdf, "Languages Detected", langs or "N/A")
        if frameworks:
            _info_row(pdf, "Frameworks", frameworks)

    pdf.ln(5)

    # --- Risk Score ---
    by_severity = summary.get("by_severity", {})
    if by_severity:
        _section_title(pdf, "RISK OVERVIEW")

        # Severity table header
        pdf._font("B", 9)
        pdf.set_fill_color(50, 60, 80)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(50, 7, "  SEVERITY", fill=True)
        pdf.cell(30, 7, "COUNT", align="C", fill=True)
        pdf.cell(60, 7, "RISK LEVEL", align="C", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

        row_alt = False
        for sev in ["CRITICAL", "HIGH", "ERROR", "MEDIUM", "WARNING", "MODERATE", "LOW", "INFO"]:
            count = by_severity.get(sev, 0)
            if count == 0:
                continue

            if row_alt:
                pdf.set_fill_color(245, 245, 250)
            else:
                pdf.set_fill_color(255, 255, 255)

            # Severity badge
            r, g, b = _severity_color(sev)
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf._font("B", 8)
            pdf.cell(50, 6, f"  {sev}", fill=True)

            pdf.set_text_color(0, 0, 0)
            pdf.set_fill_color(245 if row_alt else 255, 245 if row_alt else 255, 250 if row_alt else 255)
            pdf._font("", 9)
            pdf.cell(30, 6, str(count), align="C", fill=True)
            pdf.cell(60, 6, _risk_label(sev), align="C", fill=True, new_x="LMARGIN", new_y="NEXT")
            row_alt = not row_alt

        pdf.ln(5)

    # --- Scanner Breakdown ---
    by_scanner = summary.get("by_scanner", {})
    if by_scanner:
        _section_title(pdf, "SCANNER COVERAGE")
        for scanner, count in by_scanner.items():
            pdf._font("", 9)
            pdf.cell(5, 5, "")
            pdf.cell(0, 5, _sanitize(f"{scanner}: {count} finding(s)"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    # --- Remediation Summary (if scan-fix) ---
    pr_url = scan_data.get("pull_request")
    files_fixed = scan_data.get("files_fixed", [])
    sast_fixed = scan_data.get("sast_findings_fixed", 0)

    if pr_url or files_fixed:
        _section_title(pdf, "REMEDIATION APPLIED")

        if pr_url:
            _info_row(pdf, "Pull Request", _sanitize(pr_url))
        if sast_fixed:
            _info_row(pdf, "SAST Issues Fixed", str(sast_fixed))
        if files_fixed:
            _info_row(pdf, "Files Modified", str(len(files_fixed)))
            pdf.ln(2)
            pdf._font("B", 8)
            pdf.cell(0, 5, "  Fixed Files:", new_x="LMARGIN", new_y="NEXT")
            pdf._font("", 8)
            for ff in files_fixed:
                path = _sanitize(ff.get("path", ""))
                count = ff.get("findings_fixed", 0)
                pdf.cell(0, 4, f"    - {path} ({count} issue(s) fixed)", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(5)

    # --- Detailed Findings ---
    findings = scan_data.get("findings", scan_data.get("all_findings", []))
    if findings:
        pdf.add_page()
        _section_title(pdf, f"DETAILED FINDINGS ({len(findings)})")

        for i, finding in enumerate(findings[:100], 1):
            if pdf.get_y() > 245:
                pdf.add_page()

            severity = finding.get("severity", "MEDIUM")
            rule_id = _sanitize(finding.get("rule_id", "unknown"))
            file_path = _sanitize(finding.get("path", "N/A"))
            line = finding.get("line", "-")
            message = _sanitize(finding.get("message", "No description"))
            category = finding.get("metadata", {}).get("category", "")
            scanner = finding.get("metadata", {}).get("scanner", "")
            package = finding.get("metadata", {}).get("package", "")

            # Finding card
            r, g, b = _severity_color(severity)
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf._font("B", 8)
            pdf.cell(18, 5, f" {severity} ", fill=True)

            pdf.set_text_color(30, 30, 30)
            pdf._font("B", 9)
            pdf.cell(0, 5, f"  #{i}  {rule_id}", new_x="LMARGIN", new_y="NEXT")

            # Meta line
            pdf._font("", 7)
            pdf.set_text_color(80, 80, 80)
            meta_parts = [f"File: {file_path}:{line}"]
            if scanner:
                meta_parts.append(f"Scanner: {scanner}")
            if category:
                meta_parts.append(f"Type: {category}")
            if package:
                meta_parts.append(f"Package: {package}")
            pdf.cell(0, 4, "  " + "  |  ".join(meta_parts), new_x="LMARGIN", new_y="NEXT")

            # Description
            pdf.set_text_color(0, 0, 0)
            pdf._font("", 8)
            msg_display = message[:400]
            pdf.multi_cell(0, 4, f"  {msg_display}")

            # Separator
            pdf.set_draw_color(220, 220, 220)
            pdf.line(10, pdf.get_y() + 1, 200, pdf.get_y() + 1)
            pdf.ln(4)

    # Generate bytes
    return bytes(pdf.output())


def _section_title(pdf: VulnerabilityReport, title: str):
    """Render a section title with underline."""
    pdf._font("B", 11)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(59, 130, 246)  # blue
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 80, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(4)
    pdf.set_text_color(0, 0, 0)


def _info_row(pdf: VulnerabilityReport, label: str, value: str):
    """Render a label: value row."""
    pdf._font("B", 9)
    pdf.cell(50, 5, f"  {label}:")
    pdf._font("", 9)
    pdf.cell(0, 5, value, new_x="LMARGIN", new_y="NEXT")


def _severity_color(severity: str) -> tuple:
    """Get RGB color for severity level."""
    s = severity.upper()
    if s == "CRITICAL":
        return (180, 30, 30)
    if s in ("HIGH", "ERROR"):
        return (220, 100, 20)
    if s in ("MEDIUM", "WARNING", "MODERATE"):
        return (180, 150, 20)
    if s == "LOW":
        return (60, 130, 200)
    return (100, 100, 100)


def _risk_label(severity: str) -> str:
    """Get risk description for severity."""
    s = severity.upper()
    if s == "CRITICAL":
        return "Immediate action required"
    if s in ("HIGH", "ERROR"):
        return "High priority fix needed"
    if s in ("MEDIUM", "WARNING", "MODERATE"):
        return "Should be addressed"
    if s == "LOW":
        return "Low priority"
    return "Informational"
