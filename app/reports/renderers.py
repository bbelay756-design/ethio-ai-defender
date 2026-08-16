"""
Report Renderers Module for JSON, HTML, and Future PDF Export

Provides extensible report rendering architecture:
- JSONReportRenderer : Deterministic formatted JSON serializer.
- HTMLReportRenderer : Standalone, responsive, printable cybersecurity SOC report.
- PDFReportRenderer  : Architecture stub ready for headless browser or PDF library export.
"""

import abc
import json
import html
from typing import Dict, Any
from app.reports.models import SecurityReport, EvidenceTier


class BaseReportRenderer(abc.ABC):
    """
    Abstract Base Class for Report Renderers.
    """

    @abc.abstractmethod
    def render(self, report: SecurityReport) -> str:
        """Renders the SecurityReport into the target string/markup format."""
        pass


class JSONReportRenderer(BaseReportRenderer):
    """
    Structured JSON Report Renderer.
    """

    def __init__(self, indent: int = 2):
        self.indent = indent

    def render(self, report: SecurityReport) -> str:
        return json.dumps(report.to_dict(), indent=self.indent, ensure_ascii=False)


class HTMLReportRenderer(BaseReportRenderer):
    """
    Responsive Standalone HTML Report Renderer for SOC Analysts and Executives.
    """

    def render(self, report: SecurityReport) -> str:
        r_dict = report.to_dict()
        sec = r_dict["sections"]
        is_am = report.language == "am"

        # Badge CSS mapping
        tier_badges = {
            "OBSERVED": '<span class="badge badge-observed">OBSERVED</span>',
            "RULE-BASED": '<span class="badge badge-rule">RULE-BASED</span>',
            "AI-INTERPRETED": '<span class="badge badge-ai">AI-INTERPRETED</span>'
        }

        # Build evidence items HTML
        evidence_rows = ""
        for ev in sec["13_evidence"]:
            badge = tier_badges.get(ev["tier"], f'<span class="badge">{ev["tier"]}</span>')
            evidence_rows += f"""
            <tr class="evidence-row">
                <td>{badge}</td>
                <td><strong>{html.escape(ev['category'])}</strong></td>
                <td>{html.escape(ev['statement'])}</td>
            </tr>
            """

        # Build indicators items HTML
        indicator_cards = ""
        for ind in sec["9_suspicious_indicators"]:
            indicator_cards += f"""
            <div class="indicator-item">
                <div class="ind-header">
                    <span class="ind-id">{html.escape(ind.get('id', 'IND'))}</span>
                    <span class="ind-name">{html.escape(ind.get('name', 'Finding'))}</span>
                    <span class="ind-sev">{html.escape(ind.get('severity', 'MEDIUM'))}</span>
                </div>
                <div class="ind-body">{html.escape(ind.get('evidence', ''))}</div>
                <div class="ind-exp"><em>{html.escape(ind.get('explanation', ''))}</em></div>
            </div>
            """

        # Build benign explanations HTML
        benign_items = "".join([f"<li>{html.escape(b)}</li>" for b in sec["14_possible_benign_explanations"]])
        # Build recommendations HTML
        rec_items = "".join([f"<li>{html.escape(r)}</li>" for r in sec["15_recommended_investigation"]])
        # Build limitations HTML
        lim_items = "".join([f"<li>{html.escape(l)}</li>" for l in sec["16_limitations"]])

        title_text = "ETHIO-AI DEFENDER - SECURITY ANALYSIS REPORT" if not is_am else "ETHIO-AI DEFENDER - የደህንነት ትንተና ሪፖርት"

        score_val = sec["10_threat_score"].get("score", 0)
        risk_val = sec["10_threat_score"].get("risk_level", "LOW")

        html_out = f"""<!DOCTYPE html>
<html lang="{report.language}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title_text} - {html.escape(report.report_id)}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --surface-color: #111827;
            --border-color: #1f2937;
            --text-color: #f3f4f6;
            --text-muted: #9ca3af;
            --accent-color: #3b82f6;
            --critical-color: #ef4444;
            --high-color: #f97316;
            --medium-color: #eab308;
            --low-color: #22c55e;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 30px 20px;
            line-height: 1.6;
        }}
        .report-container {{
            max-width: 1000px;
            margin: 0 auto;
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 36px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
        }}
        .header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .header-title h1 {{
            margin: 0;
            font-size: 24px;
            color: var(--text-color);
            letter-spacing: -0.5px;
        }}
        .header-meta {{
            font-size: 13px;
            color: var(--text-muted);
            margin-top: 5px;
        }}
        .score-box {{
            text-align: center;
            background: #1f2937;
            padding: 12px 24px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .score-val {{
            font-size: 32px;
            font-weight: 800;
            color: var(--accent-color);
        }}
        .score-level {{
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        h2 {{
            font-size: 17px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
            margin-top: 30px;
            color: var(--accent-color);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }}
        .info-card {{
            background: #0f172a;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            font-size: 14px;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            padding: 4px 0;
            border-bottom: 1px solid #1e293b;
        }}
        .info-label {{
            color: var(--text-muted);
        }}
        .info-val {{
            font-family: Consolas, monospace;
            word-break: break-all;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-observed {{ background: #065f46; color: #6ee7b7; }}
        .badge-rule {{ background: #1e40af; color: #93c5fd; }}
        .badge-ai {{ background: #6b21a8; color: #d8b4fe; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 13px;
        }}
        th, td {{
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            color: var(--text-muted);
            font-weight: 600;
        }}
        .indicator-item {{
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 10px;
        }}
        .ind-header {{
            display: flex;
            justify-content: space-between;
            font-weight: 600;
            margin-bottom: 6px;
        }}
        .ind-id {{ color: var(--accent-color); font-family: monospace; }}
        .ind-body {{ font-size: 13px; color: var(--text-color); }}
        .ind-exp {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
        .disclaimer-footer {{
            margin-top: 40px;
            padding: 16px;
            background: #0f172a;
            border-left: 4px solid var(--accent-color);
            font-size: 12px;
            color: var(--text-muted);
        }}
        @media print {{
            body {{ background: white; color: black; padding: 0; }}
            .report-container {{ border: none; box-shadow: none; padding: 0; }}
            .info-card, .indicator-item {{ background: #f8fafc; border: 1px solid #e2e8f0; color: black; }}
            .info-val, .ind-body {{ color: black; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <div class="header">
            <div class="header-title">
                <h1>{title_text}</h1>
                <div class="header-meta">
                    Report ID: <strong>{html.escape(report.report_id)}</strong> | 
                    Generated: {html.escape(report.generated_at)} | 
                    Language: {html.escape(report.language.upper())}
                </div>
            </div>
            <div class="score-box">
                <div class="score-val">{score_val}</div>
                <div class="score-level">{risk_val}</div>
            </div>
        </div>

        <!-- 1. Executive Summary -->
        <h2>1. Executive Summary</h2>
        <div class="info-card">
            <p>{html.escape(sec["1_executive_summary"])}</p>
        </div>

        <!-- 2 & 3. File Info and Hashes -->
        <div class="grid-2">
            <div>
                <h2>2. File Information</h2>
                <div class="info-card">
                    <div class="info-row"><span class="info-label">Filename:</span><span class="info-val">{html.escape(str(sec["2_file_information"].get("filename", "N/A")))}</span></div>
                    <div class="info-row"><span class="info-label">File Size:</span><span class="info-val">{sec["2_file_information"].get("file_size", 0)} bytes</span></div>
                    <div class="info-row"><span class="info-label">Format:</span><span class="info-val">{html.escape(str(sec["2_file_information"].get("file_kind", "EXE")))}</span></div>
                    <div class="info-row"><span class="info-label">Target Architecture:</span><span class="info-val">{html.escape(str(sec["2_file_information"].get("machine_type", "x64")))}</span></div>
                </div>
            </div>
            <div>
                <h2>3. Cryptographic Hashes</h2>
                <div class="info-card">
                    <div class="info-row"><span class="info-label">SHA-256:</span><span class="info-val">{html.escape(str(sec["3_hashes"].get("sha256", "N/A")))}</span></div>
                    <div class="info-row"><span class="info-label">SHA-1:</span><span class="info-val">{html.escape(str(sec["3_hashes"].get("sha1", "N/A")))}</span></div>
                    <div class="info-row"><span class="info-label">MD5:</span><span class="info-val">{html.escape(str(sec["3_hashes"].get("md5", "N/A")))}</span></div>
                </div>
            </div>
        </div>

        <!-- 4, 5, 6. PE, Sections, Entropy -->
        <div class="grid-2">
            <div>
                <h2>4 & 5. PE & Section Analysis</h2>
                <div class="info-card">
                    <div class="info-row"><span class="info-label">Total Sections:</span><span class="info-val">{sec["5_section_analysis"].get("total_sections", 0)}</span></div>
                    <div class="info-row"><span class="info-label">W+X Permissions:</span><span class="info-val">{'DETECTED' if sec["5_section_analysis"].get("has_wx_sections") else 'NONE'}</span></div>
                    <div class="info-row"><span class="info-label">Subsystem:</span><span class="info-val">{html.escape(str(sec["4_pe_information"].get("subsystem", "Windows GUI")))}</span></div>
                </div>
            </div>
            <div>
                <h2>6. Entropy Analysis</h2>
                <div class="info-card">
                    <div class="info-row"><span class="info-label">Shannon Entropy:</span><span class="info-val">{sec["6_entropy_analysis"].get("file_entropy", 0.0):.2f} / 8.0</span></div>
                    <div class="info-row"><span class="info-label">Classification:</span><span class="info-val">{html.escape(str(sec["6_entropy_analysis"].get("classification", "NORMAL")))}</span></div>
                </div>
            </div>
        </div>

        <!-- 7 & 8. Strings & Imports -->
        <div class="grid-2">
            <div>
                <h2>7. String Analysis</h2>
                <div class="info-card">
                    <div class="info-row"><span class="info-label">Extracted URLs:</span><span class="info-val">{len(sec["7_string_analysis"].get("urls", []))}</span></div>
                    <div class="info-row"><span class="info-label">IP Addresses:</span><span class="info-val">{len(sec["7_string_analysis"].get("ip_addresses", []))}</span></div>
                    <div class="info-row"><span class="info-label">Registry Paths:</span><span class="info-val">{len(sec["7_string_analysis"].get("registry_paths", []))}</span></div>
                </div>
            </div>
            <div>
                <h2>8. Import / API Analysis</h2>
                <div class="info-card">
                    <div class="info-row"><span class="info-label">Total Imports:</span><span class="info-val">{sec["8_import_api_analysis"].get("total_imports", 0)}</span></div>
                    <div class="info-row"><span class="info-label">Categories:</span><span class="info-val">{html.escape(', '.join(sec["8_import_api_analysis"].get("categories_present", [])) or 'None')}</span></div>
                </div>
            </div>
        </div>

        <!-- 9. Suspicious Indicators -->
        <h2>9. Correlated Suspicious Indicators</h2>
        {indicator_cards or '<div class="info-card">No severe correlated indicators detected.</div>'}

        <!-- 10 & 11. Threat Score & Ethiopian Context -->
        <div class="grid-2">
            <div>
                <h2>10. Heuristic Threat Score</h2>
                <div class="info-card">
                    <div class="info-row"><span class="info-label">Calculated Score:</span><span class="info-val">{score_val} / 100</span></div>
                    <div class="info-row"><span class="info-label">Assigned Risk Level:</span><span class="info-val">{risk_val}</span></div>
                </div>
            </div>
            <div>
                <h2>11. Ethiopian Context</h2>
                <div class="info-card">
                    <div class="info-row"><span class="info-label">Environment:</span><span class="info-val">{html.escape(str(sec["11_ethiopian_context"].get("environment", "GENERAL")))}</span></div>
                    <div class="info-row"><span class="info-label">Sector Relevance:</span><span class="info-val">{html.escape(str(sec["11_ethiopian_context"].get("relevance", "LOW")))}</span></div>
                    <div class="info-row"><span class="info-label">Reasoning:</span><span class="info-val">{html.escape(str(sec["11_ethiopian_context"].get("reason", "")))}</span></div>
                </div>
            </div>
        </div>

        <!-- 12. AI Assessment -->
        <h2>12. AI Security Analyst Interpretation</h2>
        <div class="info-card">
            <p><strong>Assessment:</strong> {html.escape(str(sec["12_ai_assessment"].get("assessment", risk_val)))} (Confidence: {html.escape(str(sec["12_ai_assessment"].get("confidence", "MEDIUM")))})</p>
            <p>{html.escape(str(sec["12_ai_assessment"].get("summary", "")))}</p>
        </div>

        <!-- 13. Evidence (Tri-tiered Model) -->
        <h2>13. Epistemological Evidence Model</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 140px;">Certainty Tier</th>
                    <th style="width: 180px;">Category</th>
                    <th>Statement / Finding</th>
                </tr>
            </thead>
            <tbody>
                {evidence_rows}
            </tbody>
        </table>

        <!-- 14, 15, 16. Benign Explanations, Investigation, Limitations -->
        <h2>14. Possible Benign Explanations</h2>
        <ul style="color: var(--text-color); font-size: 14px;">{benign_items}</ul>

        <h2>15. Recommended Investigation</h2>
        <ul style="color: var(--text-color); font-size: 14px;">{rec_items}</ul>

        <h2>16. Limitations</h2>
        <ul style="color: var(--text-color); font-size: 14px;">{lim_items}</ul>

        <!-- Mandatory Disclaimer Footer -->
        <div class="disclaimer-footer">
            <strong>Mandatory Defensive Notice:</strong> {html.escape(report.disclaimer)}
        </div>
    </div>
</body>
</html>"""
        return html_out


class PDFReportRenderer(BaseReportRenderer):
    """
    Pluggable PDF Report Renderer Architecture.
    Prepares HTML markup with print directives ready for PDF document generators.
    """

    def __init__(self):
        self.html_renderer = HTMLReportRenderer()

    def render(self, report: SecurityReport) -> str:
        """
        Renders print-ready HTML payload configured with @page and PDF styles.
        """
        raw_html = self.html_renderer.render(report)
        return raw_html
