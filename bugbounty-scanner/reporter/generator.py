"""
reporter/generator.py
=====================
Automated Report Generator

Produces professional security reports in:
- HTML (styled, printable)
- JSON (machine-readable)
- Markdown (GitHub/Notion compatible)
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from loguru import logger
from jinja2 import Environment, BaseLoader

from core.models import ScanResult, Vulnerability, Severity


REPORTS_DIR = Path("reports")

# ── HTML Report Template ──────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Scan Report — {{ result.target }}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');
  :root {
    --bg:      #070B14; --bg2: #0C1220; --bg3: #111827; --card: #141E35;
    --cyan:    #00E5FF; --green: #00FF9D; --orange: #FF7043;
    --red:     #FF3D57; --purple: #A855F7; --white: #FFFFFF;
    --light:   #C9D8F0; --muted: #5C7090; --border: #1C2940;
  }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--light); font-family:'Inter',sans-serif; font-size:14px; line-height:1.6; }
  .container { max-width:1100px; margin:0 auto; padding:40px 24px; }
  /* ── Header ── */
  .report-header { background:var(--bg2); border:1px solid var(--border); border-radius:12px; padding:40px; margin-bottom:32px; position:relative; overflow:hidden; }
  .report-header::before { content:''; position:absolute; top:0; left:0; right:0; height:3px; background:linear-gradient(90deg,var(--cyan),var(--green),var(--purple)); }
  .report-title { font-size:28px; font-weight:700; color:var(--white); margin-bottom:8px; }
  .report-subtitle { color:var(--cyan); font-family:'JetBrains Mono',monospace; font-size:13px; }
  .report-meta { display:flex; gap:32px; margin-top:24px; flex-wrap:wrap; }
  .meta-item { display:flex; flex-direction:column; gap:4px; }
  .meta-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.1em; }
  .meta-value { font-size:14px; font-weight:600; color:var(--white); }
  /* ── Risk Badge ── */
  .risk-badge { display:inline-block; padding:6px 16px; border-radius:20px; font-size:12px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; }
  .risk-CRITICAL { background:rgba(255,61,87,.2); color:var(--red); border:1px solid var(--red); }
  .risk-HIGH     { background:rgba(255,112,67,.2); color:var(--orange); border:1px solid var(--orange); }
  .risk-MEDIUM   { background:rgba(255,193,7,.15); color:#FFC107; border:1px solid #FFC107; }
  .risk-LOW      { background:rgba(0,229,255,.1); color:var(--cyan); border:1px solid var(--cyan); }
  .risk-NONE     { background:rgba(0,255,157,.1); color:var(--green); border:1px solid var(--green); }
  /* ── Stats Grid ── */
  .stats-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:32px; }
  .stat-card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px; text-align:center; transition:border-color .2s; }
  .stat-card:hover { border-color:var(--cyan); }
  .stat-number { font-size:36px; font-weight:700; line-height:1; margin-bottom:8px; }
  .stat-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.1em; }
  .color-critical { color:var(--red); } .color-high { color:var(--orange); }
  .color-medium { color:#FFC107; } .color-low { color:var(--cyan); }
  .color-green { color:var(--green); } .color-purple { color:var(--purple); }
  /* ── Section ── */
  .section { margin-bottom:40px; }
  .section-title { font-size:18px; font-weight:600; color:var(--white); margin-bottom:16px; padding-bottom:8px; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:10px; }
  .section-icon { width:24px; height:24px; border-radius:6px; display:flex; align-items:center; justify-content:center; font-size:12px; }
  /* ── Vuln Card ── */
  .vuln-card { background:var(--card); border:1px solid var(--border); border-radius:10px; margin-bottom:16px; overflow:hidden; }
  .vuln-header { padding:16px 20px; display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; border-bottom:1px solid var(--border); }
  .vuln-title { font-size:15px; font-weight:600; color:var(--white); flex:1; }
  .vuln-body { padding:20px; }
  .vuln-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
  @media(max-width:600px) { .vuln-grid { grid-template-columns:1fr; } }
  .field-label { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; margin-bottom:4px; }
  .field-value { font-size:13px; color:var(--light); word-break:break-all; }
  .code-block { background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:12px 16px; font-family:'JetBrains Mono',monospace; font-size:12px; color:var(--green); overflow-x:auto; margin-top:8px; }
  .remediation { background:rgba(0,255,157,.05); border:1px solid rgba(0,255,157,.2); border-radius:8px; padding:16px; margin-top:16px; }
  .remediation-title { font-size:12px; font-weight:600; color:var(--green); text-transform:uppercase; letter-spacing:.08em; margin-bottom:8px; }
  .remediation-body { font-size:13px; color:var(--light); white-space:pre-line; }
  .cvss-score { font-family:'JetBrains Mono',monospace; font-size:20px; font-weight:700; }
  /* ── Attack Surface ── */
  .endpoint-row { display:flex; align-items:center; gap:12px; padding:10px 16px; border-bottom:1px solid var(--border); font-size:13px; }
  .endpoint-row:last-child { border-bottom:none; }
  .method-badge { font-size:10px; font-weight:700; padding:2px 8px; border-radius:4px; font-family:'JetBrains Mono',monospace; min-width:52px; text-align:center; }
  .method-GET    { background:rgba(0,229,255,.15); color:var(--cyan); }
  .method-POST   { background:rgba(0,255,157,.15); color:var(--green); }
  .method-PUT    { background:rgba(255,112,67,.15); color:var(--orange); }
  .method-DELETE { background:rgba(255,61,87,.15); color:var(--red); }
  /* ── Footer ── */
  .footer { text-align:center; padding:32px 0; color:var(--muted); font-size:12px; border-top:1px solid var(--border); margin-top:48px; }
  .warning-banner { background:rgba(255,112,67,.1); border:1px solid rgba(255,112,67,.3); border-radius:10px; padding:16px 20px; margin-bottom:32px; font-size:13px; color:var(--orange); }
</style>
</head>
<body>
<div class="container">
  <!-- Warning -->
  <div class="warning-banner">
    ⚠️ <strong>CONFIDENTIAL</strong> — This report contains sensitive security findings.
    Do not distribute. For authorized security testing only.
  </div>

  <!-- Header -->
  <div class="report-header">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:16px">
      <div>
        <div class="report-title">🔍 Security Scan Report</div>
        <div class="report-subtitle">AI-Powered Bug Bounty Autonomous Scanner v1.0.0</div>
      </div>
      <span class="risk-badge risk-{{ result.overall_risk }}">
        {{ result.overall_risk }} RISK
      </span>
    </div>
    <div class="report-meta">
      <div class="meta-item"><span class="meta-label">Target</span><span class="meta-value">{{ result.target }}</span></div>
      <div class="meta-item"><span class="meta-label">Scan ID</span><span class="meta-value" style="font-family:'JetBrains Mono',monospace;font-size:12px">{{ result.scan_id[:8] }}</span></div>
      <div class="meta-item"><span class="meta-label">Started</span><span class="meta-value">{{ result.started_at.strftime('%Y-%m-%d %H:%M UTC') if result.started_at else 'N/A' }}</span></div>
      <div class="meta-item"><span class="meta-label">Duration</span><span class="meta-value">{{ "%.1f"|format(result.duration_seconds) }}s</span></div>
      <div class="meta-item"><span class="meta-label">Endpoints</span><span class="meta-value">{{ result.endpoints|length }}</span></div>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-number" style="color:var(--white)">{{ result.vulnerabilities|length }}</div><div class="stat-label">Total Findings</div></div>
    <div class="stat-card"><div class="stat-number color-critical">{{ result.critical_count }}</div><div class="stat-label">Critical</div></div>
    <div class="stat-card"><div class="stat-number color-high">{{ result.high_count }}</div><div class="stat-label">High</div></div>
    <div class="stat-card"><div class="stat-number color-medium">{{ result.medium_count }}</div><div class="stat-label">Medium</div></div>
    <div class="stat-card"><div class="stat-number color-low">{{ result.low_count }}</div><div class="stat-label">Low</div></div>
    <div class="stat-card"><div class="stat-number color-green">{{ result.endpoints|length }}</div><div class="stat-label">Endpoints</div></div>
  </div>

  <!-- Vulnerabilities -->
  <div class="section">
    <div class="section-title">🐛 Vulnerability Findings</div>
    {% for vuln in result.vulnerabilities %}
    <div class="vuln-card">
      <div class="vuln-header">
        <div class="vuln-title">{{ vuln.title }}</div>
        <span class="risk-badge risk-{{ vuln.severity.value|upper }}">
          {{ vuln.severity.value|upper }}
        </span>
        {% if vuln.cvss_score > 0 %}
        <span class="cvss-score color-{% if vuln.cvss_score >= 9 %}critical{% elif vuln.cvss_score >= 7 %}high{% elif vuln.cvss_score >= 4 %}medium{% else %}low{% endif %}">
          CVSS {{ "%.1f"|format(vuln.cvss_score) }}
        </span>
        {% endif %}
      </div>
      <div class="vuln-body">
        <p style="color:var(--light);margin-bottom:16px">{{ vuln.description }}</p>
        <div class="vuln-grid">
          <div>
            <div class="field-label">Affected URL</div>
            <div class="field-value" style="color:var(--cyan)">{{ vuln.url }}</div>
          </div>
          <div>
            <div class="field-label">Vulnerability Type</div>
            <div class="field-value">{{ vuln.vuln_type.value }}</div>
          </div>
          {% if vuln.parameter %}
          <div>
            <div class="field-label">Vulnerable Parameter</div>
            <div class="field-value" style="font-family:'JetBrains Mono',monospace">{{ vuln.parameter }}</div>
          </div>
          {% endif %}
          {% if vuln.confidence > 0 %}
          <div>
            <div class="field-label">Confidence</div>
            <div class="field-value">{{ "%.0f"|format(vuln.confidence * 100) }}%</div>
          </div>
          {% endif %}
          {% if vuln.cwe_id %}
          <div><div class="field-label">CWE</div><div class="field-value">{{ vuln.cwe_id }}</div></div>
          {% endif %}
          {% if vuln.owasp_category %}
          <div><div class="field-label">OWASP</div><div class="field-value">{{ vuln.owasp_category }}</div></div>
          {% endif %}
        </div>
        {% if vuln.payload %}
        <div class="field-label">Proof of Concept Payload</div>
        <div class="code-block">{{ vuln.payload }}</div>
        {% endif %}
        {% if vuln.evidence %}
        <div class="field-label" style="margin-top:12px">Evidence</div>
        <div class="code-block">{{ vuln.evidence }}</div>
        {% endif %}
        {% if vuln.remediation %}
        <div class="remediation">
          <div class="remediation-title">✅ Remediation Advice</div>
          <div class="remediation-body">{{ vuln.remediation }}</div>
        </div>
        {% endif %}
      </div>
    </div>
    {% else %}
    <p style="color:var(--muted);text-align:center;padding:32px">No vulnerabilities found.</p>
    {% endfor %}
  </div>

  <!-- Attack Surface -->
  {% if result.endpoints %}
  <div class="section">
    <div class="section-title">🗺️ Attack Surface ({{ result.endpoints|length }} endpoints)</div>
    <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden">
      {% for ep in result.endpoints[:30] %}
      <div class="endpoint-row">
        <span class="method-badge method-{{ ep.method.value }}">{{ ep.method.value }}</span>
        <span style="color:var(--light);font-family:'JetBrains Mono',monospace;font-size:12px;flex:1;word-break:break-all">{{ ep.url }}</span>
        {% if ep.status_code %}<span style="color:var(--muted);font-size:12px">{{ ep.status_code }}</span>{% endif %}
        {% if ep.is_api %}<span class="risk-badge" style="font-size:10px;padding:2px 8px;background:rgba(168,85,247,.15);color:var(--purple);border-color:var(--purple)">API</span>{% endif %}
      </div>
      {% endfor %}
      {% if result.endpoints|length > 30 %}
      <div class="endpoint-row" style="color:var(--muted);justify-content:center">… and {{ result.endpoints|length - 30 }} more endpoints</div>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <!-- Recon -->
  {% if result.recon %}
  <div class="section">
    <div class="section-title">🔭 Reconnaissance Findings</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px">
      {% if result.recon.subdomains %}
      <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px">
        <div class="field-label" style="margin-bottom:12px">Subdomains ({{ result.recon.subdomains|length }})</div>
        {% for sub in result.recon.subdomains[:10] %}<div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--cyan);margin-bottom:4px">{{ sub }}</div>{% endfor %}
      </div>
      {% endif %}
      {% if result.recon.technologies %}
      <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px">
        <div class="field-label" style="margin-bottom:12px">Technologies Detected</div>
        {% for tech in result.recon.technologies %}<span style="display:inline-block;margin:3px;padding:4px 10px;background:rgba(0,229,255,.1);color:var(--cyan);border:1px solid rgba(0,229,255,.3);border-radius:16px;font-size:12px">{{ tech }}</span>{% endfor %}
      </div>
      {% endif %}
      {% if result.recon.ip_addresses %}
      <div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px">
        <div class="field-label" style="margin-bottom:12px">IP Addresses</div>
        {% for ip in result.recon.ip_addresses %}<div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--green);margin-bottom:4px">{{ ip }}</div>{% endfor %}
      </div>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <div class="footer">
    Generated by AI Bug Bounty Scanner v1.0.0 — {{ now }} UTC<br>
    <strong>⚠️ For authorized security testing only. Unauthorized use is illegal.</strong>
  </div>
</div>
</body>
</html>"""


class ReportGenerator:
    """Generates HTML, JSON, and Markdown security reports."""

    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir or REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def generate_all(self, result: ScanResult) -> Dict[str, str]:
        """Generate reports in all formats. Returns dict of format→path."""
        paths = {}
        scan_prefix = f"{result.scan_id[:8]}_{result.target.replace('.', '_')}"

        html_path = await self.generate_html(result, f"{scan_prefix}.html")
        json_path = await self.generate_json(result, f"{scan_prefix}.json")
        md_path   = await self.generate_markdown(result, f"{scan_prefix}.md")

        paths["html"] = str(html_path)
        paths["json"] = str(json_path)
        paths["markdown"] = str(md_path)

        logger.info(f"[REPORTER] Reports saved to {self.output_dir}")
        return paths

    async def generate_html(self, result: ScanResult, filename: str) -> Path:
        """Render HTML report from Jinja2 template."""
        env = Environment(loader=BaseLoader())
        template = env.from_string(HTML_TEMPLATE)
        html = template.render(
            result=result,
            now=datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
        )
        path = self.output_dir / filename
        path.write_text(html, encoding="utf-8")
        return path

    async def generate_json(self, result: ScanResult, filename: str) -> Path:
        """Generate machine-readable JSON report."""
        data = {
            "scan_id":          result.scan_id,
            "target":           result.target,
            "status":           result.status.value,
            "overall_risk":     result.overall_risk,
            "started_at":       result.started_at.isoformat() if result.started_at else None,
            "completed_at":     result.completed_at.isoformat() if result.completed_at else None,
            "duration_seconds": result.duration_seconds,
            "summary": {
                "total":    len(result.vulnerabilities),
                "critical": result.critical_count,
                "high":     result.high_count,
                "medium":   result.medium_count,
                "low":      result.low_count,
                "endpoints": len(result.endpoints),
            },
            "vulnerabilities": [
                {
                    "vuln_id":      v.vuln_id,
                    "type":         v.vuln_type.value,
                    "severity":     v.severity.value,
                    "title":        v.title,
                    "description":  v.description,
                    "url":          v.url,
                    "method":       v.method.value,
                    "parameter":    v.parameter,
                    "payload":      v.payload,
                    "evidence":     v.evidence,
                    "cvss_score":   v.cvss_score,
                    "cvss_vector":  v.cvss_vector,
                    "confidence":   v.confidence,
                    "remediation":  v.remediation,
                    "cwe":          v.cwe_id,
                    "owasp":        v.owasp_category,
                    "discovered_at": v.discovered_at.isoformat(),
                }
                for v in result.vulnerabilities
            ],
            "endpoints": [
                {"url": e.url, "method": e.method.value, "is_api": e.is_api,
                 "status_code": e.status_code}
                for e in result.endpoints
            ],
            "recon": {
                "subdomains":   result.recon.subdomains if result.recon else [],
                "technologies": result.recon.technologies if result.recon else [],
                "ip_addresses": result.recon.ip_addresses if result.recon else [],
            } if result.recon else None,
        }
        path = self.output_dir / filename
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    async def generate_markdown(self, result: ScanResult, filename: str) -> Path:
        """Generate Markdown report for GitHub/Notion."""
        lines = [
            f"# Security Scan Report — {result.target}",
            f"",
            f"> **Scan ID:** `{result.scan_id[:8]}`  ",
            f"> **Overall Risk:** `{result.overall_risk}`  ",
            f"> **Date:** {result.started_at.strftime('%Y-%m-%d') if result.started_at else 'N/A'}",
            f"",
            f"---",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {result.critical_count} |",
            f"| 🟠 High | {result.high_count} |",
            f"| 🟡 Medium | {result.medium_count} |",
            f"| 🔵 Low | {result.low_count} |",
            f"| **Total** | **{len(result.vulnerabilities)}** |",
            f"",
            f"**Endpoints Discovered:** {len(result.endpoints)}  ",
            f"**Scan Duration:** {result.duration_seconds:.1f}s",
            f"",
            f"---",
            f"",
            f"## Vulnerabilities",
            f"",
        ]

        for i, v in enumerate(result.vulnerabilities, 1):
            sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(v.severity.value, "⚪")
            lines += [
                f"### {i}. {sev_emoji} {v.title}",
                f"",
                f"- **Type:** {v.vuln_type.value}",
                f"- **Severity:** {v.severity.value.upper()} (CVSS {v.cvss_score:.1f})",
                f"- **URL:** `{v.url}`",
            ]
            if v.parameter:
                lines.append(f"- **Parameter:** `{v.parameter}`")
            if v.payload:
                lines += [f"", f"**Payload:**", f"```", f"{v.payload}", f"```"]
            if v.evidence:
                lines += [f"", f"**Evidence:** {v.evidence}"]
            if v.remediation:
                lines += [f"", f"**Remediation:**", f"", f"{v.remediation}"]
            lines += [f"", f"---", f""]

        path = self.output_dir / filename
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
