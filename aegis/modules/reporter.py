import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from rich.console import Console

console = Console()
ALLOWED_FORMATS = {"json", "md", "html"}


def _safe_json_for_html(data: Any) -> str:
    """Sérialise en JSON et neutralise les balises susceptibles d'introduire des XSS."""
    raw = json.dumps(data, indent=4, ensure_ascii=False)
    return (
        raw.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def generate_markdown_report(report: dict[str, Any]) -> str:
    """Génère un rapport Markdown structuré et propre."""
    safe_json = json.dumps(report.get("results", {}), indent=4, ensure_ascii=False).replace("```", "`\u200b``")
    return (
        f"# Rapport d'Audit & Sécurité — AEGIS\n\n"
        f"- **Framework :** `{report.get('tool', 'AEGIS Security Framework')}`\n"
        f"- **Version :** `{report.get('version', '0.2.0')}`\n"
        f"- **Module :** `{str(report.get('module', '')).upper()}`\n"
        f"- **Cible :** `{report.get('target', '')}`\n"
        f"- **Horodatage (UTC) :** `{report.get('timestamp', '')}`\n\n"
        f"---\n\n"
        f"## Résultats Détaillés\n\n"
        f"```json\n{safe_json}\n```\n"
    )


def generate_html_report(report: dict[str, Any]) -> str:
    """
    Génère un rapport HTML interactif durci avec Content-Security-Policy stricte
    et échappement intégral des données dynamiques.
    """
    module_escaped = html.escape(str(report.get("module", "")).upper())
    target_escaped = html.escape(str(report.get("target", "")))
    timestamp_escaped = html.escape(str(report.get("timestamp", "")))
    results_safe = _safe_json_for_html(report.get("results", {}))

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Durcissement de sécurité : CSP stricte et protection anti MIME-sniffing -->
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta name="referrer" content="no-referrer">
    <title>AEGIS Security Report — {module_escaped}</title>
    <style>
        :root {{
            --bg-color: #0b0f19;
            --card-bg: #111827;
            --accent: #00ff9d;
            --accent-glow: rgba(0, 255, 157, 0.2);
            --border-color: #1f2937;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            padding: 2.5rem 1rem;
            margin: 0;
            line-height: 1.6;
        }}
        .container {{
            max-width: 960px;
            margin: auto;
            background: var(--card-bg);
            padding: 2.5rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        }}
        .header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1.25rem;
            margin-bottom: 1.75rem;
        }}
        .header h1 {{
            margin: 0;
            color: var(--accent);
            font-size: 1.85rem;
            letter-spacing: -0.5px;
        }}
        .badge {{
            background: var(--accent-glow);
            color: var(--accent);
            padding: 0.35rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.85rem;
            font-weight: 600;
            border: 1px solid var(--accent);
        }}
        .meta-box {{
            background: #0d131f;
            padding: 1.25rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            border-left: 4px solid var(--accent);
        }}
        .meta-item {{
            margin: 0.4rem 0;
            display: flex;
            align-items: center;
        }}
        .meta-label {{
            font-weight: 600;
            color: var(--text-secondary);
            width: 170px;
        }}
        .meta-value {{
            color: #38bdf8;
            font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        }}
        pre {{
            background: #050811;
            color: #38bdf8;
            padding: 1.5rem;
            border-radius: 8px;
            overflow-x: auto;
            border: 1px solid var(--border-color);
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.92rem;
        }}
        .footer {{
            text-align: center;
            margin-top: 2.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ AEGIS Security Framework</h1>
            <span class="badge">{module_escaped}</span>
        </div>
        <div class="meta-box">
            <div class="meta-item"><span class="meta-label">Module exécuté :</span><span class="meta-value">{module_escaped}</span></div>
            <div class="meta-item"><span class="meta-label">Cible analysée :</span><span class="meta-value">{target_escaped}</span></div>
            <div class="meta-item"><span class="meta-label">Horodatage (UTC) :</span><span class="meta-value">{timestamp_escaped}</span></div>
        </div>
        <h2>Résultats et Télémétrie d'Audit</h2>
        <pre>{results_safe}</pre>
        <div class="footer">
            Généré automatiquement par <strong>AEGIS Security Framework v0.2.0</strong> — CyberAnonymat Project
        </div>
    </div>
</body>
</html>"""


def sanitize_filename_component(text: str) -> str:
    """Nettoie une chaîne pour empêcher toute traversée de chemin (path traversal) ou injection de nom de fichier."""
    # Suppression des séparateurs de dossiers et caractères de traversée
    cleaned = re.sub(r"[\/\\:\*\?\"<>\|\x00]", "_", text)
    cleaned = cleaned.replace("..", "_").strip(" ._")
    return cleaned[:50] or "target"


def save_report(module_name: str, target: str, data: Any, output_format: str = "json") -> Optional[Path]:
    """Sauvegarde les résultats d'un module dans aegis_reports/ avec protection anti-traversée de répertoire."""
    fmt = output_format.lower().strip()
    if fmt not in ALLOWED_FORMATS:
        console.print(f"[bold red][-][/bold red] Format de rapport non supporté : {output_format} (Formats autorisés : {', '.join(sorted(ALLOWED_FORMATS))})")
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    reports_dir = Path("aegis_reports").resolve()

    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        safe_mod = sanitize_filename_component(module_name)
        safe_tgt = sanitize_filename_component(target)
        filename = f"aegis_{safe_mod}_{safe_tgt}_{timestamp}.{fmt}"

        # Vérification stricte que le chemin résolu reste dans le dossier de rapports
        filepath = (reports_dir / filename).resolve()
        if not str(filepath).startswith(str(reports_dir)):
            console.print("[bold red][-][/bold red] Tentative d'évasion de répertoire détectée. Rapport annulé.")
            return None

        report_data = {
            "tool": "AEGIS Security Framework",
            "version": "0.2.0",
            "module": module_name,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "results": data,
        }

        if fmt == "json":
            content = json.dumps(report_data, indent=4, ensure_ascii=False)
        elif fmt == "md":
            content = generate_markdown_report(report_data)
        else:
            content = generate_html_report(report_data)

        filepath.write_text(content, encoding="utf-8")
        console.print(f"[bold green][✓][/bold green] Rapport {fmt.upper()} généré en toute sécurité : [cyan]{filepath}[/cyan]")
        return filepath
    except OSError as e:
        console.print(f"[bold red][-][/bold red] Erreur d'écriture du rapport : {e}")
        return None
