import socket
import ssl
from urllib.parse import urlparse
from typing import Optional, Any
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from aegis.modules.reporter import save_report

console = Console()

AEGIS_USER_AGENT = "AEGIS-Security-Framework/0.2.0 (+https://github.com/Belalingbi/aegis)"


def search_cves(keyword: str, max_results: int = 5) -> list[dict[str, Any]]:
    """Interroge l'API publique NIST NVD pour chercher des CVEs par mot-clé."""
    clean_keyword = keyword.strip()
    if not clean_keyword:
        return []

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={clean_keyword}&resultsPerPage={max_results}"
    console.print(f"[bold green][*][/bold green] Interrogation de la base NIST NVD pour : [cyan]{clean_keyword}[/cyan]...")

    headers = {"User-Agent": AEGIS_USER_AGENT}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            cve_list = []

            table = Table(title=f"CVEs Récentes Associées : {clean_keyword}")
            table.add_column("ID CVE", style="cyan", no_wrap=True)
            table.add_column("Sévérité (CVSS)", style="red")
            table.add_column("Description", style="white")

            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "N/A")

                descriptions = cve_data.get("descriptions", [])
                desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "Pas de description")
                if len(desc) > 95:
                    desc = desc[:95] + "..."

                metrics = cve_data.get("metrics", {})
                cvss_score = "N/A"
                if "cvssMetricV31" in metrics:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_score = f"{cvss_data.get('baseScore', 'N/A')} ({cvss_data.get('baseSeverity', 'N/A')})"
                elif "cvssMetricV30" in metrics:
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_score = f"{cvss_data.get('baseScore', 'N/A')} ({cvss_data.get('baseSeverity', 'N/A')})"

                table.add_row(cve_id, cvss_score, desc)
                cve_list.append({"id": cve_id, "score": cvss_score, "description": desc})

            if cve_list:
                console.print(table)
                return cve_list
            else:
                console.print(f"[yellow][!][/yellow] Aucune CVE trouvée pour : {clean_keyword}")
                return []
        elif response.status_code in {403, 429}:
            console.print(f"[yellow][!][/yellow] Limite de débit API NIST NVD atteinte (HTTP {response.status_code}). Réessayez dans un court instant.")
            return []
        else:
            console.print(f"[bold red][-][/bold red] Erreur API NVD (Statut : {response.status_code})")
            return []
    except requests.RequestException as e:
        console.print(f"[bold red][-][/bold red] Impossible de contacter l'API CVE : {e}")
        return []


def calculate_header_score(present_headers: dict[str, str], max_score: int = 100) -> tuple[int, str]:
    """Calcule une note de sécurité (A+, A, B, C, D, F) basée sur les en-têtes HTTP de sécurité."""
    weights = {
        "Strict-Transport-Security": 25,
        "Content-Security-Policy": 25,
        "X-Frame-Options": 15,
        "X-Content-Type-Options": 15,
        "Referrer-Policy": 10,
        "Permissions-Policy": 10,
    }

    score = 0
    for h, weight in weights.items():
        if h in present_headers and present_headers[h] != "ABSENT":
            score += weight

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return score, grade


def run_audit(target: str, cve_keyword: Optional[str] = None, output: Optional[str] = None) -> dict[str, Any]:
    """Fonction principale d'audit : Headers de sécurité HTTP, vérification SSL/TLS et CVEs NIST."""
    report_data: dict[str, Any] = {"headers": {}, "ssl": {}, "cves": [], "score": None, "grade": None}

    clean_target = target.strip()
    if not clean_target:
        console.print("[bold red][-][/bold red] Cible vide pour l'audit.")
        return report_data

    # Sécurisation du schéma d'URL (protection contre file://, gopher://, etc.)
    if "://" in clean_target:
        parsed_test = urlparse(clean_target)
        if parsed_test.scheme not in {"http", "https"}:
            console.print(f"[bold red][-][/bold red] Protocole non autorisé : '{parsed_test.scheme}'. Seuls HTTP et HTTPS sont permis.")
            return report_data
        target_url = clean_target
    else:
        target_url = "https://" + clean_target if "." in clean_target else clean_target

    parsed_url = urlparse(target_url) if "://" in target_url else None
    hostname = parsed_url.hostname if parsed_url and parsed_url.hostname else clean_target

    console.print(f"[bold green][*][/bold green] Lancement de l'audit de sécurité pour : [cyan]{clean_target}[/cyan]\n")

    if cve_keyword:
        report_data["cves"] = search_cves(cve_keyword)
    elif parsed_url and parsed_url.scheme in {"http", "https"}:
        # 1. Audit des en-têtes HTTP de sécurité
        headers_dict: dict[str, str] = {}
        try:
            req_headers = {"User-Agent": AEGIS_USER_AGENT}
            response = requests.get(target_url, headers=req_headers, timeout=8, allow_redirects=True)
            headers = response.headers

            table = Table(title=f"Audit des En-têtes HTTP — {hostname}")
            table.add_column("En-tête de Sécurité", style="cyan", no_wrap=True)
            table.add_column("État", style="bold")
            table.add_column("Analyse / Recommandation", style="magenta")

            security_headers = {
                "Strict-Transport-Security": "Force HTTPS (HSTS)",
                "Content-Security-Policy": "Protection contre les injections XSS & code malveillant",
                "X-Frame-Options": "Protection contre le Clickjacking (UI Redressing)",
                "X-Content-Type-Options": "Empêche le MIME-type sniffing",
                "Referrer-Policy": "Contrôle les métadonnées de navigation transmises",
                "Permissions-Policy": "Restreint l'accès aux capteurs & fonctionnalités du navigateur",
                "Server": "Bannière du serveur web (Divulgation d'infrastructure)",
            }

            for header, desc in security_headers.items():
                if header in headers:
                    val = headers[header]
                    headers_dict[header] = val
                    if header == "Server":
                        table.add_row(header, "[yellow]DIVULGUÉ[/yellow]", f"Valeur : {val} (Divulgation d'infos)")
                        tech_name = val.split("/")[0].split()[0].lower()
                        if tech_name and len(tech_name) > 2:
                            report_data["cves"] = search_cves(tech_name, max_results=3)
                    else:
                        table.add_row(header, "[green]CONFORME[/green]", val[:45] + "..." if len(val) > 45 else val)
                else:
                    headers_dict[header] = "ABSENT"
                    if header == "Server":
                        table.add_row(header, "[green]MASQUÉ[/green]", "Non divulgué (Excellente pratique)")
                    else:
                        table.add_row(header, "[red]ABSENT[/red]", f"Recommandé : {desc}")

            console.print(table)
            report_data["headers"] = headers_dict

            # Score et Grade
            score, grade = calculate_header_score(headers_dict)
            report_data["score"] = score
            report_data["grade"] = grade
            grade_color = "green" if grade in {"A+", "A"} else "yellow" if grade in {"B", "C"} else "red"
            console.print(Panel(
                f"[bold]Score de Durcissement HTTP :[/bold] [{grade_color}]{score}/100 (Grade: {grade})[/{grade_color}]\n"
                f"[dim]Plus le score est élevé, meilleure est la résilience contre les attaques web courantes (XSS, Clickjacking, MiTM).[/dim]",
                title="🛡️ Évaluation Posture HTTP",
                border_style=grade_color,
                expand=False
            ))

        except requests.RequestException as e:
            console.print(f"[bold red][-][/bold red] Erreur lors de la requête HTTP vers {target_url} : {e}")

        # 2. Audit du certificat SSL/TLS (si HTTPS)
        if parsed_url.scheme == "https" and hostname:
            console.print(f"\n[bold green][*][/bold green] Vérification du certificat SSL/TLS pour [cyan]{hostname}[/cyan]...")
            try:
                context = ssl.create_default_context()
                port = parsed_url.port or 443
                with socket.create_connection((hostname, port), timeout=6) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        tls_version = ssock.version()
                        if cert:
                            issuer = dict(x[0] for x in cert.get("issuer", ()))
                            subject = dict(x[0] for x in cert.get("subject", ()))
                            not_after = cert.get("notAfter", "Inconnu")

                            report_data["ssl"] = {
                                "issuer": issuer.get("commonName", "Inconnu"),
                                "subject": subject.get("commonName", "Inconnu"),
                                "expires": not_after,
                                "tls_version": tls_version,
                                "cipher": cipher[0] if cipher else "Inconnu",
                            }

                            console.print(f"  [green]•[/green] Version TLS : [bold]{tls_version}[/bold]")
                            console.print(f"  [green]•[/green] Chiffrement : {cipher[0] if cipher else 'N/A'}")
                            console.print(f"  [green]•[/green] Émetteur (CA) : {report_data['ssl']['issuer']}")
                            console.print(f"  [green]•[/green] Sujet (CN) : {report_data['ssl']['subject']}")
                            console.print(f"  [green]•[/green] Date d'expiration : [bold]{not_after}[/bold]")
            except Exception as e:
                console.print(f"[bold red][-][/bold red] Erreur de vérification SSL/TLS : {e}")
    else:
        # Recherche directe de CVE si la cible est un mot-clé ou logiciel
        report_data["cves"] = search_cves(clean_target)

    if output:
        save_report("audit", clean_target, report_data, output_format=output)

    return report_data
