import hashlib
import math
import os
import re
from pathlib import Path
from typing import Optional, Any
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from aegis.modules.reporter import save_report

console = Console()
CHUNK_SIZE = 65536
MAX_DISPLAY_STRINGS = 10

# Motifs de détection d'indicateurs de compromission (IOCs)
IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
URL_REGEX = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")


def calculate_hashes(file_path: Path) -> Optional[dict[str, str]]:
    """Calcule les empreintes cryptographiques d'un fichier (MD5, SHA-1, SHA-256, SHA-512) par blocs (chunks)."""
    sha512_hash = hashlib.sha512()
    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5()

    try:
        with file_path.open("rb") as f:
            for byte_block in iter(lambda: f.read(CHUNK_SIZE), b""):
                sha512_hash.update(byte_block)
                sha256_hash.update(byte_block)
                sha1_hash.update(byte_block)
                md5_hash.update(byte_block)
        return {
            "md5": md5_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
            "sha512": sha512_hash.hexdigest(),
        }
    except OSError as e:
        console.print(f"[bold red][-][/bold red] Erreur de lecture fichier (hashes) : {e}")
        return None


def calculate_entropy(file_path: Path) -> float:
    """Calcule l'entropie de Shannon (0 à 8) en flux par blocs pour éviter la surcharge mémoire."""
    byte_counts = [0] * 256
    total_bytes = 0

    try:
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                total_bytes += len(chunk)
                for byte in chunk:
                    byte_counts[byte] += 1

        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p_x = count / total_bytes
                entropy -= p_x * math.log2(p_x)
        return entropy
    except OSError as e:
        console.print(f"[bold red][-][/bold red] Erreur de lecture fichier (entropie) : {e}")
        return 0.0


def extract_strings(file_path: Path, min_len: int = 5, max_strings: int = 5000) -> list[str]:
    """Extrait les chaînes ASCII imprimables par blocs en gérant les frontières entre chunks."""
    if min_len < 1:
        min_len = 1

    strings: list[str] = []
    current_chars: list[str] = []

    try:
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                for byte in chunk:
                    if 32 <= byte <= 126:
                        current_chars.append(chr(byte))
                    else:
                        if len(current_chars) >= min_len:
                            strings.append("".join(current_chars))
                            if len(strings) >= max_strings:
                                return strings
                        current_chars.clear()

        if len(current_chars) >= min_len and len(strings) < max_strings:
            strings.append("".join(current_chars))
    except OSError as e:
        console.print(f"[bold red][-][/bold red] Erreur de lecture fichier (chaînes) : {e}")

    return strings


def extract_iocs_from_strings(strings: list[str]) -> dict[str, list[str]]:
    """Identifie des indicateurs de compromission (IOCs) potentiels dans les chaînes extraites."""
    joined = "\n".join(strings)
    raw_ips = list(set(IPV4_REGEX.findall(joined)))
    raw_urls = list(set(URL_REGEX.findall(joined)))
    raw_emails = list(set(EMAIL_REGEX.findall(joined)))

    # Filtrer les fausses alertes locales/inutiles
    filtered_ips = [ip for ip in raw_ips if not ip.startswith("0.") and ip != "255.255.255.255"][:15]
    filtered_urls = [u for u in raw_urls if len(u) < 120][:15]
    filtered_emails = raw_emails[:15]

    return {
        "ips": sorted(filtered_ips),
        "urls": sorted(filtered_urls),
        "emails": sorted(filtered_emails),
    }


def check_virustotal(sha256_hash: str) -> Optional[dict[str, Any]]:
    """Interroge l'API VirusTotal v3 avec le hash SHA-256 via la variable d'environnement VT_API_KEY."""
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        console.print(
            "[bold yellow][!][/bold yellow] Clé API VirusTotal non définie. "
            "Configurez la variable d'environnement [cyan]VT_API_KEY[/cyan]."
        )
        console.print("[dim]Exemple : export VT_API_KEY='votre_cle_api'[/dim]")
        return None

    # Masquage de la clé pour éviter la divulgation dans les logs
    masked_key = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "***"
    console.print(f"[dim]Utilisation de la clé VT configurée : {masked_key}[/dim]")

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "Accept": "application/json",
        "x-apikey": api_key,
    }

    console.print("[bold green][*][/bold green] Interrogation de l'API VirusTotal pour le hash SHA-256...")
    try:
        response = requests.get(url, headers=headers, timeout=12)
        if response.status_code == 200:
            payload = response.json()
            stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats")
            return stats if isinstance(stats, dict) else None
        if response.status_code == 404:
            console.print("[yellow][!][/yellow] Hash absent de la base VirusTotal (fichier inconnu ou non soumis).")
            return None
        if response.status_code == 429:
            console.print("[bold yellow][!][/bold yellow] Limite de requêtes VirusTotal atteinte (HTTP 429).")
            return None
        console.print(f"[bold red][-][/bold red] Réponse inattendue de VirusTotal (HTTP {response.status_code}).")
        return None
    except requests.RequestException as e:
        console.print(f"[bold red][-][/bold red] Erreur réseau lors de l'appel VirusTotal : {e}")
        return None
    except ValueError:
        console.print("[bold red][-][/bold red] Réponse JSON invalide reçue de VirusTotal.")
        return None


def run_forensic(file_path_str: str, check_vt: bool = False, output: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Fonction principale du module forensique avec hashes, entropie, strings, extraction d'IOCs et VirusTotal."""
    path = Path(file_path_str)
    if not path.exists():
        console.print(f"[bold red][-][/bold red] Fichier introuvable : {file_path_str}")
        return None

    # Détection des liens symboliques pour éviter les boucles ou fuites
    is_symlink = path.is_symlink()
    try:
        resolved_path = path.resolve()
        if not resolved_path.is_file():
            console.print(f"[bold red][-][/bold red] La cible n'est pas un fichier régulier : {file_path_str}")
            return None
        stat = resolved_path.stat()
    except OSError as e:
        console.print(f"[bold red][-][/bold red] Impossible d'accéder aux métadonnées du fichier : {e}")
        return None

    console.print(f"[bold green][*][/bold green] Analyse forensique de : [cyan]{resolved_path.name}[/cyan]\n")

    table_meta = Table(title="Métadonnées du Fichier")
    table_meta.add_column("Propriété", style="cyan")
    table_meta.add_column("Valeur", style="green")
    table_meta.add_row("Nom complet", resolved_path.name)
    table_meta.add_row("Taille", f"{stat.st_size} octets ({stat.st_size / 1024:.2f} Ko)")
    table_meta.add_row("Chemin résolu", str(resolved_path))
    if is_symlink:
        table_meta.add_row("Lien symbolique", f"[yellow]OUI -> {resolved_path}[/yellow]")
    console.print(table_meta)

    console.print("\n[bold green][*][/bold green] Calcul des empreintes cryptographiques...")
    hashes = calculate_hashes(resolved_path)
    vt_stats: Optional[dict[str, Any]] = None

    if hashes:
        table_hash = Table(title="Empreintes Cryptographiques (IOCs)")
        table_hash.add_column("Algorithme", style="cyan", no_wrap=True)
        table_hash.add_column("Valeur", style="magenta")
        table_hash.add_row("MD5", hashes["md5"])
        table_hash.add_row("SHA-1", hashes["sha1"])
        table_hash.add_row("SHA-256", hashes["sha256"])
        table_hash.add_row("SHA-512", hashes["sha512"][:64] + "...")
        console.print(table_hash)

        if check_vt:
            console.print("")
            vt_stats = check_virustotal(hashes["sha256"])
            if vt_stats:
                malicious = int(vt_stats.get("malicious", 0))
                suspicious = int(vt_stats.get("suspicious", 0))
                harmless = int(vt_stats.get("harmless", 0))
                undetected = int(vt_stats.get("undetected", 0))

                table_vt = Table(title="Résultats VirusTotal")
                table_vt.add_column("Catégorie", style="cyan")
                table_vt.add_column("Moteurs", style="bold")
                table_vt.add_row("Malveillant", f"[red]{malicious}[/red]")
                table_vt.add_row("Suspect", f"[yellow]{suspicious}[/yellow]")
                table_vt.add_row("Inoffensif", f"[green]{harmless}[/green]")
                table_vt.add_row("Non détecté", f"[dim]{undetected}[/dim]")
                console.print(table_vt)

                if malicious > 0:
                    console.print(
                        f"[bold red][ALERTE SÉCURITÉ][/bold red] Fichier signalé comme malveillant par "
                        f"{malicious} moteur(s) sur VirusTotal."
                    )
                else:
                    console.print("[bold green][✓][/bold green] Aucune détection malveillante signalée.")

    entropy = calculate_entropy(resolved_path)
    console.print(f"\n[bold green][*][/bold green] Entropie de Shannon : [bold]{entropy:.4f}[/bold] / 8.0")
    if entropy > 7.2:
        console.print("[bold red][!][/bold red] Entropie très élevée : contenu potentiellement chiffré, compressé ou packé (malware obfuscation).")
    elif entropy < 4.0:
        console.print("[bold blue][i][/bold blue] Entropie basse : contenu textuel ou structuré simple.")
    else:
        console.print("[bold green][✓][/bold green] Entropie dans une plage standard.")

    strings = extract_strings(resolved_path, min_len=6)
    console.print(f"\n[bold green][*][/bold green] Chaînes ASCII extraites (>= 6 car.) : {len(strings)}")
    if strings:
        console.print(f"[dim]Aperçu ({min(len(strings), MAX_DISPLAY_STRINGS)} premières) :[/dim]")
        for s in strings[:MAX_DISPLAY_STRINGS]:
            console.print(f"  • {s}")

    # Extraction automatique d'IOCs dans les chaînes
    iocs = extract_iocs_from_strings(strings)
    if iocs["ips"] or iocs["urls"] or iocs["emails"]:
        table_iocs = Table(title="IOCs Détectés dans les Chaînes")
        table_iocs.add_column("Type", style="cyan")
        table_iocs.add_column("Indicateurs Trouvés", style="yellow")
        if iocs["ips"]:
            table_iocs.add_row("Adresses IP", ", ".join(iocs["ips"]))
        if iocs["urls"]:
            table_iocs.add_row("URLs", "\n".join(iocs["urls"]))
        if iocs["emails"]:
            table_iocs.add_row("Emails", ", ".join(iocs["emails"]))
        console.print(table_iocs)

    report_payload = {
        "metadata": {
            "filename": resolved_path.name,
            "size_bytes": stat.st_size,
            "resolved_path": str(resolved_path),
            "is_symlink": is_symlink,
        },
        "hashes": hashes or {},
        "entropy": round(entropy, 4),
        "iocs": iocs,
        "strings_sample": strings[:50],
        "virustotal": vt_stats or {},
    }

    if output:
        save_report("forensic", resolved_path.name, report_payload, output_format=output)

    return report_payload
