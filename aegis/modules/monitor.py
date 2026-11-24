import time
import os
from pathlib import Path
from rich.console import Console

console = Console()

# Signatures et motifs d'attaques cyber
SUSPICIOUS_PATTERNS = [
    # Authentification et brute force
    ("failed password", "Brute Force / Échec Auth"),
    ("invalid user", "Énumération Utilisateur"),
    ("authentication failure", "Échec d'Authentification"),
    ("permission denied", "Accès Refusé"),
    ("unauthorized", "Accès Non Autorisé"),
    # Injections et attaques Web
    ("union select", "Injection SQL (SQLi)"),
    ("' or 1=1", "Injection SQL (Bypass Auth)"),
    ("<script>", "Cross-Site Scripting (XSS)"),
    ("javascript:", "Cross-Site Scripting (XSS)"),
    ("../..", "Path Traversal (LFI/RFI)"),
    ("..\\..", "Path Traversal Windows"),
    # Exécution de code et shells
    ("/bin/sh", "Tentative d'Exécution de Shell"),
    ("/bin/bash", "Tentative d'Exécution de Shell"),
    ("cmd.exe", "Exécution de Commande Windows"),
    ("powershell", "Activité PowerShell Suspecte"),
    ("${jndi:", "Exploitation Log4j (CVE-2021-44228)"),
    ("eval(base64", "Décodage de Web Shell Obfusqué"),
    # Erreurs système critiques
    ("segfault", "Segmentation Fault / Crash Mémoire"),
    ("panic", "Kernel Panic / Crash"),
    ("exploit", "Mot-clé Exploit Détecté"),
    ("malware", "Mot-clé Malware Détecté"),
]


def run_monitor(log_path_str: str) -> None:
    """Surveille un fichier de log en temps réel (tail -f like) avec détection d'attaques et gestion de logrotate."""
    path = Path(log_path_str)
    if not path.is_file():
        console.print(f"[bold red][-][/bold red] Le fichier de log n'existe pas : {log_path_str}")
        return

    console.print(f"[bold green][*][/bold green] Surveillance active (mode live) sur : [cyan]{path.resolve()}[/cyan]")
    console.print("[dim]Appuyez sur Ctrl+C à tout moment pour interrompre la surveillance...[/dim]\n")

    try:
        current_size = path.stat().st_size
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            # Se positionner à la fin du fichier pour les nouveaux événements
            f.seek(0, 2)

            while True:
                line = f.readline()
                if not line:
                    # Vérifier si le fichier a été tronqué (ex: rotation de logs / logrotate)
                    try:
                        new_size = path.stat().st_size
                        if new_size < current_size:
                            console.print("[yellow][!][/yellow] Rotation de log détectée (repositionnement au début du fichier).")
                            f.seek(0, 0)
                        current_size = new_size
                    except OSError:
                        pass
                    time.sleep(0.5)
                    continue

                line_stripped = line.strip()
                if not line_stripped:
                    continue

                line_lower = line_stripped.lower()
                matched_label = None
                for keyword, label in SUSPICIOUS_PATTERNS:
                    if keyword in line_lower:
                        matched_label = label
                        break

                if matched_label:
                    console.print(f"[bold red][ALERTE: {matched_label}][/bold red] {line_stripped}")
                else:
                    console.print(f"[dim]{line_stripped}[/dim]")

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!][/bold yellow] Surveillance arrêtée par l'utilisateur.")
    except Exception as e:
        console.print(f"\n[bold red][-][/bold red] Une erreur est survenue lors de la surveillance : {e}")
