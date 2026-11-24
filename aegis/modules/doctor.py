import os
import sys
import platform
import socket
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def check_doctor() -> bool:
    """
    Exécute un diagnostic complet de l'environnement, des dépendances,
    des privilèges et des capacités de sécurité d'AEGIS.
    """
    console.print("[bold green][*][/bold green] Exécution du diagnostic de santé : [cyan]AEGIS Doctor[/cyan]\n")

    table = Table(title="Diagnostic d'Intégrité & Environnement")
    table.add_column("Composant / Contrôle", style="cyan")
    table.add_column("Statut", style="bold")
    table.add_column("Détails & Recommandations", style="white")

    all_passed = True

    # 1. Version Python
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 9):
        table.add_row("Version Python", "[green]OK[/green]", f"Python {py_ver} (Requis >= 3.9)")
    else:
        table.add_row("Version Python", "[red]OBSOLÈTE[/red]", f"Python {py_ver} (Mise à niveau vers >= 3.9 requise)")
        all_passed = False

    # 2. Système d'exploitation
    os_name = f"{platform.system()} {platform.release()}"
    table.add_row("Système d'Exploitation", "[green]DÉTECTÉ[/green]", os_name)

    # 3. Dépendances clés
    required_packages = [
        ("click", "Interface CLI Click"),
        ("rich", "Rendu terminal & tableaux Rich"),
        ("requests", "Client HTTP & APIs"),
        ("psutil", "Métriques système & connexions"),
        ("textual", "Interface TUI plein écran"),
        ("scapy", "Manipulation & capture de paquets"),
    ]

    import importlib.metadata
    for pkg, label in required_packages:
        try:
            try:
                ver = importlib.metadata.version(pkg)
            except Exception:
                mod = __import__(pkg)
                ver = getattr(mod, "__version__", "installé")
            table.add_row(f"Package: {pkg}", "[green]OK[/green]", f"{label} (v{ver})")
        except ImportError:
            table.add_row(f"Package: {pkg}", "[red]MANQUANT[/red]", f"Installez via: pip install {pkg}")
            all_passed = False

    # 4. Privilèges d'exécution
    is_admin = False
    try:
        if platform.system() == "Windows":
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            is_admin = (os.geteuid() == 0)
    except Exception:
        pass

    if is_admin:
        table.add_row("Privilèges Système", "[yellow]ÉLEVÉS (Root/Admin)[/yellow]", "Tous les modules opérationnels (y compris capture Scapy brute).")
    else:
        table.add_row("Privilèges Système", "[blue]UTILISATEUR STANDARD[/blue]", "OK pour recon, audit, forensic, fuzz. Lancez avec sudo/admin pour 'aegis traffic'.")

    # 5. Connectivité DNS / Réseau
    try:
        socket.gethostbyname("cloudflare.com")
        table.add_row("Connectivité Réseau", "[green]OK[/green]", "Résolution DNS et accès externe fonctionnels.")
    except socket.gaierror:
        table.add_row("Connectivité Réseau", "[yellow]HORS-LIGNE / RESTREINT[/yellow]", "Résolution DNS échouée. Les modules locaux restent utilisables.")

    # 6. Clé VirusTotal
    vt_key = os.getenv("VT_API_KEY", "").strip()
    if vt_key:
        masked = f"{vt_key[:4]}...{vt_key[-4:]}" if len(vt_key) > 8 else "***"
        table.add_row("Intégration VirusTotal", "[green]CONFIGURÉ[/green]", f"Clé VT détectée ({masked}).")
    else:
        table.add_row("Intégration VirusTotal", "[dim]NON DÉFINIE[/dim]", "Optionnel. Définissez VT_API_KEY pour enrichir 'aegis forensic --vt'.")

    # 7. Dossier de rapports
    reports_dir = Path("aegis_reports")
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        test_file = reports_dir / ".test_write"
        test_file.write_text("test", encoding="utf-8")
        test_file.unlink()
        table.add_row("Dossier Rapports", "[green]ACCESSIBLE[/green]", f"Écriture autorisée dans {reports_dir.resolve()}")
    except OSError as e:
        table.add_row("Dossier Rapports", "[red]INACCESSIBLE[/red]", f"Erreur de permission : {e}")
        all_passed = False

    console.print(table)

    if all_passed:
        console.print("\n[bold green][✓] L'environnement AEGIS est sain, durci et prêt à l'emploi.[/bold green]")
    else:
        console.print("\n[bold yellow][!] Des avertissements ou dépendances manquantes ont été relevés.[/bold yellow]")

    return all_passed
