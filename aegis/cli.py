import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis import __version__
from aegis.modules.recon import run_recon
from aegis.modules.audit import run_audit
from aegis.modules.tasks import run_workflow
from aegis.modules.forensic import run_forensic
from aegis.modules.monitor import run_monitor
from aegis.modules.traffic import run_traffic_sniffer
from aegis.modules.fuzz import run_fuzzer
from aegis.modules.gui import run_gui
from aegis.modules.doctor import check_doctor

console = Console()


def print_banner() -> None:
    """Affiche la bannière officielle AEGIS Security Framework."""
    banner = (
        f"[bold #00ff9d]🛡️  AEGIS SECURITY FRAMEWORK[/bold #00ff9d] [dim]v{__version__}[/dim]\n"
        f"[white]Plateforme CLI & TUI d'Audit, Reconnaissance, Forensique, Fuzzing & Surveillance[/white]\n"
        f"[dim]CyberAnonymat Project • Conçu pour Kali Linux, Parrot OS, Arch, Debian, Ubuntu, Windows & macOS[/dim]\n"
        f"[dim]Auteur : Belalingbi Steve (https://github.com/Belalingbi/)[/dim]"
    )
    console.print(Panel(banner, border_style="#00ff9d", expand=False))


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="aegis")
@click.pass_context
def main(ctx: click.Context) -> None:
    """AEGIS : Framework modulaire de cybersécurité offensif et défensif tout-en-un."""
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("[bold yellow]Tableau de Bord & Navigation Rapide[/bold yellow]\n")

        table = Table(title="Modules Opérationnels Disponibles")
        table.add_column("Commande", style="bold #00ff9d", no_wrap=True)
        table.add_column("Domaine", style="cyan")
        table.add_column("Description & Capacités Clés", style="white")

        table.add_row("aegis recon", "Reconnaissance", "Scan TCP multithreadé, DNS et bannières (-t, -p, -o)")
        table.add_row("aegis audit", "Audit & CVE", "Audit headers HTTP, certificats SSL/TLS et CVE NIST NVD (-t, -c, -o)")
        table.add_row("aegis auto", "Automatisation", "Workflows (system-health, quick-pentest, hardening-check) (-w, -t)")
        table.add_row("aegis forensic", "Forensique", "Hashes (MD5/SHA1/256/512), Shannon entropy, IOCs & VirusTotal (-f, --vt, -o)")
        table.add_row("aegis monitor", "Surveillance", "Suivi temps réel de logs & détection d'intrusions / attaques (-l)")
        table.add_row("aegis traffic", "Réseau / Trafic", "Sniffer passif de paquets IP/TCP/UDP/ICMP via Scapy (-i, -c)")
        table.add_row("aegis fuzz", "Web Fuzzing", "Découverte multithreadée de répertoires avec contrôle de débit (-t, -w, -p, -d, -o)")
        table.add_row("aegis doctor", "Diagnostic", "Vérification de l'environnement, des dépendances et privilèges")
        table.add_row("aegis gui", "Interface TUI", "Console interactive ergonomique plein écran dans le terminal")

        console.print(table)
        console.print(
            "\n[dim]Utilisation : [bold]aegis [COMMANDE] --help[/bold] pour afficher l'aide détaillée d'un module.[/dim]"
        )


@main.command()
@click.option("--target", "-t", required=True, help="Adresse IP ou nom de domaine cible (ex: 127.0.0.1, scanme.nmap.org).")
@click.option(
    "--ports",
    "-p",
    default="21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080,8443",
    show_default=True,
    help="Ports TCP séparés par des virgules ou plages (ex: 22,80,443 ou 80-90,8080).",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "md", "html"], case_sensitive=False),
    default=None,
    help="Export du rapport dans aegis_reports/ (json, md, html).",
)
def recon(target: str, ports: str, output: str) -> None:
    """[1] Reconnaissance réseau : Résolution DNS, scan TCP multithreadé et bannières."""
    print_banner()
    run_recon(target, ports, output=output)


@main.command()
@click.option("--target", "-t", required=True, help="URL, hôte ou mot-clé technologique à auditer (ex: https://example.com).")
@click.option("--cve", "-c", default=None, help="Rechercher directement des CVEs par mot-clé dans la base NIST NVD.")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "md", "html"], case_sensitive=False),
    default=None,
    help="Export du rapport d'audit dans aegis_reports/ (json, md, html).",
)
def audit(target: str, cve: str, output: str) -> None:
    """[2] Audit web, en-têtes HTTP de sécurité, certificats SSL/TLS et CVEs NIST."""
    print_banner()
    run_audit(target, cve_keyword=cve, output=output)


@main.command()
@click.option(
    "--workflow",
    "-w",
    required=True,
    type=click.Choice(["system-health", "quick-pentest", "hardening-check"], case_sensitive=False),
    help="Nom du workflow à exécuter.",
)
@click.option("--target", "-t", default=None, help="Cible optionnelle pour le workflow (par défaut: 127.0.0.1).")
def auto(workflow: str, target: str) -> None:
    """[3] Automatisation de workflows (santé système, pentest combiné, audit durcissement)."""
    print_banner()
    run_workflow(workflow, target=target)


@main.command()
@click.option("--file", "-f", "file_path", required=True, type=click.Path(exists=True), help="Chemin du fichier à analyser.")
@click.option("--vt", is_flag=True, help="Consulter l'API VirusTotal v3 via la variable VT_API_KEY.")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "md", "html"], case_sensitive=False),
    default=None,
    help="Export du rapport forensique dans aegis_reports/ (json, md, html).",
)
def forensic(file_path: str, vt: bool, output: str) -> None:
    """[4] Analyse forensique de fichier (MD5, SHA1/256/512, entropie, extraction IOCs, VirusTotal)."""
    print_banner()
    run_forensic(file_path, check_vt=vt, output=output)


@main.command()
@click.option("--log", "-l", "log_path", required=True, type=click.Path(exists=True), help="Chemin du fichier de log à surveiller.")
def monitor(log_path: str) -> None:
    """[5] Surveillance de logs en temps réel (tail -f like) et détection d'intrusions / attaques."""
    print_banner()
    run_monitor(log_path)


@main.command()
@click.option("--interface", "-i", default=None, help="Interface réseau à écouter (ex: eth0, wlan0).")
@click.option("--count", "-c", default=20, show_default=True, type=int, help="Nombre de paquets à capturer.")
def traffic(interface: str, count: int) -> None:
    """[6] Capture et analyse passive de trafic réseau via Scapy (privilèges root/admin requis)."""
    print_banner()
    run_traffic_sniffer(interface=interface, count=count)


@main.command()
@click.option("--target", "-t", required=True, help="URL cible (ex: https://example.com).")
@click.option("--wordlist", "-w", default=None, type=click.Path(exists=True), help="Wordlist personnalisée de chemins.")
@click.option("--threads", "-p", default=10, show_default=True, type=int, help="Nombre de threads simultanés.")
@click.option("--delay", "-d", default=0.0, show_default=True, type=float, help="Délai entre requêtes en secondes (anti-ban/WAF).")
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "md", "html"], case_sensitive=False),
    default=None,
    help="Export des chemins détectés dans aegis_reports/ (json, md, html).",
)
def fuzz(target: str, wordlist: str, threads: int, delay: float, output: str) -> None:
    """[7] Découverte de répertoires et fichiers cachés (Fuzzing web multithreadé)."""
    print_banner()
    run_fuzzer(target, wordlist_file=wordlist, threads=threads, delay=delay, output=output)


@main.command()
def doctor() -> None:
    """[8] Diagnostic de l'environnement, des dépendances, privilèges et sécurité."""
    print_banner()
    check_doctor()


@main.command()
def gui() -> None:
    """[9] Lancer l'interface graphique interactive dans le terminal (TUI Textual)."""
    run_gui()


if __name__ == "__main__":
    main()
