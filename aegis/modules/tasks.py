import platform
from typing import Optional
import psutil
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from aegis.modules.recon import run_recon
from aegis.modules.audit import run_audit

console = Console()

# Ports à risque / protocoles non sécurisés fréquemment audités
INSECURE_PORTS = {
    21: "FTP (Non chiffré - Mots de passe en clair)",
    23: "Telnet (Non chiffré - Obsolète et vulnérable)",
    25: "SMTP (Relais potentiel sans TLS)",
    69: "TFTP (Non authentifié)",
    80: "HTTP (Trafic web en clair sans HTTPS)",
    110: "POP3 (Non chiffré)",
    135: "RPC Windows (Surface d'attaque fréquente)",
    139: "NetBIOS (Surface d'attaque fréquente)",
    445: "SMB (Cible fréquente: EternalBlue, ransomware)",
    3389: "RDP (Bureau à distance exposé)",
}


def run_hardening_check() -> None:
    """Audit rapide du durcissement local de la machine et des ports d'écoute."""
    console.print("[bold green][*][/bold green] Exécution du workflow : [cyan]System Hardening & Security Audit[/cyan]\n")

    os_info = f"{platform.system()} {platform.release()} ({platform.architecture()[0]})"
    console.print(f"[bold]Système d'exploitation :[/bold] [cyan]{os_info}[/cyan]")
    console.print(f"[bold]Machine / Hostname :[/bold] [cyan]{platform.node()}[/cyan]")

    # 1. Vérification des ressources
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/") if hasattr(psutil, "disk_usage") else None

    # 2. Analyse des services en écoute
    insecure_found = []
    listening_count = 0
    try:
        net_connections = psutil.net_connections(kind="inet")
        listening = [c for c in net_connections if c.status == "LISTEN"]
        listening_count = len(listening)

        table_ports = Table(title="Services & Ports Locaux en Écoute")
        table_ports.add_column("Adresse IP", style="cyan")
        table_ports.add_column("Port", justify="right", style="green")
        table_ports.add_column("PID", justify="right", style="magenta")
        table_ports.add_column("Évaluation Sécurité", style="bold")

        for conn in listening:
            port = conn.laddr.port
            eval_text = "[green]Standard[/green]"
            if port in INSECURE_PORTS:
                eval_text = f"[bold red]À RISQUE: {INSECURE_PORTS[port]}[/bold red]"
                insecure_found.append((port, INSECURE_PORTS[port]))
            table_ports.add_row(conn.laddr.ip, str(port), str(conn.pid or "N/A"), eval_text)

        console.print(table_ports)
    except Exception as e:
        console.print(f"[dim]Note: Analyse des sockets restreinte par l'environnement ({e}).[/dim]")

    # 3. Recommandations de durcissement
    table_recom = Table(title="🛡️ Recommandations de Durcissement (Hardening)")
    table_recom.add_column("Domaine", style="cyan")
    table_recom.add_column("Recommandation Clé", style="white")

    table_recom.add_row("Protocoles Réseau", "Désactiver les protocoles en clair (Telnet, FTP, HTTP) au profit de SSH, SFTP, HTTPS.")
    table_recom.add_row("Pare-feu / Firewall", "Activer le pare-feu local (ufw/iptables sur Linux, Windows Defender Firewall sur Windows).")
    table_recom.add_row("Mises à jour de sécurité", "Appliquer immédiatement les correctifs OS et packages (apt upgrade / Windows Update).")
    table_recom.add_row("Principe de Moindre Privilège", "Exécuter les services sous des comptes de service restreints, jamais sous root/Administrator.")
    table_recom.add_row("Authentification Forte", "Imposer l'authentification multifacteur (MFA) et désactiver l'accès root SSH direct.")

    console.print(table_recom)

    if insecure_found:
        console.print(f"\n[bold red][ALERTE DURCISSEMENT][/bold red] {len(insecure_found)} service(s) sensible(s) ou non chiffré(s) détecté(s) !")
    else:
        console.print("\n[bold green][✓][/bold green] Aucun protocole obsolète critique (Telnet, FTP non sécurisé) détecté en écoute locale.")


def run_workflow(workflow_name: str, target: Optional[str] = None) -> None:
    """Exécute un workflow d'automatisation prédéfini (system-health, quick-pentest, hardening-check)."""
    name = workflow_name.lower().strip()

    if name == "system-health":
        console.print("[bold green][*][/bold green] Exécution du workflow : [cyan]System Health & Security Check[/cyan]\n")

        cpu_usage = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/") if hasattr(psutil, "disk_usage") else None

        table = Table(title="État du Système & Ressources Locales")
        table.add_column("Métrique", style="cyan")
        table.add_column("Valeur", style="green")

        table.add_row("Système", f"{platform.system()} {platform.release()}")
        table.add_row("Utilisation CPU", f"{cpu_usage}%")
        table.add_row("Mémoire Vive (RAM)", f"{mem.percent}% ({mem.used / (1024**3):.2f} Go / {mem.total / (1024**3):.2f} Go)")
        if disk:
            table.add_row("Espace Disque (Racine)", f"{disk.percent}% ({disk.used / (1024**3):.2f} Go / {disk.total / (1024**3):.2f} Go)")

        console.print(table)

        try:
            net_connections = psutil.net_connections(kind="inet")
            listening = [c for c in net_connections if c.status == "LISTEN"]
            console.print(f"\n[bold green][*][/bold green] Ports locaux en écoute (LISTEN) : [bold]{len(listening)}[/bold]")

            if listening:
                net_table = Table(title="Services Locaux en Écoute")
                net_table.add_column("Adresse IP", style="cyan")
                net_table.add_column("Port", justify="right", style="green")
                net_table.add_column("PID", justify="right", style="magenta")

                for conn in listening[:15]:
                    net_table.add_row(conn.laddr.ip, str(conn.laddr.port), str(conn.pid or "N/A"))
                console.print(net_table)
        except Exception as e:
            console.print(f"[dim]Note: Connexions réseau non consultables ({e}).[/dim]")

    elif name == "quick-pentest":
        tgt = target if target else "127.0.0.1"
        console.print(f"[bold green][*][/bold green] Exécution du workflow : [cyan]Quick Pentest[/cyan] sur [bold]{tgt}[/bold]\n")

        console.print("[bold]--- ÉTAPE 1 : Reconnaissance des ports standards ---[/bold]")
        run_recon(tgt, "21,22,80,443,3306,8080")

        console.print("\n[bold]--- ÉTAPE 2 : Audit de sécurité Web ---[/bold]")
        audit_target = tgt if tgt.startswith("http://") or tgt.startswith("https://") else f"https://{tgt}"
        run_audit(audit_target)

    elif name in {"hardening-check", "system-hardening", "hardening"}:
        run_hardening_check()

    else:
        console.print(f"[bold red][-][/bold red] Workflow inconnu : [bold]{workflow_name}[/bold]")
        console.print("[yellow]Workflows disponibles :[/yellow] system-health, quick-pentest, hardening-check")
