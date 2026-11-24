from typing import Optional
from rich.console import Console

console = Console()


def packet_callback(packet) -> None:
    """Callback exécuté pour chaque paquet capturé avec affichage en temps réel."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError:
        return

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "AUTRE"
        details = ""

        if TCP in packet:
            proto = "TCP"
            details = f"Port {packet[TCP].sport} ➔ {packet[TCP].dport} [Flags: {packet[TCP].flags}]"
        elif UDP in packet:
            proto = "UDP"
            details = f"Port {packet[UDP].sport} ➔ {packet[UDP].dport}"
        elif ICMP in packet:
            proto = "ICMP"
            details = f"Type: {packet[ICMP].type} (Ping / Contrôle)"

        console.print(f"[cyan]{ip_src:<15}[/cyan] ➔ [green]{ip_dst:<15}[/green] | [bold yellow]{proto:<5}[/bold yellow] | {details}")


def run_traffic_sniffer(interface: Optional[str] = None, count: int = 20) -> None:
    """Lance la capture passive et l'analyse de paquets réseau."""
    try:
        from scapy.all import sniff
    except ImportError:
        console.print("[bold red][-][/bold red] Scapy n'est pas installé ou n'a pas pu être chargé. Exécutez : [cyan]pip install scapy[/cyan]")
        return

    console.print(f"[bold green][*][/bold green] Démarrage du sniffer réseau (Capture de [cyan]{count}[/cyan] paquets)...")
    if interface:
        console.print(f"[dim]Interface réseau sélectionnée : {interface}[/dim]")
    console.print("[dim]Appuyez sur Ctrl+C pour stopper la capture à tout moment...\n[/dim]")

    try:
        sniff(iface=interface, prn=packet_callback, count=int(count), store=False)
        console.print("\n[bold green][✓][/bold green] Capture de trafic terminée avec succès.")
    except PermissionError:
        console.print(
            "\n[bold red][-][/bold red] Erreur de privilèges : La capture brute de paquets requiert des droits élevés.\n"
            "  • Sous Linux : [cyan]sudo aegis traffic[/cyan] (ou attribuez la capacité [bold]CAP_NET_RAW[/bold]).\n"
            "  • Sous Windows : Exécutez dans un terminal Administrateur avec [bold]Npcap[/bold] installé."
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!][/bold yellow] Capture interrompue par l'utilisateur.")
    except Exception as e:
        console.print(f"\n[bold red][-][/bold red] Une erreur est survenue lors de la capture : {e}")
