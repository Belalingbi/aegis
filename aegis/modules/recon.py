import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from rich.console import Console
from rich.table import Table
from aegis.modules.reporter import save_report

console = Console()
MAX_WORKERS = 64


def parse_ports(ports_str: str) -> Optional[list[int]]:
    """
    Valide et déduplique une liste de ports TCP compris entre 1 et 65535.
    Prend en charge les ports isolés (ex: 22,80) et les plages (ex: 8000-8010).
    """
    ports: list[int] = []
    seen: set[int] = set()

    for raw_part in ports_str.split(","):
        item = raw_part.strip()
        if not item:
            continue

        # Prise en charge des plages de ports (ex: 80-90)
        if "-" in item:
            parts = item.split("-", 1)
            try:
                start_p = int(parts[0].strip())
                end_p = int(parts[1].strip())
            except ValueError:
                return None
            if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p):
                return None
            # Limiter une plage excessive pour éviter l'épuisement des ressources
            if end_p - start_p > 5000:
                end_p = start_p + 5000
            for p in range(start_p, end_p + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
        else:
            try:
                port = int(item)
            except ValueError:
                return None
            if not (1 <= port <= 65535):
                return None
            if port not in seen:
                seen.add(port)
                ports.append(port)

    return ports if ports else None


def scan_port(target_ip: str, port: int, timeout: float = 1.2) -> tuple[int, str, str]:
    """
    Vérifie si un port TCP est ouvert et tente une lecture intelligente de bannière.
    Stratégie passive d'abord (écoute des bannières de bienvenue SSH, FTP, SMTP, MySQL)
    puis sonde active HTTP HEAD si aucun message initial n'est reçu.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target_ip, port)) == 0:
                banner = ""
                # 1. Écoute passive brève pour les services qui envoient une bannière à la connexion (SSH, FTP, etc.)
                try:
                    s.settimeout(0.4)
                    raw_banner = s.recv(1024)
                    if raw_banner:
                        banner = raw_banner.decode("utf-8", errors="ignore").splitlines()[0].strip()
                except (socket.timeout, OSError):
                    pass

                # 2. Si aucune bannière passive, envoyer une requête générique sécurisée
                if not banner:
                    try:
                        s.settimeout(timeout)
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
                        raw_banner = s.recv(1024)
                        if raw_banner:
                            banner = raw_banner.decode("utf-8", errors="ignore").splitlines()[0].strip()
                    except OSError:
                        banner = "Port ouvert (sans bannière lisible)"

                return port, "OUVERT", banner or "Port ouvert"
    except OSError:
        pass
    return port, "FERMÉ", ""


def run_recon(target: str, ports_str: str, output: Optional[str] = None) -> list[dict]:
    """Exécute la reconnaissance DNS + scan TCP multithreadé avec option de rapport."""
    clean_target = target.strip()
    if not clean_target:
        console.print("[bold red][-][/bold red] Cible vide.")
        return []

    # Nettoyage si l'utilisateur a passé http:// ou https:// par habitude
    if "://" in clean_target:
        clean_target = clean_target.split("://", 1)[1].split("/")[0].split(":")[0]

    try:
        target_ip = socket.gethostbyname(clean_target)
    except socket.gaierror:
        console.print(f"[bold red][-][/bold red] Résolution DNS impossible pour : {clean_target}")
        return []

    ports = parse_ports(ports_str)
    if not ports:
        console.print("[bold red][-][/bold red] Ports invalides. Fournissez des entiers ou plages entre 1 et 65535 (ex: 22,80,443 ou 80-90).")
        return []

    workers = min(len(ports), MAX_WORKERS)
    console.print(f"[bold green][*][/bold green] Cible : [cyan]{clean_target}[/cyan] -> [bold]{target_ip}[/bold]")
    console.print(f"[bold green][*][/bold green] Scan de {len(ports)} port(s) ({workers} threads)...\n")

    open_ports: list[tuple[int, str]] = []
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, target_ip, p) for p in ports]
        for future in as_completed(futures):
            port, status, banner = future.result()
            if status == "OUVERT":
                open_ports.append((port, banner))
                results.append({"port": port, "status": status, "banner": banner})

    open_ports.sort(key=lambda item: item[0])
    results.sort(key=lambda item: item["port"])

    if open_ports:
        table = Table(title=f"Ports Ouverts — {clean_target} ({target_ip})")
        table.add_column("Port", justify="right", style="cyan", no_wrap=True)
        table.add_column("État", style="green")
        table.add_column("Bannière / Service", style="magenta")
        for port, banner in open_ports:
            table.add_row(str(port), "OUVERT", banner or "N/A")
        console.print(table)
    else:
        console.print("[bold yellow][!][/bold yellow] Aucun port ouvert détecté sur la sélection.")

    if output:
        save_report("recon", clean_target, {"target_ip": target_ip, "scanned_ports": len(ports), "open_ports": results}, output_format=output)

    return results
