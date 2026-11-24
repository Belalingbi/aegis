import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Any
from urllib.parse import urlparse
import requests
from rich.console import Console
from rich.table import Table
from aegis.modules.reporter import save_report

console = Console()
MAX_FUZZ_WORKERS = 50
AEGIS_USER_AGENT = "AEGIS-Security-Framework/0.2.0 (+https://github.com/Belalingbi/aegis)"

DEFAULT_WORDLIST = [
    "admin", "login", "dashboard", "api", "config.json",
    "robots.txt", "sitemap.xml", ".git/HEAD", "backup.zip",
    "wp-login.php", "test.php", "index.php", "server-status",
    "uploads", "images", "css", "js", "private", "secret",
    "backup.tar.gz", ".env", "config.php", "phpinfo.php",
    "swagger", "openapi.json", "graphql", "actuator/health",
    "debug", "shell.php", "upload.php", ".htaccess",
]


def normalize_http_target(target: str) -> Optional[str]:
    """Valide et normalise une URL cible en http ou https."""
    raw = target.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return raw.rstrip("/")


def test_path(base_url: str, path: str, timeout: float = 3.5, delay: float = 0.0) -> Optional[tuple[str, int, int]]:
    """Teste un chemin relatif sur base_url avec User-Agent sécurisé et délai optionnel."""
    if delay > 0:
        time.sleep(delay)

    clean_path = path.lstrip("/")
    url = f"{base_url}/{clean_path}"
    headers = {"User-Agent": AEGIS_USER_AGENT}
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        if response.status_code in {200, 301, 302, 307, 308, 401, 403}:
            return clean_path, response.status_code, len(response.content)
    except requests.RequestException:
        pass
    return None


def run_fuzzer(
    target: str,
    wordlist_file: Optional[str] = None,
    threads: int = 10,
    delay: float = 0.0,
    output: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Exécute la découverte de chemins et ressources HTTP cachées."""
    base_url = normalize_http_target(target)
    if not base_url:
        console.print("[bold red][-][/bold red] URL cible invalide (schéma http:// ou https:// requis avec hôte valide).")
        return []

    safe_threads = max(1, min(int(threads), MAX_FUZZ_WORKERS))
    words = list(DEFAULT_WORDLIST)

    if wordlist_file:
        wl_path = Path(wordlist_file)
        if not wl_path.is_file():
            console.print(f"[bold red][-][/bold red] Fichier wordlist introuvable : {wordlist_file}")
            return []
        try:
            loaded = [
                line.strip()
                for line in wl_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if loaded:
                words = loaded
                console.print(f"[bold green][*][/bold green] Wordlist personnalisée chargée : {len(words)} entrées.")
        except OSError as e:
            console.print(f"[bold red][-][/bold red] Erreur lecture wordlist ({e}). Utilisation de la wordlist par défaut.")

    console.print(f"[bold green][*][/bold green] Fuzzing sur [cyan]{base_url}[/cyan] ({len(words)} chemins, {safe_threads} threads)...\n")

    found: list[tuple[str, int, int]] = []
    with ThreadPoolExecutor(max_workers=safe_threads) as executor:
        futures = [executor.submit(test_path, base_url, word, 3.5, delay) for word in words]
        for future in as_completed(futures):
            res = future.result()
            if res:
                found.append(res)

    found.sort(key=lambda item: item[0])
    results = [{"path": f"/{p}", "status": s, "size": size} for p, s, size in found]

    if found:
        table = Table(title=f"Chemins Détectés — {base_url}")
        table.add_column("Chemin", style="cyan", no_wrap=True)
        table.add_column("Statut HTTP", style="bold")
        table.add_column("Taille (octets)", justify="right", style="magenta")
        for path, status, size in found:
            if status == 200:
                status_str = "[green]200 OK[/green]"
            elif status in {301, 302, 307, 308}:
                status_str = f"[yellow]{status} Redirection[/yellow]"
            elif status in {401, 403}:
                status_str = f"[blue]{status} Protégé[/blue]"
            else:
                status_str = str(status)
            table.add_row(f"/{path}", status_str, str(size))
        console.print(table)
    else:
        console.print("[yellow][!][/yellow] Aucun chemin notable découvert.")

    if output:
        save_report("fuzz", base_url, {"target": base_url, "discovered": results}, output_format=output)

    return results
