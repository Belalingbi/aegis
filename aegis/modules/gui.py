from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Footer, Header, Input, Log, Static
from aegis.modules.audit import run_audit
from aegis.modules.forensic import run_forensic
from aegis.modules.recon import run_recon
from aegis.modules.fuzz import run_fuzzer


class AegisGUI(App):
    """Interface graphique TUI pour le framework AEGIS propulsée par Textual."""

    CSS = """
    Screen {
        background: #0f141c;
        color: #cdd6f4;
    }
    #sidebar {
        dock: left;
        width: 32;
        background: #151d2a;
        border-right: solid #00ff9d;
        padding: 1;
    }
    #main-content {
        padding: 2;
        background: #0f141c;
    }
    Button {
        width: 100%;
        margin-bottom: 1;
        background: #222f3e;
        color: #cdd6f4;
        border: none;
    }
    Button:hover {
        background: #00ff9d;
        color: #0b0f19;
    }
    Input {
        margin-bottom: 1;
        background: #1a2233;
        border: solid #374151;
        color: #00ff9d;
    }
    Log {
        background: #090d15;
        border: solid #222f3e;
        height: 1fr;
    }
    .title {
        text-style: bold;
        color: #00ff9d;
        margin-bottom: 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self.current_module = "recon"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("🛡️ AEGIS TUI CONSOLE", classes="title")
                yield Button("1. Reconnaissance Réseau", id="btn-recon")
                yield Button("2. Audit Web & CVE", id="btn-audit")
                yield Button("3. Analyse Forensique", id="btn-forensic")
                yield Button("4. Fuzzing Web Léger", id="btn-fuzz")
                yield Button("Quitter", id="btn-quit", variant="error")
            with Vertical(id="main-content"):
                yield Static(
                    "Tableau de Bord AEGIS — Module actif : Reconnaissance Réseau",
                    classes="title",
                    id="panel-title",
                )
                yield Input(
                    placeholder="Saisissez la cible (ex: 127.0.0.1, https://example.com, fichier ou mot-clé)...",
                    id="target-input",
                )
                yield Button("Lancer l'Analyse", id="btn-run", variant="success")
                yield Static("\nJournal d'Exécution & Télémétrie", id="output-label")
                yield Log(id="log-output", highlight=True)
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id
        title_widget = self.query_one("#panel-title", Static)
        log_view = self.query_one("#log-output", Log)

        if button_id == "btn-recon":
            self.current_module = "recon"
            title_widget.update("Module actif : Reconnaissance Réseau (Scan TCP & DNS)")
        elif button_id == "btn-audit":
            self.current_module = "audit"
            title_widget.update("Module actif : Audit Web, Certificats SSL & CVEs NIST")
        elif button_id == "btn-forensic":
            self.current_module = "forensic"
            title_widget.update("Module actif : Analyse Forensique (Empreintes, Entropie, VirusTotal)")
        elif button_id == "btn-fuzz":
            self.current_module = "fuzz"
            title_widget.update("Module actif : Fuzzing & Découverte de Ressources Web")
        elif button_id == "btn-quit":
            self.exit()
        elif button_id == "btn-run":
            target = self.query_one("#target-input", Input).value.strip()
            log_view.clear()
            if not target:
                log_view.write("[!] Erreur : veuillez saisir une cible valide avant de lancer l'analyse.")
                return
            log_view.write(f"[*] Démarrage du module [{self.current_module.upper()}] sur : {target}")
            self._execute_module_worker(self.current_module, target)

    @work(thread=True, exclusive=True)
    def _execute_module_worker(self, module_name: str, target: str) -> None:
        log_view = self.query_one("#log-output", Log)
        try:
            if module_name == "recon":
                run_recon(target, "21,22,25,80,443,3306,8080")
            elif module_name == "audit":
                run_audit(target)
            elif module_name == "forensic":
                run_forensic(target)
            elif module_name == "fuzz":
                run_fuzzer(target)
            self.call_from_thread(log_view.write, "[✓] Traitement terminé avec succès.")
        except Exception as exc:
            self.call_from_thread(log_view.write, f"[!] Erreur d'exécution : {exc}")


def run_gui() -> None:
    """Point d'entrée du mode graphique terminal."""
    app = AegisGUI()
    app.run()
