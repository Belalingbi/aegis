# 🛡️ AEGIS Security Framework (`v0.2.0`)

**AEGIS** (`aegis-sec`) est un framework modulaire en ligne de commande (**CLI**) et interface terminal (**TUI**) conçu pour le diagnostic réseau, l'audit de configuration et de vulnérabilités, l'automatisation de workflows, l'analyse forensique légère, la surveillance de journaux, la capture de trafic et la collecte OSINT / Threat Intelligence sous Linux (Kali Linux, Parrot OS, Arch Linux, BlackArch, etc.).

> **Avertissement légal :** Utilisez AEGIS uniquement sur des systèmes, réseaux ou applications que vous possédez ou pour lesquels vous disposez d'une autorisation explicite. Consultez [SECURITY.md](SECURITY.md) avant toute utilisation.

---

## 🚀 Modules et Fonctionnalités

- **Dashboard global (`aegis`) :** Vue d'ensemble des commandes et accès rapide à l'aide (`aegis --help`).
- **Reconnaissance réseau (`aegis recon`) :** Résolution DNS, scan de ports TCP multithreadé avec validation de plage (`1-65535`) et récupération de bannières.
- **Audit web, SSL/TLS & CVE (`aegis audit`) :** Inspection des en-têtes HTTP de sécurité, vérification des certificats TLS, interrogation de l'API NIST NVD (`--cve` ou détection technologique) et export de rapports (`json`, `md`, `html`).
- **Automatisation (`aegis auto`) :** Scénarios prédéfinis (`system-health`, `quick-pentest`)[cite: 1].
- **Analyse forensique & VirusTotal (`aegis forensic`) :** Calcul des empreintes (`MD5`, `SHA-1`, `SHA-256`), entropie de Shannon et extraction de chaînes ASCII par blocs (*chunks*) afin de limiter l'empreinte mémoire, avec vérification optionnelle via l'API VirusTotal v3 (`--vt` et variable d'environnement `VT_API_KEY`)[cite: 1].
- **Surveillance de logs (`aegis monitor`) :** Suivi en temps réel d'un fichier journal et mise en évidence des lignes correspondant à des motifs suspects (`Ctrl+C` pour arrêter)[cite: 1].
- **Analyse de trafic (`aegis traffic`) :** Capture passive de paquets (`IP`, `TCP`, `UDP`, `ICMP`) via `Scapy`[cite: 1].
- **Fuzzing web (`aegis fuzz`) :** Découverte de chemins/ressources HTTP avec wordlist intégrée ou personnalisée (`-w`) et contrôle du parallélisme (`-p`)[cite: 1].
- **Interface TUI (`aegis gui`) :** Tableau de bord interactif en terminal propulsé par `Textual`, exécutant les actions dans des *workers* dédiés pour ne pas bloquer l'interface[cite: 1].
- **Reporting (`reporter`) :** Export structuré dans `aegis_reports/` aux formats `json`, `md` et `html` (avec échappement des données dynamiques)[cite: 1].

---

## 📦 Installation

Il est recommandé d'installer AEGIS dans un environnement virtuel Python (`Python >= 3.9`) :[cite: 1]

```bash
git clone [https://github.com/cyberanonymat-sudo/aegis.git](https://github.com/cyberanonymat-sudo/aegis.git)
cd aegis
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```[cite: 1]

---

## 📖 Exemples d'Utilisation

```bash
# Tableau de bord global
aegis

# Reconnaissance réseau
aegis recon -t 127.0.0.1 -p "22,80,443,8080"

# Audit HTTP/SSL + recherche CVE + export HTML/MD/JSON
aegis audit -t [https://example.com](https://example.com) -o html
aegis audit -t example.com --cve openssl -o md

# Workflow automatisé
aegis auto -w system-health
aegis auto -w quick-pentest

# Analyse forensique par blocs + vérification VirusTotal
export VT_API_KEY="votre_cle_api_virustotal"
aegis forensic -f /bin/ls --vt

# Fuzzing web léger
aegis fuzz -t [http://scanme.nmap.org](http://scanme.nmap.org) -p 10

# Surveillance de logs en temps réel
aegis monitor -l /var/log/auth.log

# Capture de trafic (privilèges root / CAP_NET_RAW requis)
sudo aegis traffic -c 20

# Interface graphique en terminal (TUI)
aegis gui
```[cite: 1]

---

## 🧪 Tests

```bash
pytest -v