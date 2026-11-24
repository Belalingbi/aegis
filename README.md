# 🛡️ AEGIS — Framework Modulaire de Cybersécurité

**AEGIS** est une suite universelle d'outils de cybersécurité en ligne de commande (**CLI**) et terminal interactif (**TUI**), développée par **Belalingbi Steve** au sein du projet **CyberAnonymat**.

AEGIS centralise la reconnaissance réseau, l'audit d'en-têtes et SSL, l'analyse forensique de binaires/fichiers, le fuzzing web, la surveillance de logs et le durcissement système au sein d'une commande unique et autonome : `aegis`.

---

## ⚡ Installation Universelle

### 1. Installation via Git & Pip (Toutes plateformes : Linux, macOS, Windows)

```bash
git clone https://github.com/Belalingbi/aegis.git
cd aegis
python3 -m venv .venv
source .venv/bin/activate  # Sous Windows : .venv\Scripts\activate
pip install -e .
```

Une fois installé, la commande `aegis` est accessible immédiatement depuis n'importe quel terminal :

```bash
aegis
```

### 2. Déploiement via Docker (Sans dépendances locales)

```bash
docker build -t aegis .
docker run -it --rm --network host aegis
```

---

## 🚀 Capacités & Modules Disponibles

| Commande | Module | Description |
| :--- | :--- | :--- |
| `aegis` | **Dashboard** | Tableau de bord synthétique et orientation |
| `aegis recon` | **Reconnaissance** | Résolution DNS, scan TCP multithreadé (plages et ports) et bannières |
| `aegis audit` | **Audit Web & SSL** | Analyse des en-têtes HTTP de sécurité (score & note A+ à F), SSL/TLS et CVE NIST |
| `aegis auto` | **Automatisation** | Workflows intégrés : `system-health`, `quick-pentest`, `hardening-check` |
| `aegis forensic` | **Forensique & IOCs** | Hashes (MD5, SHA1, SHA256, SHA512), entropie de Shannon, extraction d'IOCs et VirusTotal |
| `aegis fuzz` | **Fuzzing Web** | Découverte de répertoires cachés avec gestion du débit (`--delay`) anti-ban |
| `aegis monitor` | **Surveillance** | Détection d'attaques en temps réel sur journaux système (SQLi, XSS, Brute force) |
| `aegis traffic` | **Capture Réseau** | Analyse passive de paquets IP/TCP/UDP/ICMP via Scapy (droits root/admin) |
| `aegis doctor` | **Diagnostic** | Vérification de l'intégrité de l'environnement, dépendances et privilèges |
| `aegis gui` | **Interface TUI** | Console interactive graphique dans le terminal |

---

## 🔒 Durcissement & Sécurité Applicative

AEGIS intègre des mécanismes de protection native contre les cyberattaques visant l'outil d'audit lui-même :

1. **Prévention des Injections XSS (Rapports HTML) :**
   - Mise en œuvre stricte d'une directive *Content-Security-Policy* (`default-src 'none'; style-src 'unsafe-inline';`).
   - Échappement HTML systématique de toutes les entrées dynamiques (bannières, serveurs distants).
2. **Neutralisation du Path Traversal :**
   - Validation stricte des chemins de rapports et nettoyage des caractères interdits pour confiner les sorties dans `aegis_reports/`.
3. **Protection contre le Déni de Service & Bombes de données :**
   - Lecture en streaming par blocs (*chunks*) de 64 Ko pour l'analyse forensique et l'entropie.
   - Contrôle du débit (*rate limiting* / `--delay`) lors du fuzzing pour préserver la cible.
4. **Hygiène des Secrets (OSINT & APIs) :**
   - Lecture de `VT_API_KEY` depuis l'environnement sans journalisation en clair.

---

## 🧪 Exécution des Tests

Le framework intègre une suite de tests unitaires et fonctionnels avec `pytest` :

```bash
pytest -v
```

---

## ⚖️ Avertissement Légal

Cet outil est destiné exclusivement à des fins d'apprentissage, d'audit autorisé, de diagnostic système et de recherche en sécurité défensive. Tout usage non autorisé sur des systèmes tiers est strictement prohibé par la législation en vigueur.

**Auteur :** [Belalingbi Steve](https://github.com/Belalingbi/) — CyberAnonymat Project  
**Licence :** MIT
