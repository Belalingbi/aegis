# TRD — AEGIS Security Framework

- **Projet :** AEGIS (`aegis-sec`)[cite: 1]
- **Architecture :** Framework modulaire Python (CLI `Click`, rendu `Rich`, TUI `Textual`, réseau/paquets `Requests` / `Socket` / `Scapy`, système `Psutil`)[cite: 1]
- **Langage :** Python (`>= 3.9`)[cite: 1]

---

## 1. Architecture Technique et Organisation du Code

### Structure du dépôt
```text
aegis/
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── aegis/
    ├── __init__.py
    ├── cli.py              # Point d'entrée Click, dashboard global & routage
    └── modules/
        ├── __init__.py
        ├── recon.py          # Résolution DNS, scan TCP multithreadé, banner grabbing
        ├── audit.py          # Headers HTTP, certificat SSL/TLS, client API NIST NVD
        ├── tasks.py          # Workflows automatisés (system-health, quick-pentest)
        ├── forensic.py       # Hashes (MD5/SHA1/SHA256), entropie, strings, VirusTotal
        ├── monitor.py        # Suivi de logs en temps réel & détection par mots-clés
        ├── traffic.py        # Sniffer passif basé sur Scapy
        ├── fuzz.py           # Énumération HTTP multithreadée de chemins
        ├── gui.py            # Interface TUI Textual
        └── reporter.py       # Export JSON, Markdown et HTML vers aegis_reports/
```[cite: 1]

### Flux d'exécution
1. `aegis` invoque `aegis.cli:main` via le point d'entrée défini dans `[project.scripts]` (`pyproject.toml`)[cite: 1].
2. `cli.py` valide les arguments/options (`Click`), affiche éventuellement la bannière `Rich` et délègue à la fonction métier du module correspondant (`run_recon`, `run_audit`, `run_workflow`, `run_forensic`, `run_monitor`, `run_traffic_sniffer`, `run_fuzzer`, `run_gui`)[cite: 1].
3. Les modules d'audit/analyse peuvent appeler `save_report()` dans `reporter.py` pour persister les résultats[cite: 1].

---

## 2. Stack Technique et Dépendances

- **CLI :** `click>=8.1.0`[cite: 1]
- **Affichage console :** `rich>=13.7.0`[cite: 1]
- **Métriques système/réseau :** `psutil>=5.9.0`[cite: 1]
- **Requêtes HTTP :** `requests>=2.31.0`[cite: 1]
- **Interface TUI :** `textual>=0.40.0`[cite: 1]
- **Manipulation de paquets :** `scapy>=2.5.0`[cite: 1]
- **Bibliothèque standard :** `socket`, `ssl`, `urllib.parse`, `concurrent.futures`, `hashlib`, `math`, `pathlib`, `os`, `time`, `json`, `datetime`[cite: 1]

---

## 3. Sécurité du Langage Python et Gestion des Risques Cyber / Hacking

Python offre une grande rapidité de développement et un écosystème riche en cybersécurité, mais il impose des exigences strictes en matière d'environnement, de dépendances, de secrets et d'exécution privilégiée :

### 3.1 Gestion des secrets et intégrations externes (OSINT / Threat Intel)
- **Interdiction des secrets codés en dur :** Les clés API (ex. `VT_API_KEY` pour VirusTotal) doivent être lues depuis les variables d'environnement (`os.getenv("VT_API_KEY")`) ou un coffre/fichier local exclu par `.gitignore`[cite: 1].
- **Hygiène des logs :** Ne jamais journaliser la clé API complète ni les en-têtes d'authentification dans les sorties console ou les rapports exportés.
- **Limites de débit (*rate limiting*) & API tierces :** Les API publiques (NIST NVD, VirusTotal gratuit) imposent des quotas et des latences ; prévoir gestion des codes HTTP (`403`, `404`, `429`, `5xx`), *timeouts* et messages d'erreur non verbeux sur la stack interne.

### 3.2 Privilèges, réseau et surface d'attaque offensive
- **Moindre privilège :** La majorité des modules (`recon`, `audit`, `forensic`, `fuzz`, `gui`) doivent fonctionner **sans `root`**. Seule la capture brute de paquets (`aegis traffic` via `Scapy`) nécessite des privilèges élevés (`sudo` ou capacité `CAP_NET_RAW` / `CAP_NET_ADMIN` sur Linux)[cite: 1].
- **Contrôle des cibles et du bruit réseau :** Limiter le nombre de *workers* (`ThreadPoolExecutor`), appliquer des *timeouts* réseau systématiques et éviter les requêtes non bornées.
- **Isolation d'environnement :** Recommander l'installation dans un environnement virtuel (`venv`) afin d'éviter les collisions avec les paquets système gérés par les gestionnaires de paquets Linux (ex. `PEP 668` sur Debian/Kali/Arch récents)[cite: 1].

### 3.3 Vulnérabilités applicatives dans l'outil lui-même (hardening)
- **Injection HTML / XSS dans les rapports HTML :** Dans `generate_html_report`, l'injection brute de données issues de cibles externes (bannières HTTP, en-têtes `Server`, descriptions CVE, chemins) dans un document HTML peut introduire des séquences problématiques (`</script>`, balises ou entités). **Exigence TRD :** échapper systématiquement les chaînes dynamiques (`html.escape`) et/ou sérialiser proprement en JSON échappé (`<` -> `\u003c`) avant insertion dans le HTML[cite: 1].
- **Traversée de chemin / validation d'entrées :** Valider les chemins de fichiers (`Path`, `exists=True` via `Click`)[cite: 1], normaliser les URLs (`urllib.parse.urlparse`) et valider les plages de ports (`1` à `65535`) avant exécution.
- **Chaîne d'approvisionnement (*supply chain*) :** Figer ou encadrer proprement les versions dans `pyproject.toml` / `requirements.txt`, auditer périodiquement les dépendances (`pip-audit` / `safety`) et exclure `aegis_reports/`, `*.json`, `*.log`, `.venv/` via `.gitignore`[cite: 1].

---

## 4. Robustesse du Code, Résilience et Performance

### 4.1 Gestion de la mémoire sur gros fichiers (`forensic`)
- **Problème identifié dans le prototype :** `calculate_entropy` et `extract_strings` lisent l'intégralité du fichier en mémoire (`f.read()`), ce qui peut provoquer une forte pression mémoire (voire un `MemoryError` / OOM kill) sur des fichiers volumineux (images disque, dumps, archives lourdes)[cite: 1].
- **Exigence TRD :** Traiter les fichiers **par blocs (*chunks*)** (ex. `4096` ou `65536` octets) pour le calcul de l'entropie de Shannon (accumulation des fréquences d'octets sur flux) et l'extraction de chaînes ASCII/UTF-8, et borner l'affichage/extraction si nécessaire[cite: 1].

### 4.2 Gestion des exceptions et arrêt propre
- **Aucune exception non interceptée au niveau module :** Encadrer les appels réseau (`requests.RequestException`, `socket.gaierror`, `ssl.SSLError`, `Timeout`), E/S disque (`OSError`, `PermissionError`) et threads (`Exception`) avec des retours explicites et non bloquants[cite: 1].
- **Interruption utilisateur (`Ctrl+C`) :** Gérer proprement `KeyboardInterrupt` dans les boucles longues (`monitor`, `traffic`, scans) afin de libérer les ressources et afficher un état de sortie propre[cite: 1].
- **Thread-safety et TUI (`gui.py`) :** Les appels bloquants (scan réseau, requêtes HTTP/CVE, analyse de fichiers) exécutés depuis `Textual` ne doivent pas figer la boucle événementielle de l'interface ; les isoler dans des *workers* asynchrones/threads dédiés et acheminer proprement les sorties vers le widget `Log`[cite: 1].

### 4.3 Validation des entrées utilisateur
- **Ports (`recon`) :** Vérifier que chaque port est un entier compris dans `[1, 65535]`, dédupliquer la liste et rejeter proprement les formats malformés[cite: 1].
- **URLs et protocoles (`audit`, `fuzz`) :** Normaliser le schéma (`http`/`https`) avec prudence (privilégier `https` ou respecter explicitement l'URL fournie) et valider la présence d'un `hostname` valide[cite: 1].
- **Logs (`monitor`) :** Gérer la rotation ou troncature potentielle de fichier log (*logrotate*) en vérifiant la taille du fichier entre deux itérations si nécessaire.

---

## 5. Stratégie de Test, Qualité et Déploiement

### Tests automatisés recommandés
- **Tests unitaires (`pytest`) :**
  - `forensic.py` : vérification des hashes MD5/SHA-1/SHA-256 sur vecteurs connus, entropie nulle sur fichier vide, entropie proche de `0` sur texte répétitif et proche de `8` sur données aléatoires, extraction de chaînes[cite: 1].
  - `recon.py` : validation du parsing des ports, gestion des hôtes introuvables (`socket.gaierror`) et comportement sur ports fermés/ouverts (mock socket)[cite: 1].
  - `audit.py` & `fuzz.py` : tests avec réponses HTTP mockées (`requests` / `responses` ou `unittest.mock`), gestion d'erreurs API NVD et filtrage des statuts HTTP[cite: 1].
  - `reporter.py` : génération effective des fichiers `json`, `md` et `html` et vérification de l'échappement des contenus spéciaux[cite: 1].
- **Tests d'intégration CLI :** Invocation de `aegis --help`, `aegis` (dashboard), `aegis auto -w system-health` et `aegis forensic` sur fichiers temporaires.

### Qualité et livraison
- **Typage & lint :** Adoption progressive des annotations de types (`typing`), formatage/linting (`ruff` ou `flake8`) et vérification statique (`mypy`).
- **Versioning & release :** Suivi sémantique (`SemVer`, ex. `v0.1.0`, `v0.2.0`), tags Git annotés et notes de version sur le dépôt[cite: 1].