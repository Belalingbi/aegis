# PRD — AEGIS Security Framework

- **Projet :** AEGIS (`aegis-sec`)[cite: 1]
- **Auteur / Organisation :** Belalingbi Steve — CyberAnonymat Project[cite: 1]
- **Format cible :** CLI & TUI (Terminal User Interface) pour environnements Linux (Kali Linux, Parrot OS, Arch Linux, BlackArch, Linux générique)[cite: 1]
- **Statut :** Cadrage produit & évolution post-v0.2.0[cite: 1]

---

## 1. Vision et Objectif Produit

**AEGIS** est un framework modulaire en ligne de commande (CLI) et interface terminal graphique (TUI) conçu pour centraliser les opérations courantes de diagnostic réseau, d'audit de configuration/vulnérabilités, d'automatisation de workflows, d'analyse forensique légère, de surveillance de journaux, d'analyse de trafic et de collecte OSINT/Threat Intelligence au sein d'une commande unique (`aegis`)[cite: 1].

### Problème résolu
Les praticiens (analystes SOC, pentesters, administrateurs systèmes, chercheurs OSINT) jonglent souvent entre de multiples scripts isolés et outils aux sorties hétérogènes. AEGIS unifie ces briques dans une interface cohérente, installable globalement via Python, capable de produire des sorties lisibles en terminal et des rapports exportables (`JSON`, `Markdown`, `HTML`)[cite: 1].

---

## 2. Périmètre Fonctionnel et Personas

### Personas cibles
1. **Pentester / Auditeur sécurité offensive :** besoin de reconnaissance rapide, audit HTTP/SSL, fuzzing de chemins web et export structuré de constats[cite: 1].
2. **Analyste Blue Team / SOC / Incident Responder :** besoin de surveillance de logs en temps réel, analyse forensique de fichiers (hashes, entropie, chaînes, réputation VirusTotal) et capture de trafic[cite: 1].
3. **Administrateur système / Chercheur OSINT :** besoin de contrôles d'hygiène système, corrélation de vulnérabilités (NIST NVD) et workflows reproductibles[cite: 1].

### Modules et capacités
| Module / Commande | Rôle produit | Fonctionnalités clés |
| :--- | :--- | :--- |
| **Dashboard global (`aegis`)** | Point d'entrée & orientation | Bannière, tableau récapitulatif des commandes et aide contextuelle[cite: 1]. |
| **Reconnaissance (`aegis recon`)** | Cartographie réseau initiale | Résolution DNS, scan de ports TCP multithreadé et *banner grabbing*[cite: 1]. |
| **Audit & CVE (`aegis audit`)** | Évaluation de surface & menaces | Audit des en-têtes HTTP de sécurité, vérification SSL/TLS, recherche CVE via API NIST NVD et export[cite: 1]. |
| **Automatisation (`aegis auto`)** | Orchestration de scénarios | Workflows prédéfinis (ex. `system-health`, `quick-pentest`)[cite: 1]. |
| **Forensique (`aegis forensic`)** | Triage de fichiers & IOCs | Métadonnées, hachages (MD5, SHA-1, SHA-256), entropie de Shannon, extraction de chaînes ASCII et consultation VirusTotal (`--vt`)[cite: 1]. |
| **Monitoring (`aegis monitor`)** | Détection continue sur logs | Lecture en continu d'un fichier journal et mise en évidence d'indicateurs/mots-clés suspects[cite: 1]. |
| **Trafic (`aegis traffic`)** | Observation réseau passive | Capture et affichage de trames/paquets (IP, TCP, UDP, ICMP) via Scapy[cite: 1]. |
| **Fuzzing web (`aegis fuzz`)** | Découverte de chemins/ressources | Test de chemins via wordlist par défaut ou personnalisée, filtrage des codes HTTP pertinents[cite: 1]. |
| **Interface TUI (`aegis gui`)** | Pilotage visuel en terminal | Navigation latérale, saisie de cible et console de sortie interactive[cite: 1]. |
| **Reporting (`reporter`)** | Restitution & archivage | Génération de rapports dans `aegis_reports/` aux formats `json`, `md` et `html`[cite: 1]. |

---

## 3. Exigences Fonctionnelles (FR)

- **FR-01 — Invocation unifiée :** L'utilisateur doit pouvoir invoquer `aegis` sans argument pour afficher le tableau de bord, ou appeler une sous-commande dédiée avec `--help`[cite: 1].
- **FR-02 — Reconnaissance cible :** `aegis recon` doit résoudre une cible (IP ou nom de domaine), scanner une liste de ports fournie et afficher l'état et la bannière éventuelle[cite: 1].
- **FR-03 — Audit web, TLS et veille CVE :** `aegis audit` doit inspecter les en-têtes HTTP clés (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Server`), vérifier les informations de certificat TLS (`HTTPS`) et interroger l'API NIST NVD (par mot-clé `--cve`, technologie détectée ou cible)[cite: 1].
- **FR-04 — Workflows automatisés :** `aegis auto` doit exécuter des séquences nommées (`system-health`, `quick-pentest`) et informer clairement si un workflow est inconnu[cite: 1].
- **FR-05 — Analyse forensique et OSINT/Threat Intel :** `aegis forensic` doit calculer MD5, SHA-1 et SHA-256, évaluer l'entropie de Shannon (0 à 8) avec seuils d'alerte, extraire les chaînes ASCII et interroger optionnellement VirusTotal v3 via la variable d'environnement `VT_API_KEY`[cite: 1].
- **FR-06 — Surveillance de journaux :** `aegis monitor` doit suivre un fichier de log en temps réel, filtrer/mettre en valeur les lignes contenant des motifs suspects et s'arrêter proprement sur `Ctrl+C`[cite: 1].
- **FR-07 — Capture de trafic :** `aegis traffic` doit permettre de spécifier une interface (`-i`) et un nombre de paquets (`-c`), tout en gérant l'absence de privilèges suffisants de manière explicite[cite: 1].
- **FR-08 — Fuzzing de répertoires :** `aegis fuzz` doit accepter une URL cible, une wordlist optionnelle (`-w`) et un niveau de parallélisme (`-p`), en rapportant les statuts HTTP notables (`200`, `301`, `302`, `401`, `403`)[cite: 1].
- **FR-09 — Export de rapports :** Les modules éligibles (`audit`, et extensible aux autres modules) doivent pouvoir exporter leurs résultats en `json`, `md` et `html`[cite: 1].

---

## 4. Exigences Non Fonctionnelles (NFR), Sécurité et Éthique

### Usage responsable, cybersécurité et hacking encadré
- **Cadre légal et éthique :** AEGIS intègre des fonctions offensives/exploratoires (scan de ports, fuzzing de répertoires, capture réseau, corrélation CVE)[cite: 1]. L'outil doit être destiné exclusivement à des environnements autorisés, audits légitimes, laboratoires (ex. DVWA, Metasploitable, cibles de test autorisées) et opérations défensives/OSINT[cite: 1].
- **Avertissement explicite et responsabilité :** Le produit doit documenter clairement les règles d'usage autorisé (`README.md` / `SECURITY.md`) et éviter d'embarquer des charges utiles destructrices ou d'exploitation non maîtrisée.
- **OSINT & confidentialité :** Lors des requêtes vers des services tiers (NIST NVD, VirusTotal), seules les informations nécessaires (hash SHA-256, mot-clé technique ou cible explicitement fournie par l'utilisateur) doivent être transmises, sans exfiltration silencieuse de données locales.

### Fiabilité et expérience utilisateur
- **Réactivité :** Les opérations réseau et de scan doivent utiliser le parallélisme contrôlé et des délais d'expiration (*timeouts*) afin de ne pas bloquer indéfiniment l'utilisateur[cite: 1].
- **Portabilité Linux :** Fonctionnement dans un environnement virtuel Python (`venv`) ou installation éditable (`pip install -e .`) sur distributions Linux modernes (`Python >= 3.9`)[cite: 1].

---

## 5. Hors Périmètre (v0.2.0)

- Moteur d'exploitation automatisé de vulnérabilités à fort impact.
- Agent centralisé multi-hôtes ou plateforme SaaS cloud.
- Décompilation binaire complète ou analyse dynamique en *sandbox* isolée.

---

## 6. Métriques de Succès Produit

- **Adoption & installation :** Installation propre sans conflit système dans un `venv` sur les distributions Linux ciblées[cite: 1].
- **Complétude modulaire :** 100 % des commandes annoncées dans le dashboard (`recon`, `audit`, `auto`, `forensic`, `monitor`, `traffic`, `fuzz`, `gui`) opérationnelles et documentées[cite: 1].
- **Qualité des livrables :** Génération fiable de rapports `JSON`, `Markdown` et `HTML` exploitables lors d'un compte rendu[cite: 1].