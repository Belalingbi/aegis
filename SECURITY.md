# Politique de Sécurité — AEGIS Security Framework

## Signalement de Vulnérabilités

La sécurité de nos utilisateurs et de l'outil est prioritaire. Si vous découvrez une faille de sécurité dans AEGIS, merci de nous la signaler de manière responsable :

- **Contact :** Via GitHub Security Advisories ou profil auteur [Belalingbi](https://github.com/Belalingbi/)
- Merci de ne pas ouvrir d'issue publique avant publication d'un correctif.
- Veuillez joindre les étapes de reproduction, un PoC minimal et les versions testées.

## Directives de Durcissement pour les Utilisateurs

1. **Moindre Privilège :** N'exécutez avec `sudo` ou privilèges administrateur que le module `aegis traffic` (nécessaire pour la capture de paquets bruts).
2. **Isolation :** Utilisez un environnement virtuel Python ou le conteneur Docker officiel.
3. **Gestion des Clés :** Ne partagez jamais vos clés API tierces (ex: VirusTotal).
