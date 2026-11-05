# ADR-0006 : Installation de Trivy en version fixe et vérifiée

Statut : accepté · Date : 2026-11-05

## Contexte
Airlock appelle le binaire Trivy, qui ne s'installe pas via PyPI. Le script
`install.sh` de la branche `main` change dans le temps et s'exécute en `sudo`.
C'est un risque de chaîne d'approvisionnement, ce qu'Airlock combat.

## Options
1. `curl ... | sudo sh` depuis `main` : simple, mais ni script ni version figés.
2. Script du tag de la version : version et script figés.
3. Archive de la release et vérification SHA-256 : plus long, entièrement vérifiable.

## Décision
Option 2 en développement :
`curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/v<VERSION>/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v<VERSION>`
Option 3 dans l'image de production (Dockerfile). Version unique notée dans
le dépôt (`v0.76.1`, à confirmer sur la page des releases avant usage).

## Conséquences
+ Installation reproductible et auditable.
+ La base de vulnérabilités se prépare à l'avance (`trivy image --download-db-only`)
  et se passe via `cache_dir` (à brancher dans `pipeline.py`).
− Mise à jour de version manuelle, à consigner dans le journal des décisions.
