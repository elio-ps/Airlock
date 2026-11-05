# ADR-0002 : GuardDog utilisé comme bibliothèque Python

Statut : accepté · Date : 2026-11-05 (décision antérieure, rédigée a posteriori)

## Contexte
GuardDog détecte des comportements malveillants dans les paquets npm et
PyPI. Il peut s'appeler en ligne de commande ou s'importer en Python.

## Options
1. Appeler la commande `guarddog` en sous-processus et lire sa sortie texte.
2. Importer GuardDog et utiliser ses résultats structurés.

## Décision
Option 2 (`analysis/guarddog_scan.py`).

## Conséquences
+ Résultats structurés (nom de règle, localisation) sans parsing de texte.
+ Plus facile à tester (mode `scan_local`, fixtures).
− Couplage à l'API interne de GuardDog : une mise à jour peut casser le
  wrapper. Version à fixer dans `requirements.txt` (actuellement `>=1.0`).
− GuardDog s'exécute dans le même processus que Airlock : pas d'isolation.
  Le code analysé n'est pas exécuté, mais un bug d'analyse pèse sur le
  processus principal.
