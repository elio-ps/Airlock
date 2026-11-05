# ADR-0003 : Règles `threat-*` bloquantes, `capability-*` ignorées

Statut : accepté, à revoir (voir Conséquences) · Date : 2026-11-05 (rédigée a posteriori)

## Contexte
GuardDog produit deux familles de règles. `capability-*` décrit ce que le
code peut faire (réseau, fichiers, processus) et apparaît dans presque tout
code légitime. `threat-*` décrit un comportement documenté comme malveillant
(exfiltration, exécution de code obfusqué, persistance).

## Options
1. Bloquer sur toute règle GuardDog.
2. Bloquer sur `threat-*`, ignorer `capability-*`.
3. Score pondéré mêlant les deux.

## Décision
Option 2 : une règle `threat-*` donne BLOCK, les `capability-*` ne changent
pas le verdict.

## Conséquences
+ Peu de faux positifs sur le corpus d'évaluation (10/10 malveillants,
  0 faux positif sur 10 sains).
− Faille connue : la fixture `hook-evil-sim` (postinstall simulé) ne déclenche
  que des `capability-*` et est donc autorisée. Le test correspondant est
  marqué xfail.
− À revoir : ajouter une règle « `capability-*` dans un hook d'installation
  (postinstall) », puis retirer le xfail.
