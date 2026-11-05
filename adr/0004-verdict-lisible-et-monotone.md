# ADR-0004 : Verdict lisible, qui ne peut qu'empirer

Statut : accepté · Date : 2026-11-05 (décision antérieure, rédigée a posteriori)

## Contexte
Le verdict (ALLOW / QUARANTINE / BLOCK) doit pouvoir être expliqué à un
humain et ajusté selon la politique d'une entreprise.

## Options
1. Score pondéré unique avec seuil.
2. Règles explicites, chaque signal pouvant relever le niveau de gravité.

## Décision
Option 2 (`verdict/aggregate.py`) :
- une règle `threat-*` GuardDog : BLOCK ;
- une CVE HIGH ou CRITICAL : QUARANTINE ;
- Scorecard < 3/10 sur un paquet peu dépendu (< 50) : QUARANTINE ;
- sinon ALLOW.
Le verdict ne peut qu'empirer au fil des étages : un BLOCK n'est jamais
annulé par un bon score deps.dev. Les seuils sont isolés dans `Policy`,
chargeable depuis un fichier JSON.

## Conséquences
+ Chaque décision est justifiée par une raison lisible dans le rapport.
+ Seuils modifiables sans toucher à la logique.
− Moins fin qu'un score : deux signaux faibles ne s'additionnent pas.
− La règle sur les dépendants dépend du champ `dependent_count` de deps.dev,
  à vérifier sur une vraie réponse (valeur absente = 0 dans le code).
