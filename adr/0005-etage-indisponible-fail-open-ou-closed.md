# ADR-0005 : Comportement quand un étage est indisponible

Statut : proposé · Date : 2026-11-05

## Contexte
Trivy et deps.dev dépendent du réseau. Aujourd'hui, un étage indisponible est
marqué `unavailable` et n'aggrave jamais le verdict : si GuardDog ne trouve
rien, le paquet est autorisé (ALLOW) même sans CVE ni score. Pour un proxy
placé sur le chemin critique, c'est un choix de sécurité à assumer.

## Options
1. Fail-open (actuel) : étage indisponible, on continue.
2. Fail-closed : au moins un étage indisponible, donc QUARANTINE.
3. Configurable par politique, avec défaut fail-closed en production.

## Décision proposée
Option 3 : ajouter à `Policy` un paramètre (par exemple `fail_closed`).
Défaut fail-open pour le développement et les tests, fail-closed en production.
Distinguer aussi « paquet inconnu de deps.dev » (code 404, signal en soi pour
un paquet récent) d'une panne réseau.

## Conséquences
+ Une panne de Trivy ou de deps.dev ne laisse plus passer un paquet sans
  contrôle complet.
− Plus de mises en quarantaine à traiter à la main en cas de panne : prévoir
  une procédure Day 2 (et le cache des résultats, ADR à venir).
− À implémenter et tester (`test_aggregate_marks_unavailable_stage_distinctly`
  existe déjà et sert de base).
