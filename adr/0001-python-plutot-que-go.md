# ADR-0001 : Python plutôt que Go pour le pipeline

Statut : accepté · Date : 2026-11-05 (décision antérieure, rédigée a posteriori)

## Contexte
Airlock enchaîne ingestion, SBOM, Trivy, GuardDog, deps.dev et verdict.
GuardDog est écrit en Python. Trivy, Falco et OPA sont écrits en Go. Le
projet est mené par un binôme, avec un seul langage souhaité pour limiter
la complexité d'intégration.

## Options
1. Python pour tout le pipeline.
2. Go pour le proxy de paquets, Python pour l'analyse.
3. Go pour tout.

## Décision
Option 1 pour l'étage d'analyse actuel. L'option 2 reste possible pour le
proxy de paquets du rendu final, à trancher dans un nouvel ADR.

## Conséquences
+ GuardDog s'utilise comme bibliothèque (voir ADR-0002), le SBOM
  (`cyclonedx-python-lib`) et `requests` sont dans le même écosystème.
+ Un futur étage IA (scikit-learn, pandas) reste dans le même langage.
− Un proxy en Python sera moins performant qu'en Go sous charge.
− Trivy reste un binaire externe à installer (voir ADR-0006).
