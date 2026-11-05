# Décisions d'architecture (ADR)

Une fiche par décision : contexte, options, décision, conséquences.
Format : numéro croissant, statut `proposé` / `accepté` / `remplacé`.
Les ADR 0001 à 0005 ont été rédigés a posteriori (5 novembre 2026) pour des
décisions déjà prises dans le code.

| N° | Décision | Statut |
|---|---|---|
| [0001](0001-python-plutot-que-go.md) | Python plutôt que Go pour le pipeline | accepté |
| [0002](0002-guarddog-en-bibliotheque.md) | GuardDog utilisé comme bibliothèque Python | accepté |
| [0003](0003-threat-bloquant-capability-ignore.md) | Règles `threat-*` bloquantes, `capability-*` ignorées | accepté (à revoir) |
| [0004](0004-verdict-lisible-et-monotone.md) | Verdict lisible, qui ne peut qu'empirer | accepté |
| [0005](0005-etage-indisponible-fail-open-ou-closed.md) | Comportement quand un étage est indisponible | proposé |
| [0006](0006-installation-trivy-verifiee.md) | Installation de Trivy en version fixe et vérifiée | accepté |
