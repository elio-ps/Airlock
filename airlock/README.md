# Airlock — Contrôler ce qui entre dans la chaîne de build

Projet scolaire à but éducatif. Étage traité ici : **"Passer un paquet
npm/PyPI au crible"** (SBOM, Trivy, GuardDog, deps.dev), première brique du
pipeline Airlock (proxy → analyse par étages → policies → verdict).

## Pourquoi Python

Choix assumé pour ce projet :
- **GuardDog** (DataDog) est écrit en Python — on l'utilise comme
  bibliothèque, pas en sous-processus, ce qui donne des résultats
  structurés directement exploitables plutôt que du parsing de texte.
- L'écosystème SBOM (`cyclonedx-python-lib`), les registres (`requests`),
  et un futur étage IA/scoring (scikit-learn, pandas) restent dans le
  même écosystème, sans changement de langage entre les étages.
- Alternative envisagée : Go pour le proxy de paquets (cohérent avec
  Trivy/Falco/OPA), mais écartée ici pour limiter la complexité
  d'intégration d'un projet scolaire à un seul langage.

## Architecture de cet étage

```
ingestion (fetch.py) → SBOM (generate.py) → ┬→ Trivy (trivy_scan.py)   ┐
                                              ├→ GuardDog (guarddog_scan.py) ├→ verdict (aggregate.py)
                                              └→ deps.dev (depsdev.py)  ┘
```

Chaque étage réseau (Trivy, deps.dev) est conçu pour **échouer proprement**
plutôt que de faire planter le pipeline : un signal indisponible est
marqué `unavailable`, jamais confondu avec un signal "RAS". C'est une
distinction volontaire pour ne pas donner un faux sentiment de sécurité si
un outil n'a simplement pas pu s'exécuter (réseau, timeout...).

```
airlock/
├── ingest/fetch.py          # télécharge + extrait un paquet npm/PyPI, vérifie l'intégrité
├── sbom/generate.py         # génère un SBOM CycloneDX 1.5 (composant + dépendances déclarées)
├── analysis/
│   ├── trivy_scan.py        # scan CVE via `trivy sbom`
│   ├── guarddog_scan.py     # analyse comportementale statique (règles threat-*/capability-*)
│   └── depsdev.py           # score OpenSSF Scorecard, hygiène du projet
├── verdict/aggregate.py     # combine tout en un verdict ALLOW/QUARANTINE/BLOCK justifié
├── corpus/
│   ├── samples/              # 10 échantillons malveillants + 10 sains (fixtures GuardDog, Apache 2.0)
│   └── run_eval.py           # mesure faux positifs / négatifs sur le corpus
├── pipeline.py               # orchestrateur CLI bout en bout
└── tests/test_pipeline.py    # tests unitaires (ingestion réelle + logique d'agrégation)
```

## Installation

```bash
pip install -r airlock/requirements.txt

# Trivy (binaire Go, pas sur PyPI) :
curl -sL -o trivy.tar.gz \
  "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz"
tar xzf trivy.tar.gz trivy && chmod +x trivy && mv trivy ~/.local/bin/
```

## Utilisation

```bash
# Scan complet d'un paquet
python3 -m airlock.pipeline pypi requests --version 2.31.0
python3 -m airlock.pipeline npm left-pad

# Sauter des étages (utile si Trivy/deps.dev ne sont pas joignables)
python3 -m airlock.pipeline npm some-package --skip trivy,depsdev

# Policy personnalisée (seuils d'entreprise)
python3 -m airlock.pipeline pypi some-package --policy ma_policy.json
```

Chaque run produit un rapport complet dans
`airlock_runs/<ecosystem>-<name>-<version>/report.json`.

## Évaluer le corpus de référence

```bash
python3 -m airlock.corpus.run_eval
```

Produit `airlock/corpus/corpus_eval_report.json` avec matrice de confusion
et détail par échantillon. Voir `airlock/corpus/samples/MANIFEST.md` pour
la provenance et la justification du corpus.

**Résultat obtenu sur ce corpus** (10 malveillants / 10 sains, fixtures
officielles GuardDog) : **VP=10, FN=0, VN=10, FP=0** — accuracy 100 %,
precision 100 %, recall 100 %. Ce résultat élevé s'explique par la nature
du corpus : ce sont les propres tests de non-régression de GuardDog, donc
par construction bien séparés pour ses règles. C'est un bon test de
*cohérence de notre intégration* (le wrapper appelle correctement
l'analyseur et interprète correctement sa sortie), mais **pas** une mesure
de la performance de GuardDog en conditions réelles sur des paquets
inconnus — ce sera l'objet du corpus de détonation dynamique (Falco),
distinct de cet étage statique.

## Méthodologie de jugement (verdict)

Le verdict n'est **pas** un score pondéré opaque. Logique volontairement
lisible, avec seuils isolés dans `Policy` pour rester "configurable selon
la politique d'entreprise" :

| Signal | Déclencheur | Verdict |
|---|---|---|
| GuardDog | ≥1 règle `threat-*` déclenchée | **BLOCK** |
| Trivy | CVE de sévérité HIGH/CRITICAL | QUARANTINE |
| deps.dev | Scorecard < 3/10 **et** < 50 dépendants directs | QUARANTINE |
| — | Aucun signal suspect | ALLOW |

Le verdict ne peut qu'**empirer** au fil des étages (`_escalate`), jamais
s'améliorer : un `BLOCK` de GuardDog n'est jamais annulé par un bon score
deps.dev. Un signal `unavailable` (échec réseau) n'aggrave jamais le
verdict à lui seul — on ne pénalise pas un paquet parce qu'un outil de
scan a eu un problème réseau.

Le choix "capability-* ignorées, threat-* bloquantes" vient du fait que
`capability-*` décrit une capacité du code (accès fichier, réseau...),
présente dans la quasi-totalité du code légitime — la traiter comme
suspecte produirait un flot de faux positifs inexploitable. `threat-*`
décrit un pattern de comportement documenté comme malveillant
(exfiltration, obfuscation d'exécution, persistance...), avec beaucoup
moins de faux positifs attendus.

## Limitations connues de cet environnement de développement

Le bac à sable réseau utilisé pour développer et tester ce projet
n'autorise pas `mirror.gcr.io`/`ghcr.io` (DB Trivy) ni `api.deps.dev`
(scorecards). Le code de ces deux modules est du client HTTP/CLI standard,
testé pour sa logique de dégradation propre (`scan_failed` +
`error_message`), mais pas pour un scan réel en conditions normales. À
tester dans un environnement réseau non restreint, ou après ajout de ces
domaines à la liste d'autorisation.

## Prochaines étapes (hors scope de cet étage)

- Détonation en bac à sable jetable (Docker + Falco) sur le PoC comportemental
- Proxy de paquets sur le chemin critique (npm/PyPI)
- Policies YAML par entreprise (le fichier `Policy` est déjà prévu pour ça)
- Étage IA de scoring agrégeant tous les signaux
