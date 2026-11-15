# Guide d'utilisation d'Airlock

Ce guide explique, pas à pas, comment installer Airlock, analyser un paquet,
lire le résultat, adapter la politique de décision, puis comment lire le code.
Il s'adresse à quelqu'un qui découvre le projet.

---

## 1. Ce que fait Airlock, en une phrase

Airlock prend **un paquet npm ou PyPI**, le fait passer par plusieurs analyses
indépendantes, puis rend un verdict lisible : **ALLOW** (on peut l'utiliser),
**QUARANTINE** (un humain doit regarder) ou **BLOCK** (refusé).

```
ingestion -> SBOM -> Trivy -> GuardDog -> deps.dev -> détonation -> verdict
```

| Étape | Question posée | Exécute le code du paquet ? |
|---|---|---|
| ingestion | Le paquet téléchargé est-il intact ? | non |
| SBOM | De quoi est-il composé (dépendances) ? | non |
| Trivy | Contient-il des vulnérabilités connues (CVE) ? | non |
| GuardDog | Son code source ressemble-t-il à un malware ? | non |
| deps.dev | Le projet est-il connu et bien tenu ? | non |
| détonation | Que fait-il **vraiment** quand on l'installe ? | **oui**, dans un bac à sable |
| verdict | Que décide-t-on, et pourquoi ? | — |

Règle centrale : **seul un comportement observé à la détonation peut bloquer**.
Les signaux statiques (CVE, motifs suspects, mauvaise réputation) mettent au
plus en quarantaine (voir ADR-0007).

---

## 2. Installation

### 2.1 Prérequis

| Outil | Pourquoi | Obligatoire ? |
|---|---|---|
| Python 3.12 | le pipeline | oui |
| Trivy 0.76.1 | scan des CVE | non (sinon étape `unavailable`) |
| Podman (rootless) | bac à sable de détonation | non (sinon `--skip detonation`) |
| Falco (via `sudo`) | capteur noyau pendant la détonation | non, mais sans lui la détonation est « aveugle » |
| Accès Internet | registres npm/PyPI, base Trivy, deps.dev | oui pour un paquet distant |

### 2.2 Commandes

Depuis la racine du dépôt :

```bash
# 1. Environnement Python
python3 -m venv venv
. venv/bin/activate
pip install -r airlock/requirements.txt

# 2. Trivy, version épinglée (ADR-0006)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/v0.76.1/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin v0.76.1

# 3. Image du bac à sable (à refaire après chaque modification de sandbox/)
podman build -t localhost/airlock-sandbox:1 sandbox/

# 4. Vérifier que tout marche
python3 -m pytest airlock/tests -c airlock/pytest.ini -p no:cacheprovider
```

### 2.3 Démarrer le capteur Falco (avant les détonations)

```bash
sudo sandbox/falco.sh start     # démarre le capteur
sudo sandbox/falco.sh status    # vérifie qu'il tourne
sudo sandbox/falco.sh stop      # l'arrête
```

Falco est la **seule** partie qui tourne en root. Sans lui, la détonation reste
utile (le « sink » réseau voit encore les fuites de secrets), mais les
comportements purement fichiers (persistance, dropper) ne sont pas vus. Le
résultat est alors marqué `unavailable`, **jamais** « propre ».

---

## 3. Analyser un paquet

### 3.1 Les commandes de base

```bash
. venv/bin/activate

# Un paquet PyPI, version précise
python3 -m airlock.pipeline pypi requests --version 2.31.0

# Un paquet npm, dernière version
python3 -m airlock.pipeline npm left-pad

# Un paquet npm scopé
python3 -m airlock.pipeline npm @babel/core --version 7.24.0

# Une archive locale (npm uniquement), par exemple un paquet pas encore publié
npm pack --ignore-scripts            # produit mon-paquet-1.0.0.tgz sans rien exécuter
python3 -m airlock.pipeline npm --local ./mon-paquet-1.0.0.tgz
```

### 3.2 Toutes les options

| Option | Effet |
|---|---|
| `npm` / `pypi` | l'écosystème (obligatoire) |
| `<nom>` | le nom du paquet (sauf avec `--local`) |
| `--version X` | une version précise ; sinon la dernière |
| `--local ARCHIVE` | analyse une archive `.tgz` locale au lieu de télécharger (npm) ; deps.dev est alors sauté automatiquement |
| `--skip a,b` | saute des étapes : `sbom`, `trivy`, `guarddog`, `depsdev`, `detonation` |
| `--policy fichier.json` | politique de décision personnalisée (voir §5) |
| `--trivy-timeout N` | délai max de Trivy en secondes (120 par défaut ; mettre 300 au premier lancement, le temps que la base se télécharge) |
| `--quiet` | n'affiche que le verdict JSON, sans le journal des étapes |

Exemples utiles :

```bash
# Hors ligne ou sans bac à sable : seulement l'analyse statique locale
python3 -m airlock.pipeline npm --local ./pkg.tgz --skip trivy,detonation

# Mode « production » : une étape en panne => quarantaine
echo '{"fail_closed": true}' > prod.json
python3 -m airlock.pipeline pypi requests --policy prod.json
```

### 3.3 Le code de sortie (pour la CI ou un script)

| Code | Signification |
|---|---|
| `0` | ALLOW |
| `2` | QUARANTINE |
| `3` | BLOCK |
| `1` | erreur (paquet introuvable, archive invalide, mauvaise option…) |

```bash
python3 -m airlock.pipeline npm "$PKG" --quiet
case $? in
  0) echo "ok, on installe" ;;
  2) echo "à revoir par un humain" ;;
  3) echo "refusé" ; exit 1 ;;
  *) echo "erreur d'analyse" ; exit 1 ;;
esac
```

---

## 4. Lire le résultat

### 4.1 Ce qui s'affiche

Exemple réel (`npm left-pad 1.3.0`, Falco arrêté) :

```
[airlock] Ingesting npm:left-pad@1.3.0...
[airlock]   -> left-pad@1.3.0 fetched, sha256=870c0fe10962...
[airlock] Generating the CycloneDX SBOM...
[airlock] Trivy scan (CVEs)...
[airlock]   -> 0 CVE(s) found
[airlock] GuardDog scan (behaviour)...
[airlock]   -> 0 signal(s), 0 threat
[airlock] deps.dev query (reputation)...
[airlock]   -> Scorecard=3.9
[airlock] Detonation in the sandbox (behaviour)...
[airlock]   -> unavailable: Falco did not see the sentinel: the sensor is blind or stopped
[airlock] Aggregating the verdict...
[airlock]   -> VERDICT: ALLOW
[airlock] Full report: airlock_runs/npm-left-pad-1.3.0/report.json
```

Le journal (lignes `[airlock]`) part sur la sortie d'erreur ; le verdict JSON
part sur la sortie standard. On peut donc faire `... --quiet | jq .verdict`.

### 4.2 Le verdict JSON

```json
{
  "package_name": "left-pad",
  "version": "1.3.0",
  "ecosystem": "npm",
  "verdict": "allow",
  "reasons": ["No suspicious signal on the stages that ran."],
  "stages": [
    {"name": "sbom",       "status": "ok", "detail": "CycloneDX SBOM generated"},
    {"name": "trivy",      "status": "ok", "detail": "0 CVE(s) found, none severe"},
    {"name": "guarddog",   "status": "ok", "detail": "0 capability signal(s), 0 threat"},
    {"name": "deps.dev",   "status": "ok", "detail": "OpenSSF Scorecard score 3.9/10"},
    {"name": "detonation", "status": "unavailable", "detail": "execution failed: Falco did not see the sentinel..."}
  ]
}
```

- `verdict` : la décision.
- `reasons` : **pourquoi**, une ligne par signal qui a pesé. C'est ce qu'on lit en premier.
- `stages` : l'état de chaque étape.

### 4.3 Les quatre états d'une étape

| État | Sens | Exemple |
|---|---|---|
| `ok` | l'étape a tourné, rien de suspect | 0 CVE grave |
| `suspect` | l'étape a tourné et a trouvé quelque chose | règle GuardDog `threat-*` |
| `unavailable` | l'étape **n'a pas pu** conclure | Trivy sans base, Falco arrêté, installation qui a échoué dans le bac à sable |
| `skipped` | l'étape a été sautée volontairement | `--skip trivy`, deps.dev en mode `--local` |

> `unavailable` ne veut **jamais** dire « propre ». Par défaut (fail-open), une
> étape indisponible ne change pas le verdict ; avec `"fail_closed": true`, elle
> met le paquet en quarantaine (ADR-0005).

### 4.4 Quand obtient-on quel verdict ?

| Signal | Verdict |
|---|---|
| Détonation : comportement critique (lecture d'un faux secret, persistance, programme largué exécuté, canary envoyé sur le réseau) | **BLOCK** |
| Détonation : comportement douteux (connexion sortante, outil réseau lancé) | QUARANTINE |
| GuardDog : au moins une règle `threat-*` | QUARANTINE |
| Trivy : une CVE HIGH ou CRITICAL | QUARANTINE |
| deps.dev : Scorecard < 3/10 **et** moins de 50 dépendants, ou paquet inconnu | QUARANTINE |
| Code exécuté à l'installation (`postinstall`, `setup.py`…) qui n'a pas été détoné **complètement** | QUARANTINE |
| Rien de tout ça | ALLOW |

Le verdict ne peut **que s'aggraver** d'une étape à l'autre : un bon score
deps.dev n'annule jamais une quarantaine (ADR-0004).

Exemple : le fixture malveillant `hook-evil-sim`, analysé sans Falco, sort en
QUARANTINE (code 2) avec la raison
`Install-time code was not detonated: postinstall: node scripts/postinstall.js`.

### 4.5 Le rapport complet sur disque

Chaque analyse écrit `airlock_runs/<écosystème>-<nom>-<version>/` **dans le
dossier courant** :

```
airlock_runs/npm-left-pad-1.3.0/
├── report.json          # tout : paquet, verdict, détails de chaque étape
└── sbom/
    └── left-pad-1.3.0.cdx.json   # l'inventaire CycloneDX
```

Structure de `report.json` :

| Clé | Contenu |
|---|---|
| `package` | nom, version, sha256 de l'archive, hooks d'installation détectés |
| `verdict` | le verdict JSON ci-dessus |
| `details.trivy` | chaque CVE : identifiant, paquet, version corrigée, sévérité |
| `details.guarddog` | chaque règle déclenchée et ce qu'elle a trouvé |
| `details.depsdev` | score Scorecard, détail par critère, dépôt, licences, avis de sécurité |
| `details.detonation` | comportements observés, requêtes DNS, phases incomplètes, journal du bac à sable |

En cas de BLOCK, lire `details.detonation.findings` puis `details.detonation.log`.

---

## 5. Adapter la politique (fichier `--policy`)

Toutes les règles de décision sont des seuils regroupés dans la classe `Policy`
(`airlock/verdict/aggregate.py`). Un fichier JSON en remplace une partie ; les
clés absentes gardent leur valeur par défaut. Une clé mal orthographiée est
**refusée** (message d'erreur, code 1) pour ne pas être ignorée en silence.

| Clé | Défaut | Effet |
|---|---|---|
| `block_on_any_threat_rule` | `false` | `true` : une règle GuardDog `threat-*` bloque au lieu de mettre en quarantaine |
| `quarantine_on_cve_severity` | `["HIGH", "CRITICAL"]` | sévérités CVE qui mettent en quarantaine |
| `quarantine_on_scorecard_below` | `3.0` | seuil de score OpenSSF Scorecard |
| `quarantine_on_scorecard_below_dependents` | `50` | le seuil de score ne s'applique qu'aux paquets ayant moins de dépendants que ça |
| `quarantine_on_unknown_package` | `true` | paquet inconnu de deps.dev => quarantaine |
| `quarantine_on_undetonated_hook` | `true` | code d'installation non détoné => quarantaine |
| `fail_closed` | `false` | `true` : toute étape `unavailable` => quarantaine |
| `block_on_detonation_priority` | `["Emergency", "Alert", "Critical"]` | priorités Falco qui bloquent |
| `quarantine_on_detonation_priority` | `["Error", "Warning"]` | priorités Falco qui mettent en quarantaine |

Exemple de politique stricte pour une CI de production :

```json
{
  "fail_closed": true,
  "quarantine_on_cve_severity": ["MEDIUM", "HIGH", "CRITICAL"],
  "quarantine_on_scorecard_below": 5.0
}
```

---

## 6. La détonation en détail

Ce qui se passe quand l'étape `detonation` tourne (`airlock/detonation/sandbox.py`
côté hôte, `sandbox/detonate.sh` dans le conteneur) :

1. Un conteneur **sink** démarre : c'est le seul hôte joignable. Il répond à
   toutes les requêtes DNS et accepte le TCP sur les ports 80, 443, 4444, 8080
   et 8443, sans jamais rien transmettre vers l'extérieur.
2. Le conteneur de détonation démarre : rootless, système de fichiers en
   lecture seule, aucune capacité, réseau `--internal`. L'archive arrive par
   l'entrée standard (aucun dossier de l'hôte n'est partagé).
3. Il crée un faux dossier personnel rempli de **faux secrets** (`~/.aws`,
   `~/.ssh`, `~/.npmrc`…) contenant un **canary** unique pour ce run.
4. Il lit un fichier « sentinelle » : si Falco ne signale pas cette lecture, le
   capteur est aveugle et le résultat sera `unavailable`.
5. Il exécute le code d'installation :
   - npm : `preinstall`, `install`, `postinstall`, puis `require()` du paquet ;
   - PyPI : `pip install` (sdist ou wheel), puis import des modules.
6. Deux témoins indépendants sont lus :
   - **Falco** : faux secret lu, persistance, programme largué exécuté, connexion sortante ;
   - **le sink** : le canary est-il arrivé sur le réseau, même encodé (hex,
     base64) ou découpé en plusieurs requêtes DNS ?
7. Si une phase d'installation a échoué, dépassé son délai ou n'a rien renvoyé,
   la détonation est **incomplète** : ne rien voir ne prouve rien, la
   quarantaine pour code d'installation reste active.

Une seule détonation tourne à la fois (le sink a une adresse fixe).

---

## 7. Corpus et mesures

```bash
# Corpus statique (10 malveillants + 10 sains, échantillons de GuardDog)
python3 -m airlock.corpus.run_eval
# -> airlock/corpus/corpus_eval_report.json

# Corpus de détonation (6 + 6, fait maison, inerte) : Falco doit tourner
sudo sandbox/falco.sh start
python3 -m airlock.corpus.run_detonation
# -> airlock/corpus/detonation_eval_report.json
```

Le rapport de détonation classe chaque échantillon en `malicious`, `benign` ou
`unavailable` (capteur aveugle ou installation incomplète). Les `unavailable`
sont **exclus** des métriques et un avertissement s'affiche : un tel rapport
n'est pas une mesure valide.

---

## 8. Tests

```bash
# Tests hors ligne (par défaut)
python3 -m pytest airlock/tests -c airlock/pytest.ini -p no:cacheprovider

# Uniquement les tests qui appellent les vrais registres
python3 -m pytest airlock/tests -c airlock/pytest.ini -m network

# Tout
python3 -m pytest airlock/tests -c airlock/pytest.ini -m ""
```

---

## 9. Problèmes fréquents

| Symptôme | Cause | Solution |
|---|---|---|
| `trivy ... unavailable: The 'trivy' binary is not in PATH` | Trivy absent | l'installer (§2.2) |
| `Trivy timed out after 120s` | premier lancement, la base se télécharge | `--trivy-timeout 300` |
| `detonation ... image localhost/airlock-sandbox:1 is missing` | image non construite | `podman build -t localhost/airlock-sandbox:1 sandbox/` |
| `Falco did not see the sentinel` | Falco arrêté | `sudo sandbox/falco.sh start` |
| `install incomplete: install (exit 1)` | le paquet ne s'installe pas hors ligne (dépendance de build manquante…) | normal pour certains paquets : le verdict reste prudent |
| `Error trying to connect to socket` pendant GuardDog | une règle « metadata » de GuardDog n'a pas pu joindre un service tiers | sans effet sur les règles de code source |
| `invalid policy file` | JSON invalide ou clé inconnue | corriger le fichier (§5) |
| `Ingestion FAILED: npm package not found` | nom ou version faux | vérifier sur le registre |

---

## 10. Lire le code

Le code est découpé en **une fonction courte par étape**, au même endroit à
chaque fois. Ordre de lecture conseillé :

### 10.1 `airlock/pipeline.py` : le chef d'orchestre (commencer ici)

- `run_pipeline()` se lit de haut en bas comme le schéma du §1 : ingestion,
  SBOM, Trivy, GuardDog, deps.dev, détonation, verdict, écriture du rapport.
- Sous elle, une fonction par étape : `_ingest`, `_run_sbom`, `_run_trivy`,
  `_run_guarddog`, `_run_depsdev`, `_run_detonation`. Chacune affiche ce
  qu'elle fait et renvoie un résultat.
- `main()` lit les options de la ligne de commande et transforme le verdict en
  code de sortie.

### 10.2 `airlock/ingest/fetch.py` : récupérer le paquet sans l'exécuter

- `fetch_package()` est le point d'entrée ; il appelle `fetch_npm()` ou `fetch_pypi()`.
- Chacun : lit les métadonnées du registre (`_get_registry_json`), télécharge
  (`_download`, taille limitée), vérifie l'intégrité (`_check_npm_integrity` ou
  sha256), puis extrait en sécurité (`_safe_extract_tar` / `_safe_extract_zip` :
  refus des chemins `../`, des liens et des bombes d'archive).
- `fetch_local()` fait la même chose pour une archive locale.
- `FetchedPackage` regroupe tout ce qu'on sait du paquet ; sa propriété
  `install_hooks` liste le code qui s'exécuterait à l'installation.

### 10.3 `airlock/sbom/generate.py` : l'inventaire

`build_sbom()` crée un SBOM CycloneDX : le paquet, puis ses dépendances. Avec
les versions exactes fournies par deps.dev, chaque dépendance reçoit un
identifiant `purl`, ce qui permet à Trivy d'y chercher des CVE.

### 10.4 `airlock/analysis/` : les trois analyses statiques

Elles suivent toutes le même modèle : une fonction publique qui **ne lève
jamais d'exception** et renvoie un résultat avec `scan_failed=True` en cas de
panne.

| Fichier | Fonction | Ce qu'elle fait |
|---|---|---|
| `trivy_scan.py` | `scan_sbom()` | lance le binaire `trivy` sur le SBOM et lit son JSON |
| `guarddog_scan.py` | `scan_local()` | appelle GuardDog sur les fichiers extraits ; classe les règles en `threat` / `capability` / `metadata` |
| `depsdev.py` | `query_package()` | interroge l'API deps.dev ; les petites fonctions `_scorecard`, `_dependent_count`, `_project_key` font chacune un appel |

### 10.5 `airlock/detonation/sandbox.py` : l'exécution surveillée

- `detonate()` est le point d'entrée (verrou : une détonation à la fois).
- `_detonate()` : démarre le sink, lance le conteneur, récupère les événements
  Falco et le journal du sink, puis nettoie toujours les conteneurs.
- `analyse_sink_log()` : cherche le canary dans le trafic capté.
- `incomplete_install_phases()` : repère les phases d'installation qui n'ont pas abouti.
- Le script qui tourne **dans** le conteneur est `sandbox/detonate.sh`.

### 10.6 `airlock/verdict/aggregate.py` : la décision

- `aggregate()` appelle une fonction `_judge_<étape>()` par étape. Chacune
  renvoie un `Judgement` : la ligne d'état de l'étape, le verdict qu'elle
  propose et ses raisons.
- `aggregate()` garde ensuite **le pire** verdict (`_worst`) et toutes les raisons.
- Pour comprendre une décision, il suffit de lire la fonction `_judge_` de
  l'étape concernée (une vingtaine de lignes chacune).

### 10.7 Les tests, qui servent aussi d'exemples

| Fichier | Ce qu'il montre |
|---|---|
| `tests/test_pipeline.py` | règles du verdict, avec de faux résultats d'étapes |
| `tests/test_local.py` | ingestion locale et sécurité de l'extraction |
| `tests/test_detonation.py` | sink, capteur aveugle, phases incomplètes, verdict de détonation |

Pour comprendre une règle : chercher le test qui porte son nom
(ex. `test_verdict_never_downgrades`), puis la fonction `_judge_` correspondante.

### 10.8 Pour aller plus loin

Chaque choix important est expliqué dans un ADR (`adr/`). Pour le « pourquoi »
d'une règle, partir de l'ADR cité dans le commentaire du code.
