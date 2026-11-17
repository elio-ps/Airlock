# Justification des choix — Airlock

Ce document explique **pourquoi** Airlock est construit comme il l'est, depuis le
début du projet : le pipeline, chaque étape d'analyse, les règles de verdict, le
bac à sable Podman, le capteur Falco et ses règles, les corpus de mesure. Il sert
de support à la soutenance : chaque choix est relié au code qui l'implémente et,
quand il existe, à l'ADR qui le tranche (`adr/`).

Les ADR restent la source de vérité décision par décision (contexte, options,
conséquences). Ce document les relie entre elles et descend dans le détail que
les ADR ne donnent pas : chaque option de conteneur, chaque règle Falco, chaque
seuil.

Sommaire :

1. Le problème et le principe directeur
2. Architecture générale : un pipeline d'étapes indépendantes
3. Ingestion : ne jamais exécuter, ne jamais faire confiance
4. SBOM, Trivy et deps.dev : les signaux statiques « d'inventaire »
5. GuardDog : les motifs dans le code, et pourquoi ils ne bloquent pas
6. Le verdict : des règles lisibles, monotones, réglables
7. La détonation : le bac à sable Podman
8. Le capteur Falco et ses règles
9. Revue du 17/11/2026 : défauts corrigés et améliorations
10. Corpus et mesures
11. Limites assumées et suite du projet

---

## 1. Le problème et le principe directeur

Une attaque de la chaîne d'approvisionnement ne vise pas l'application : elle vise
**la machine du développeur ou de la CI**, au moment de l'installation. Un
`postinstall` npm ou un `setup.py` PyPI s'exécute avant la moindre ligne du
projet, avec les droits de l'utilisateur, à côté de ses jetons npm, de ses clés
SSH et de ses identifiants cloud.

Airlock se place entre le registre et la machine, et répond à une seule
question : *ce paquet peut-il entrer ?* Trois réponses possibles :

| Verdict | Sens | Code de sortie |
|---|---|---|
| ALLOW | rien de suspect sur les étapes qui ont tourné | 0 |
| QUARANTINE | un humain doit regarder avant usage | 2 |
| BLOCK | comportement malveillant **observé** | 3 |
| (erreur) | le paquet n'a pas pu être analysé | 1 |

Les codes de sortie permettent à un job CI ou à un script shell d'agir sur le
verdict sans lire de JSON. `argparse` sort par défaut en code 2 sur une erreur
d'usage, ce qui se confondrait avec QUARANTINE : `pipeline.py` le redéfinit pour
sortir en 1.

**Principe directeur, qui explique la plupart des choix suivants :**

> Un signal absent n'est jamais un signal propre. Un signal statique est une
> raison de regarder, pas une preuve. Seul un comportement observé peut bloquer.

---

## 2. Architecture générale : un pipeline d'étapes indépendantes

```
ingestion -> SBOM -> Trivy -> GuardDog -> deps.dev -> détonation -> verdict
```

### 2.1 Pourquoi Python (ADR-0001)

GuardDog, la brique d'analyse comportementale statique, est écrit en Python ; la
bibliothèque CycloneDX et `requests` aussi. Un seul langage limite le coût
d'intégration pour une équipe de deux. Go reste envisageable pour le futur proxy
sur le chemin critique (performances), via un nouvel ADR.

### 2.2 Pourquoi des étapes indépendantes

Chaque étape (`_run_sbom`, `_run_trivy`, …) **ne lève jamais d'exception** sur
une panne de scanner : elle renvoie un résultat marqué `scan_failed`. Une panne
réseau de deps.dev ne doit pas empêcher GuardDog ou la détonation de tourner.

Chaque étape produit un statut parmi quatre, distincts à dessein :

| Statut | Sens |
|---|---|
| `ok` | l'étape a tourné et n'a rien trouvé |
| `suspect` | l'étape a tourné et a trouvé quelque chose |
| `unavailable` | l'étape n'a pas pu tourner, ou n'a pas pu tout voir |
| `skipped` | l'étape a été écartée volontairement (`--skip`, paquet local) |

La distinction `unavailable` / `skipped` évite qu'un `--skip trivy` volontaire
soit compté comme une panne par la politique fail-closed (ADR-0005).

### 2.3 Pourquoi cet ordre

- L'**ingestion** vient d'abord : toutes les étapes analysent *les mêmes octets*,
  ceux qui ont été téléchargés et dont l'intégrité a été vérifiée. GuardDog
  analyse le répertoire extrait (`scan_local`) au lieu de retélécharger le
  paquet, car un second téléchargement pourrait renvoyer autre chose.
- Le **SBOM** précède **Trivy** parce que Trivy scanne le SBOM : sans SBOM,
  Trivy n'a rien à analyser et n'est pas lancé.
- La **détonation** est la dernière étape d'analyse : c'est la plus coûteuse,
  et la seule qui exécute le code.
- Le **verdict** agrège tout, et peut donc expliquer chaque décision.

### 2.4 Traçabilité

Chaque exécution écrit `airlock_runs/<écosystème>-<nom>-<version>/report.json` :
verdict, raisons, statut de chaque étape, détails bruts. C'est la piste d'audit
(voir `docs/day2-operations.md`). L'archive et l'extraction sont supprimées à la
fin (`TemporaryDirectory`) : on ne garde pas de code non fiable sur disque.

---

## 3. Ingestion : ne jamais exécuter, ne jamais faire confiance

Fichier : `airlock/ingest/fetch.py`. Tout ce qui vient du registre est une
**entrée non fiable** : le nom, la version, le nom de fichier, le contenu de
l'archive, le `package.json`.

| Choix | Justification |
|---|---|
| Aucune exécution de code | l'ingestion télécharge et extrait, c'est tout ; l'exécution est confinée à la détonation |
| Vérification d'intégrité (sha512 `integrity` npm, sinon `shasum` sha1 ; sha256 PyPI) | prouve que l'archive n'a pas été altérée en transit. Ce n'est **pas** une preuve d'innocuité : un paquet malveillant publié a une empreinte valide |
| Refus d'une archive npm sans aucune empreinte | le registre en publie toujours au moins une : son absence est une anomalie, on refuse plutôt que d'accepter une archive invérifiable (ajouté à la revue, §9) |
| sdist préféré à la wheel côté PyPI | le sdist contient le `setup.py`, là où se cachent les charges utiles d'installation ; la wheel est un repli. Les formats hérités (`.egg`, `.exe`, `.tar.bz2`) sont écartés plutôt que de faire échouer l'ingestion (§9) |
| Extraction : refus du path traversal | un membre `../../etc/cron.d/x` est refusé ; la comparaison se fait sur des chemins résolus (`is_relative_to`), pas sur des préfixes de chaînes, ce qui bloque aussi `../w-evil` à côté de `w` (test dédié) |
| Extraction : liens symboliques, liens physiques et périphériques ignorés | c'est par un lien qu'une archive s'échappe du répertoire après un premier membre anodin ; on n'extrait que fichiers et répertoires, avec en plus le filtre `data` de `tarfile` |
| Limites anti-bombe (200 Mo téléchargés, 1 Gio extrait, 50 000 membres) | une archive de quelques Ko peut se décompresser en dizaines de Go |
| `safe_slug` sur tout nom venant du registre | le nom et la version servent à construire des chemins (`airlock_runs/...`) ; `../` ou `/` y sont neutralisés |
| Délai réseau (20 s) | un registre lent ne doit pas figer le pipeline |
| User-Agent explicite | bonne pratique vis-à-vis des registres, requêtes identifiables |

### Détection du « code d'installation »

`FetchedPackage.install_hooks` liste le code qui s'exécutera à l'installation,
avant que le développeur ne lance quoi que ce soit :

- npm : scripts `preinstall`, `install`, `postinstall`, et le `node-gyp rebuild`
  implicite quand un `binding.gyp` est présent sans script `install` (npm le
  lance tout seul) ;
- PyPI : un sdist avec `setup.py`, **ou** depuis la revue un sdist avec seulement
  un `pyproject.toml`, car le construire exécute son backend de build, qui peut
  être livré dans le paquet (`backend-path`) ou appeler des hooks de build
  (`hatch_build.py`, plugins setuptools). Une wheel n'est jamais construite :
  son code ne s'exécute qu'à l'import.

Cette liste alimente la règle ADR-0008 (§6.3).

### Paquets locaux (`--local`)

Pour analyser un paquet non publié (`npm pack --ignore-scripts`). Mêmes
protections ; pas d'empreinte registre à comparer, le sha256 est enregistré pour
la traçabilité. deps.dev est automatiquement écarté (`skipped`) : il n'y a pas de
registre à interroger.

---

## 4. SBOM, Trivy et deps.dev : les signaux statiques « d'inventaire »

### 4.1 SBOM CycloneDX (`airlock/sbom/generate.py`)

| Choix | Justification |
|---|---|
| CycloneDX 1.5 JSON | standard reconnu (OWASP), lu par Trivy, exigé dans les démarches SLSA / supply chain |
| Composant racine uniquement dans `metadata.component` | conforme à la spec ; le dupliquer dans `components` faisait réécrire son `bom-ref` par le sérialiseur |
| Graphe de dépendances résolu via deps.dev | sans version exacte, pas de *purl*, et **Trivy ignore un composant sans purl**. deps.dev résout le graphe (transitif compris) sans rien installer |
| Repli : dépendances déclarées seulement | sans deps.dev, on garde un inventaire (les plages déclarées), utile à un humain mais invisible pour Trivy |
| Licence ajoutée seulement si l'expression SPDX est valide | une licence libre non SPDX ne doit pas faire échouer la génération |
| Toute exception du SBOM attrapée | les métadonnées sont non fiables : un `package.json` piégé ne doit pas faire tomber tout le pipeline ; l'étape devient `unavailable` |

### 4.2 Trivy (`airlock/analysis/trivy_scan.py`)

| Choix | Justification |
|---|---|
| `trivy sbom` sur le SBOM plutôt que `trivy fs` sur l'arbre extrait | le SBOM porte le graphe **résolu** (transitif), que l'arbre d'un paquet non installé ne contient pas |
| Binaire installé à version fixe (v0.76.1) via le script du tag (ADR-0006) | `curl … main/install.sh | sudo sh` exécuterait un script mouvant en root : exactement le risque qu'Airlock combat |
| HIGH/CRITICAL → QUARANTINE | une CVE grave est une raison de regarder, pas une preuve de malveillance |
| Délai configurable (`--trivy-timeout`) | le premier scan télécharge la base (plusieurs centaines de Mo) |
| Couverture partielle → `unavailable` (ADR-0011, ajouté à la revue) | si des dépendances n'ont pas de version résolue, Trivy ne les voit pas : dire « 0 CVE, ok » serait mentir. Le statut devient `unavailable`, avec le nombre de dépendances non scannées ; la politique fail-open/fail-closed décide |

### 4.3 deps.dev (`airlock/analysis/depsdev.py`)

Signal de **réputation / hygiène**, complémentaire : Trivy dit « vulnérable »,
GuardDog dit « ressemble à un malware », deps.dev dit « projet mal tenu ou
inconnu ».

| Choix | Justification |
|---|---|
| Score OpenSSF Scorecard < 3/10 → QUARANTINE | un projet sans revue de code, sans protection de branche, sans maintenance est une cible facile de prise de contrôle |
| … seulement si < 50 dépendants directs | un paquet très utilisé avec un mauvais score est un signal à remonter, pas à bloquer à l'aveugle (sinon on met en quarantaine une partie de l'écosystème) |
| Nombre de dépendants inconnu → traité comme « peu utilisé », mais affiché « inconnu » | prudence (on ne relâche pas une règle parce qu'une API alpha n'a pas répondu), sans prétendre « 0 dépendant » (corrigé à la revue) |
| Paquet inconnu (404) → QUARANTINE, distinct d'une panne | un paquet absent de deps.dev est souvent tout récent : c'est le profil type du typosquatting. Une erreur réseau, elle, donne `unavailable` (ADR-0005) |
| Segments d'URL encodés (`quote(..., safe="")`) | les noms npm à portée (`@scope/nom`) et les clés de projet (`github.com/x/y`) contiennent des `/` ; sans encodage, l'API renvoyait silencieusement rien (bug trouvé en conditions réelles, test réseau dédié) |
| Endpoint `v3alpha` pour les dépendants seulement | c'est le seul qui expose ce compte ; son échec n'invalide pas l'étape |

---

## 5. GuardDog : les motifs dans le code, et pourquoi ils ne bloquent pas

Fichier : `airlock/analysis/guarddog_scan.py`.

### 5.1 Bibliothèque plutôt que CLI (ADR-0002)

Résultats structurés (nom de règle, emplacement) sans analyser du texte, mode
`scan_local` testable. Contrepartie : couplage à une API interne, d'où
l'épinglage `guarddog>=3.2,<4` et la consigne Day 2 de relancer les corpus à
chaque mise à jour.

### 5.2 `threat-*` contre `capability-*`

- `capability-*` décrit ce que le code **peut** faire (réseau, fichiers,
  processus) : presque tout code légitime en a. Ignoré pour le verdict.
- `threat-*` décrit un comportement documenté comme malveillant (exfiltration,
  exécution de code obfusqué, persistance).

### 5.3 L'histoire du choix : ADR-0003 → ADR-0007

Au départ (ADR-0003), une règle `threat-*` donnait BLOCK : le corpus statique
(échantillons de GuardDog) affichait 10/10 malveillants détectés, 0 faux positif.

La mesure sur de **vrais paquets populaires** a montré l'inverse : des tests,
des chaînes d'exemple, du chargement dynamique légitime déclenchent ces règles.
Remesuré à la revue avec un script commité (`airlock/corpus/run_popular.py`) :
**7 paquets populaires sur 18** déclenchent au moins une règle `threat-*`
(requests, flask, django, pyyaml, pytest, pillow, webpack).

Décision (ADR-0007) : `threat-*` → **QUARANTINE**. BLOCK est réservé à la preuve
dynamique. `Policy.block_on_any_threat_rule` permet à une entreprise de revenir
à l'ancien comportement si elle l'assume.

Conséquence voulue : c'est cohérent avec l'objectif du sujet — détecter par
l'analyse dynamique, **sans signature**. Le malware maison m06 ne déclenche
aucune règle statique (vérifié) et est pourtant bloqué (§10).

---

## 6. Le verdict : des règles lisibles, monotones, réglables

Fichier : `airlock/verdict/aggregate.py`.

### 6.1 Règles explicites plutôt qu'un score (ADR-0004)

Un score pondéré (« 73/100 ») ne s'explique pas à un humain et se règle mal. Ici,
chaque étape est jugée par une fonction courte (`_judge_trivy`,
`_judge_guarddog`, …) qui renvoie un statut, un verdict et une **raison en
clair**. Le rapport liste toutes les raisons.

| Signal | Déclencheur | Verdict |
|---|---|---|
| Détonation | comportement Critical (lecture de leurre, persistance, dropper, fuite du canary) | **BLOCK** |
| Détonation | comportement Warning (connexion sortante, outil réseau) | QUARANTINE |
| GuardDog | ≥ 1 règle `threat-*` | QUARANTINE |
| Trivy | CVE HIGH/CRITICAL | QUARANTINE |
| deps.dev | Scorecard < 3 sur un paquet peu utilisé, ou paquet inconnu | QUARANTINE |
| Code d'installation | non détoné proprement | QUARANTINE |
| Politique fail-closed | une étape `unavailable` | QUARANTINE |
| — | rien | ALLOW |

Contrepartie assumée : deux signaux faibles ne s'additionnent pas.

### 6.2 Monotonie

Le verdict ne peut que **s'aggraver** d'une étape à l'autre (`_worst`). Une bonne
note deps.dev n'annule jamais une QUARANTINE de GuardDog ; une détonation propre
n'annule pas un motif statique (test `test_clean_detonation_never_improves_a_static_quarantine`).
Raison : un paquet qui sait détecter le bac à sable et rester sage ne doit pas
« blanchir » un signal statique.

### 6.3 Code d'installation non détoné → QUARANTINE (ADR-0008)

Personne n'a regardé ce code s'exécuter, donc personne ne s'en porte garant.
Cette règle remplace l'idée « `capability-*` dans un hook », qui ratait les hooks
en ligne (`"postinstall": "curl … | sh"`) puisqu'ils ne sont dans aucun fichier
source scanné. « Détoné proprement » signifie : capteur vivant **et** toutes les
phases d'installation terminées avec le code 0 (`_was_fully_detonated`).

### 6.4 Fail-open ou fail-closed (ADR-0005)

Quand une étape est `unavailable`, laisser passer (fail-open) ou attendre
(fail-closed) est un choix de sécurité : `Policy.fail_closed`, faux par défaut
pour le développement, à activer en production. Une étape `skipped` ne compte
jamais comme une panne.

### 6.5 Politique dans un fichier JSON

Tous les seuils vivent dans `Policy` et se chargent par `--policy fichier.json`.
Une clé inconnue ou mal orthographiée est **refusée** (sinon une faute de frappe
désactiverait une règle en silence). Depuis la revue, le **type** de chaque
valeur est aussi vérifié : une chaîne `"HIGH"` à la place de `["HIGH"]`
« fonctionnait » par comparaison de sous-chaînes, une dérive silencieuse.

---

## 7. La détonation : le bac à sable Podman

Fichiers : `airlock/detonation/sandbox.py` (hôte), `sandbox/detonate.sh`
(conteneur), `sandbox/sink.py` (faux réseau), `sandbox/Containerfile`.
Décision d'ensemble : ADR-0009.

### 7.1 Pourquoi détoner

L'analyse statique voit le texte, pas le comportement : obfuscation, données
cachées dans un JSON, code téléchargé à l'exécution lui échappent (c'est
exactement ce que fait m06). Exécuter le paquet dans un environnement jetable et
**observer** ce qu'il fait est la seule preuve qui permette de bloquer.

### 7.2 Pourquoi Podman rootless (et pas Docker, ni une VM tout de suite)

| Option | Pour | Contre | Choix |
|---|---|---|---|
| Exécuter sur l'hôte sous Falco | simple | le malware tourne vraiment chez nous | rejeté |
| **Conteneur Podman rootless** | aucun démon root ; l'UID 0 du conteneur n'est pas root sur l'hôte ; démarrage en ~1 s ; natif sur Fedora | partage le noyau de l'hôte | **retenu pour l'échelon 1** |
| Docker | très répandu | démon root : une évasion du conteneur atterrit en root | rejeté |
| microVM par détonation | noyau séparé | plus lourd à mettre en place | prévu pour le rendu final |

Le point décisif est **rootless** : même une évasion du conteneur arrive avec
les droits d'un utilisateur non privilégié de l'hôte, pas root.

### 7.3 Chaque option du conteneur de détonation, justifiée

| Option | Pourquoi |
|---|---|
| `--read-only` | le système de fichiers de l'image est immuable : le paquet ne peut pas altérer les outils (node, python, le harnais) |
| `--tmpfs /home/dev`, `/tmp`, `/work` (`rw,exec`) | seuls endroits inscriptibles, en mémoire, détruits avec le conteneur. `exec` est **voulu** : un dropper doit pouvoir s'exécuter pour que Falco le voie |
| `--cap-drop=ALL` | aucune capacité Linux : pas de raw sockets, pas de montage, pas de changement d'UID |
| `--security-opt=no-new-privileges` | un binaire setuid ne peut pas rendre des droits |
| `--user 1500:1500` | utilisateur non root dans le conteneur, comme sur un vrai poste de développeur |
| `--pids-limit=256` | neutralise une fork bomb |
| `--memory=1g`, `--cpus=2` | un mineur ou une boucle infinie ne paralyse pas l'hôte |
| `--network airlock-det` (`--internal`) | réseau **sans route vers l'extérieur**, quoi que fasse le code |
| `--disable-dns` sur ce réseau, `--dns 10.253.66.2` | sans résolveur intégré, c'est le sink qui répond à **toutes** les requêtes DNS ; sinon `aardvark-dns` de Podman l'aurait masqué |
| Archive passée sur **stdin** (`podman run -i`) | aucun chemin de l'hôte n'est monté dans le conteneur : rien à lire, rien à écrire côté hôte |
| Pas de `--rm`, suppression en `finally` | l'ID du conteneur est lu après l'exécution (pour filtrer les événements Falco), puis le conteneur est toujours supprimé |
| Nom de wheel vérifié par regex | ce nom vient du registre et atteint un shell (`detonate.sh`) : on refuse tout caractère dangereux (test `x$(id).whl`) |
| Délai global 120 s, 40 s par phase, `timeout -k 3` | un paquet qui attend indéfiniment ne bloque pas Airlock ; un dépassement est marqué et rend la détonation « incomplète » |
| Une détonation à la fois (verrou fichier) | le sink a une IP fixe sur le réseau. Le verrou est dans `$XDG_RUNTIME_DIR` et ouvert sans suivre les liens symboliques (§9) |

### 7.4 L'image (`sandbox/Containerfile`)

| Choix | Justification |
|---|---|
| Base `node:22-bookworm-slim` **épinglée par digest** | reproductible ; un tag peut changer sous nos pieds |
| `python3`, `pip`, `curl`, `wget`, `git`, `nc`… installés | un malware s'attend à les trouver ; leur usage est justement ce qu'on observe. Une image trop vide le ferait échouer sans rien révéler |
| Backends de build PEP 517 pré-installés et épinglés (hatchling, flit, poetry-core…) | l'installation est hors ligne : sans eux, un sdist moderne échouerait **avant** d'exécuter son code, et la détonation ne prouverait rien |
| Utilisateur `dev` (UID 1500) | ressemble à un poste réel |
| Sentinelle `/opt/airlock/sentinel` en lecture seule | preuve de vie du capteur (§8.3) |

### 7.5 Le déroulé dans le conteneur (`detonate.sh`)

1. **Leurres** : le harnais crée un faux `$HOME` de développeur — `~/.aws/credentials`,
   `~/.ssh/id_rsa`, `~/.npmrc`, `~/.pypirc`, `~/.git-credentials`, `~/.netrc`,
   `~/.config/gh/hosts.yml`, `~/.docker/config.json`, `~/.kube/config`. Ce sont
   les cibles des voleurs réels (jetons npm et GitHub, clés cloud, SSH). Chacun
   contient un **canary** unique par exécution.
2. **Variables d'environnement leurres** : `AWS_SECRET_ACCESS_KEY`, `NPM_TOKEN`,
   `GITHUB_TOKEN`, avec le canary. Un vol de secret depuis l'environnement ne
   produit aucun événement fichier : seul le sink peut le voir.
3. `NPM_CONFIG_USERCONFIG=/dev/null`, `PIP_CONFIG_FILE=/dev/null` : npm et pip
   **eux-mêmes** ne doivent pas lire les leurres, sinon chaque détonation
   déclencherait une alerte (faux positif systématique).
4. Le canary est retiré de l'environnement du harnais (`unset AIRLOCK_CANARY`).
5. **Sentinelle** lue, puis marqueur `[airlock] detonation starts` : tout ce que
   Falco rapporte avant appartient au harnais et est ignoré.
6. **npm** : `preinstall`, `install`, `postinstall` lancés directement par
   `npm run --if-present`, dans l'ordre de npm. Pourquoi pas `npm install` ? Il
   voudrait d'abord résoudre les dépendances, donc joindre un registre ; l'échec
   de résolution masquerait complètement le hook. Puis une phase `require`
   (charger le module) pour les charges utiles cachées dans `index.js`.
7. **PyPI** : `pip install --no-deps --no-index --no-build-isolation --target`.
   `--no-index`/`--no-deps` : aucun accès réseau attendu ; `--no-build-isolation` :
   utiliser les backends pré-installés (sinon pip voudrait les télécharger).
   Puis import de chaque module installé, pour les charges utiles à l'import.
8. **Marqueurs de fin de phase** `[airlock] phase X exit=N`. Le paquet écrit sur
   la même sortie et pourrait imprimer un faux `exit=0` : une phase n'est donc
   complète que si **tous** ses marqueurs disent 0. Une fausse ligne peut
   aggraver le résultat, jamais l'améliorer (test `test_forged_success_line_cannot_hide_a_failure`).
   La phase `require`/`import` n'est pas exigée : une bibliothèque peut
   légitimement ne pas se charger sans ses dépendances.
9. `sleep 3` final : laisser le temps aux processus lancés en arrière-plan.

### 7.6 Le sink : le seul hôte joignable

Un malware qui ne joint rien ne fait souvent rien. Le sink (conteneur séparé,
`10.253.66.2`) répond à **toute** requête DNS avec sa propre adresse et accepte
TCP sur 53, 80, 443, 4444, 8080 et 8443 : le code croit avoir atteint Internet et
passe à l'étape suivante. Rien n'est relayé. Chaque échange est écrit en JSON.

Options du sink : `--read-only`, `--cap-drop=ALL` puis seulement
`NET_BIND_SERVICE` (ports < 1024), `no-new-privileges`, 64 PID, 256 Mo. Il tourne
en UID 0 *dans* un conteneur rootless, c'est-à-dire l'utilisateur courant sur
l'hôte, pas root.

Côté hôte, la fuite est prouvée quand le **canary** apparaît dans ce que le sink
a reçu, sous plusieurs formes : en clair, en hexadécimal, en base64 (et base64url),
compressé gzip/zlib/deflate (ajouté à la revue), et **réassemblé à travers
plusieurs requêtes DNS** — par domaine de base, en prenant soit le premier label
de chaque requête (technique de m06), soit tous les labels à gauche du domaine
(plusieurs morceaux par requête, ajouté à la revue). Le canary étant aléatoire à
chaque exécution, élargir la recherche ne peut pas créer de faux positif : cela
ne peut qu'en trouver plus.

### 7.7 Deux témoins indépendants

| Témoin | Voit | Ne voit pas |
|---|---|---|
| Falco (noyau) | lecture des leurres, persistance, dropper, connexions | le contenu envoyé ; un secret lu dans l'environnement |
| Sink (réseau) | le contenu envoyé, donc la fuite effective du canary | ce qui ne sort pas (persistance, dropper) |

Ils tombent en panne indépendamment : quand Falco est arrêté, le sink attrape
encore toute exfiltration (vérifié : m01, m02, m05, m06 sont bloqués sans Falco).
Une preuve du sink suffit à bloquer même si le capteur est aveugle.

---

## 8. Le capteur Falco et ses règles

Fichiers : `sandbox/falco.sh`, `sandbox/falco/airlock_rules.yaml`. ADR-0010.

### 8.1 Pourquoi Falco

Falco lit les appels système dans le noyau : le code du paquet ne peut ni le voir
ni le tromper depuis le conteneur, contrairement à un outil qui tournerait à
l'intérieur. Le sujet le cite explicitement (réseau + fichiers).

### 8.2 Moindre privilège (ADR-0010)

Le démarrage documenté par Falco est `--privileged` avec un module noyau.
Airlock combat la chaîne d'approvisionnement : il ne doit pas donner plus que
nécessaire à son propre capteur.

| Option de `falco.sh` | Pourquoi |
|---|---|
| `engine.kind=modern_ebpf` | sonde CO-RE embarquée : pas de module noyau à compiler ni à charger (nécessite BTF, présent sur le noyau 6.x de développement) |
| `--cap-drop=ALL` puis `BPF`, `PERFMON` | charger les programmes eBPF et lire leurs tampons |
| `SYS_RESOURCE` | lever la limite de mémoire verrouillée des maps BPF |
| `SYS_PTRACE` | lire `/proc/<pid>` des autres processus pour enrichir les événements (ligne de commande, conteneur) |
| `--pid=host`, `/proc` et `/etc` de l'hôte en **lecture seule** | voir les processus des conteneurs de détonation et résoudre leurs métadonnées |
| `seccomp=unconfined` | le profil seccomp par défaut interdit l'appel système `bpf()` |
| `label=disable` | SELinux (Fedora) empêche sinon la lecture du `/proc` de l'hôte |
| Image épinglée par digest (0.45.1) | reproductibilité, pas de mise à jour silencieuse |
| `buffered_outputs=false`, sortie fichier JSON | les événements arrivent sans délai dans `events.jsonl`, que l'hôte lit après chaque détonation |

C'est le **seul** composant root d'Airlock ; les paquets tournent toujours en
rootless.

### 8.3 La sentinelle : un capteur muet n'est jamais « propre »

Un Falco silencieux peut signifier « rien ne s'est passé » ou « Falco n'a rien
vu » : deux choses opposées pour un outil de sécurité. Chaque détonation lit donc
d'abord `/opt/airlock/sentinel`. Si Falco ne rapporte pas cette lecture
(`airlock_sentinel`), le capteur était aveugle : l'étape est `unavailable`,
jamais `ok`.

Filtrage côté hôte (`_read_falco_events`) :

- seuls les événements du conteneur analysé (par son ID) sont gardés ;
- seuls ceux **postérieurs à la sentinelle** comptent : avant, c'est le harnais
  qui écrit les leurres (ce qui déclencherait `airlock_persistence_write`) ;
- depuis la revue, « postérieur » se juge sur l'**horodatage** de l'événement et
  non sur sa position dans le fichier : Falco fusionne des tampons par CPU, et un
  événement du harnais écrit en retard ne doit pas passer pour un comportement
  du paquet (faux BLOCK).

### 8.4 Les règles, une par une

Philosophie : **des comportements, pas des signatures**. Aucune règle ne connaît
un malware particulier ; chacune décrit quelque chose qu'un installateur
légitime n'a pas de raison de faire. La priorité Falco pilote directement le
verdict (`Policy.block_on_detonation_priority`,
`Policy.quarantine_on_detonation_priority`).

| Règle | Condition | Priorité → verdict | Justification |
|---|---|---|---|
| `airlock_sentinel` | lecture de `/opt/airlock/sentinel` | INFORMATIONAL → aucun effet | preuve de vie du capteur (§8.3) |
| `airlock_decoy_secret_read` | ouverture en lecture d'un des 9 fichiers leurres | CRITICAL → BLOCK | aucun installateur n'a de raison de lire `~/.aws/credentials` ou `~/.ssh/id_rsa` ; npm et pip sont redirigés vers `/dev/null` pour ne pas les lire eux-mêmes |
| `airlock_process_environ_read` | lecture de `/proc/*/environ` | CRITICAL → BLOCK | récolte des secrets dans l'environnement d'autres processus, technique classique des voleurs |
| `airlock_persistence_write` | écriture dans `.bashrc`, `.profile`, `.bash_profile`, `.zshrc`, `authorized_keys`, `~/.config/autostart/`, `~/.config/systemd/user/` | CRITICAL → BLOCK | survivre à l'installation : s'exécuter à chaque shell ou session, ou ouvrir un accès SSH |
| `airlock_exec_from_writable_dir` | exécution d'un binaire **ou d'un script** situé dans `/tmp`, `/dev/shm` ou `$HOME` | CRITICAL → BLOCK | signature comportementale d'un dropper (second étage écrit puis lancé). Pour un script `#!/bin/sh`, le noyau exécute en réalité `/bin/sh <script>` : `proc.exepath` désigne l'interpréteur et `proc.name` le script, le chemin déposé n'apparaît qu'en premier argument ; la règle reconnaît donc aussi « interpréteur connu (par son chemin réel dans l'image, que le paquet ne peut pas renommer) + premier argument dans un répertoire inscriptible ». `/work`, où les scripts du paquet tournent légitimement, est exclu |
| `airlock_outbound_connection` | `connect` IPv4/IPv6 hors boucle locale | WARNING → QUARANTINE | des installateurs légitimes téléchargent des binaires précompilés (esbuild, sharp…) : suspect, pas une preuve. La boucle locale est exclue (échantillon b06) |
| `airlock_network_tool_exec` | lancement de `curl`, `wget`, `nc`, `socat`, `ssh`… | WARNING → QUARANTINE | courant dans les malwares, mais aussi dans des `postinstall` honnêtes |

Les priorités se règlent par politique (test
`test_detonation_priorities_are_configurable`) : une entreprise peut décider
qu'une connexion sortante bloque.

---

## 9. Revue du 17/11/2026 : défauts corrigés et améliorations

Une revue complète du projet a trouvé les défauts suivants. Chacun est corrigé
et couvert par un test de non-régression (69 tests hors ligne + 9 tests réseau,
tous verts).

| # | Défaut | Conséquence | Correction |
|---|---|---|---|
| 1 | Le serveur DNS du sink mourait sur un paquet DNS tronqué (`struct.error` non attrapée) | un paquet malveillant pouvait aveugler le sink puis exfiltrer par DNS : QUARANTINE au lieu de BLOCK | parseur strict (`MalformedQuery`), boucle qui ne peut plus s'arrêter, paquets malformés journalisés **et** analysés pour le canary (`sandbox/sink.py`) |
| 2 | Trivy affichait « ok, 0 CVE » sans avoir pu voir les dépendances (pas de purl) | toujours vrai pour `--local`, et quand deps.dev est indisponible : un signal absent lu comme propre | statut `unavailable` avec le nombre de dépendances non scannées (ADR-0011) |
| 3 | Un sdist PyPI avec seulement `pyproject.toml` n'était pas vu comme du code d'installation | backend en arbre ou hooks de build exécutés sans la quarantaine d'ADR-0008 | détection étendue, backend nommé dans la raison |
| 4 | Réassemblage DNS limité au premier label | `morceau1.morceau2.domaine` échappait au sink | seconde stratégie par domaine de base, sans doublon |
| 5 | Nombre de dépendants absent affiché comme « 0 dependents » | raison trompeuse | affiché « inconnu », règle prudente inchangée |
| 6 | Verrou ouvert en `"w"` à un nom prévisible dans `/tmp` | un autre utilisateur local pouvait faire tronquer un fichier via un lien symbolique | `$XDG_RUNTIME_DIR`, `O_NOFOLLOW`, sans troncature |
| 7 | Fichier de politique non typé | `"HIGH"` au lieu de `["HIGH"]` changeait la règle en silence | type vérifié par clé |
| 8 | Repli PyPI sur `releases[0]` | un `.egg` ou `.tar.bz2` faisait échouer l'ingestion | sdist, sinon wheel, sinon erreur claire |
| 9 | Archive npm sans empreinte acceptée | archive invérifiable analysée sans le dire | refus explicite |
| 10 | La règle Falco du dropper ne voyait pas un **script** déposé puis exécuté (seulement un binaire) | m04 passait inaperçu dès que Falco tournait réellement : faux négatif découvert par la première mesure avec capteur actif | condition ajoutée sur l'interpréteur et son premier argument (§8.4) ; rejoué : m04 bloqué |

Améliorations sans risque de régression :

- événements Falco ordonnés par horodatage (§8.3) ;
- canary recherché aussi dans les corps compressés (gzip, zlib, deflate), avec
  une limite de 1 Mo décompressé (c'est une donnée de l'attaquant) ;
- sink en écoute TCP sur le port 53 (DNS sur TCP) ;
- mesure des faux positifs sur 18 paquets populaires transformée en script
  commité avec son rapport (`airlock/corpus/run_popular.py`,
  `popular_eval_report.json`) : 7/18, ADR-0007 mis à jour.

Vérification de bout en bout : image du bac à sable reconstruite, puis corpus de
détonation relancé **avec Falco actif** (capteur vivant sur les 12 exécutions) :
**TP=6, FN=0, TN=6, FP=0**. C'est la première mesure valide de l'étape dynamique ;
le rapport précédent avait été produit avec un capteur aveugle. Elle a d'abord
donné TP=5 : le dropper m04 n'était pas vu (défaut 10), ce qui montre l'intérêt de
mesurer plutôt que de supposer.

Non modifié volontairement : `report.json` garde le chemin de l'archive
temporaire (information d'audit, même si le fichier n'existe plus) et
`airlock_runs/` reste relatif au répertoire courant (documenté, changer cela
casserait les habitudes et les guides).

---

## 10. Corpus et mesures

Trois jeux, trois questions différentes :

| Corpus | Contenu | Question | Résultat |
|---|---|---|---|
| Statique (`corpus/samples/`) | 10 + 10 extraits des fixtures officielles GuardDog (Apache 2.0) | notre intégration lit-elle GuardDog correctement ? | 10/10, 0 FP (attendu : ce sont les fixtures de GuardDog) |
| Populaires (`run_popular.py`) | 18 vrais paquets npm/PyPI | les règles statiques sont-elles assez fiables pour bloquer ? | non : 7/18 signalés à tort → ADR-0007 |
| Détonation (`corpus/detonation/`) | 6 malveillants + 6 sains, faits maison, inertes | l'étape dynamique distingue-t-elle les comportements ? | TP=6, FN=0, TN=6, FP=0, capteur vivant partout (17/11/2026) |

### Pourquoi reprendre les fixtures GuardDog pour le corpus statique

Provenance vérifiable (cas réels vus par des chercheurs), corpus **adversarial**
(les extraits sains ressemblent lexicalement aux malveillants), reproductible par
n'importe qui. Sa limite est assumée et écrite : il mesure l'intégration, pas la
détection dans la nature — c'est le rôle du corpus des paquets populaires.

### Pourquoi un corpus de détonation fait maison et inerte

Détoner de vrais malwares sur un poste étudiant, et les garder dans un dépôt
public, n'est pas acceptable. Chaque échantillon :

- ne fait **rien** hors du bac à sable (verrou `AIRLOCK_SANDBOX=1`, variable que
  seul le bac à sable définit) ;
- ne vise que le TLD réservé `.invalid` (RFC 2606), qui ne peut jamais résoudre ;
- ne lit que les leurres plantés par le harnais.

Chaque malveillant exerce **un chemin de détection** différent (vol
d'environnement par HTTP, lecture de `~/.npmrc`, persistance dans `.bashrc`,
dropper dans `/tmp`, exfiltration depuis `setup.py`, et m06). Chaque sain teste
un faux positif plausible (build qui écrit dans son propre dossier, lecture de sa
propre config, `setup.py` normal, connexion en boucle locale).

### m06, le malware maison exigé par le sujet

Il se fait passer pour le téléchargeur de binaires précompilés d'un module natif.
Il échappe à l'analyse statique (vérifié : aucune règle `threat-*`) parce que :
les fichiers à voler sont des **données** dans un JSON de « miroirs », la lecture
est enrobée dans une recherche de cache plausible, et l'exfiltration est déguisée
en sondage de disponibilité des miroirs (une requête DNS par morceau hexadécimal,
pas de corps HTTP, pas d'`exec`). Il est attrapé uniquement à la détonation : par
Falco (lecture des leurres) et par le sink, qui réassemble le canary à travers
les requêtes DNS. Vérifié en exécution réelle.

### Pourquoi le rapport de détonation exclut les cas « unavailable »

Un échantillon détoné avec un capteur aveugle ou une installation interrompue
n'est ni un vrai ni un faux négatif : il n'a pas été jugé. Le compter comme
« benign » gonflerait artificiellement les vrais négatifs. Le rapport le classe à
part et signale que la mesure n'est pas valide (`sensor_alive_for_all`).

---

## 11. Limites assumées et suite du projet

| Limite | Pourquoi on l'accepte maintenant | Suite |
|---|---|---|
| Le conteneur partage le noyau de l'hôte | rootless + capacités retirées + lecture seule réduisent fortement le risque pour l'échelon 1 | microVM par détonation (rendu final) |
| Malware conscient du bac à sable ou à retardement | empreintes connues : `AIRLOCK_SANDBOX`, UID 1500, `/work`, délai de 40 s, dépendances absentes. La monotonie (§6.2) empêche une détonation sage de blanchir un signal statique | environnement plus réaliste, observation plus longue |
| Exfiltration chiffrée (TLS) ou sur un port non écouté | le sink lit du TCP en clair ; il reste l'alerte Falco de connexion sortante (QUARANTINE) | proxy TLS dans le sink |
| Dropper exécuté depuis `/work` | les scripts du paquet y tournent légitimement | règle par ascendance de processus |
| Dépendances Python d'Airlock épinglées par plages, pas par empreinte | suffisant pour un environnement de développement | fichier de verrouillage avec hachages (échelon 2) |
| Charge de revue des QUARANTINE statiques (7/18) | prix de « seul le dynamique bloque » | étage d'arbitrage IA (rendu final) |
