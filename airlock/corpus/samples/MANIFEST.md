# Corpus de référence — provenance

Ce corpus (10 échantillons malveillants + 10 échantillons sains) n'a pas été
écrit pour ce projet : il est repris tel quel des **fixtures de tests
unitaires officielles de GuardDog** (DataDog), publiées et maintenues sur
https://github.com/DataDog/guarddog sous licence **Apache 2.0**
(voir `THIRD_PARTY_LICENSE_guarddog_Apache2.0.txt`).

## Pourquoi ce choix plutôt qu'écrire nos propres échantillons ?

1. **Provenance vérifiable et documentée** — chaque échantillon correspond à
   un cas réel observé par des chercheurs en sécurité (exfiltration réseau,
   obfuscation base64, hijacking DLL, exécution silencieuse de process...),
   pas à une supposition d'étudiant sur "à quoi ressemble un malware".
2. **Corpus adversarial, pas juste "malveillant vs. propre"** — le dossier
   `benign/` de GuardDog contient volontairement des snippets qui
   *ressemblent* aux malveillants (mêmes patterns lexicaux : IP en dur,
   appels réseau, lecture de process) mais sont sémantiquement sûrs
   (ex. adresses loopback/privées plutôt que serveur d'exfiltration). C'est
   un bien meilleur test de discrimination qu'un corpus où le sain est
   trivialement différent du malveillant.
3. **Reproductibilité** — n'importe qui peut retélécharger exactement les
   mêmes fichiers depuis le dépôt officiel et vérifier nos résultats.

## Composition

### `malicious/` (10 fichiers, doivent déclencher ≥1 règle GuardDog `threat-*`)

| # | Fichier | Comportement attendu |
|---|---------|----------------------|
| 01 | threat-network-exfiltration.py | Envoi de données vers une IP publique en dur |
| 02 | exec-base64.py | Exécution de code décodé depuis du base64 |
| 03 | threat-process-download-exec.py | Téléchargement puis exécution d'un binaire |
| 04 | threat-runtime-obfuscation-base64exec.py | Obfuscation d'exécution via base64 |
| 05 | exfiltrate-sensitive-data.py | Exfiltration de données sensibles (env, credentials) |
| 06 | dll-hijacking.py | Détournement de chargement de DLL |
| 07 | code-execution.py | Exécution de code arbitraire |
| 08 | threat-filesystem-autostart.py | Persistance via démarrage automatique |
| 09 | silent-process-execution.py | Lancement de process sans fenêtre/silencieux |
| 10 | npm-exfiltrate-sensitive-data.js | Exfiltration de données sensibles (équivalent npm) |

### `benign/` (10 fichiers, ne doivent déclencher AUCUNE règle `threat-*` — tests de non-régression / faux positifs de GuardDog lui-même)

| # | Fichier | Pourquoi c'est sûr malgré l'apparence |
|---|---------|----------------------------------------|
| 01 | threat-network-exfiltration.py | Cibles réseau en loopback/privées (RFC1918), pas d'exfiltration réelle |
| 02 | threat-process-download-exec.js | Téléchargement sans exécution, ou contexte sûr |
| 03 | threat-runtime-obfuscation-base64exec.py | Usage légitime de base64 (pas d'`exec` sur le résultat) |
| 04 | threat-filesystem-autostart.py | Manipulation de fichiers de config hors des chemins de persistance |
| 05 | threat-process-sysinfo.py | Lecture d'infos système à des fins de diagnostic classique |
| 06 | capability-network-lolbas.py | Usage d'un binaire système sans intention d'évasion |
| 07 | capability-filesystem-browser.py | Navigation fichiers sans lecture sensible |
| 08 | threat-process-cryptomining.py | Pattern de calcul intensif non lié au minage |
| 09 | threat-runtime-keylogging.py | Capture clavier dans un contexte applicatif légitime (ex. accessibilité) |
| 10 | threat-runtime-dynamic-loader.py | Chargement dynamique de module standard, pas de charge cachée |

## Limite assumée

Ce corpus teste la **détection statique de patterns** (GuardDog sourcecode
analyzer). Il ne remplace pas le corpus de détonation dynamique (Falco en
sandbox), qui est un livrable distinct du projet portant spécifiquement sur
le comportement à l'exécution plutôt que sur le code source.
