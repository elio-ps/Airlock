# AI usage log and declaration

The school's AI charter puts this project at level 2–3: generative AI may be
used, but its use must be **declared and documented**, and the student remains
responsible for the entire work and must be able to explain and justify any part
of it. This file is that record.

## Tool

- **Claude (Anthropic), via Claude Code** — code assistant run from the terminal
  in the project repository.

## What AI was used for, by area

| Area | AI contribution | Student responsibility |
|---|---|---|
| Pipeline code (ingestion → verdict) | drafting modules, refactors, bug fixes | review, run, understand each stage |
| Detonation sandbox + Falco rules | design proposal, harness and rules draft | validate the isolation model, run with Falco |
| Detonation corpus (incl. home-made sample) | writing the simulated, inert fixtures | confirm they are safe and explain the techniques |
| Tests | writing unit and integration tests | check they test the right behaviour |
| Documentation (README, ADRs, this dossier) | drafting from the actual code | read, correct, own the content |
| Measurements (e.g. false positives on 18 packages) | running and tabulating | interpret and defend the numbers |

Decisions that shaped the project were taken by the student and recorded as ADRs
in [`../adr/`](../adr/) — for example: static signals only quarantine while BLOCK
requires dynamic proof (ADR-0007), and the two-witness detonation model
(ADR-0009). The "why" in each ADR is what the oral defence will draw on.

## How correctness was checked (not just generated)

- the full test suite is green on a clean checkout (`pytest airlock/tests`);
- the analysis stages were run against **real** registries and `api.deps.dev`,
  which revealed and fixed several bugs that passed the mocked tests;
- the home-made sample was verified to raise **no** GuardDog static signature yet
  to be caught at detonation;
- the false-positive rate of the static rule was **measured** on 18 popular
  packages, which is what motivated ADR-0007.

## Data protection

No sensitive or personal data was sent to any AI tool. The detonation corpus
uses only decoy data with per-run canary tokens, and all network targets are the
reserved `.invalid` domain.

## Declaration (to reproduce and complete on the submitted copy)

The charter's official formula (French, reproduced verbatim as required):

> « Je déclare avoir utilisé l'outil d'IA générative **Claude (Claude Code)**
> pour **m'assister dans la conception, l'implémentation, les tests et la
> documentation du projet Airlock**. Cet usage a concerné **les étapes listées
> dans le tableau ci-dessus**. J'ai vérifié, corrigé et validé les éléments
> retenus et demeure responsable de l'intégralité du travail remis. »

English rendering, for readers of this file: *I declare that I used the
generative AI tool Claude (Claude Code) to assist with the design,
implementation, testing and documentation of the Airlock project, for the steps
listed in the table above. I have checked, corrected and validated what was kept,
and I remain responsible for the entirety of the submitted work.*

---

Traceability of the work itself is in the Git history: each step is a separate,
described commit.
