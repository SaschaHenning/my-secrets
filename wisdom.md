# Wisdom — Muster, Fallen, Gates

Was beim Arbeiten an my-secrets immer wieder zubeißt. Dauerhaft; `HANDOFF.md` ist
nur die Übergabe und enthält das hier nicht noch einmal. Entscheidungen mit
Begründung stehen in `decisions.md`.

## Quality-Gate

`gofmt -l .` (muss leer sein), `go vet ./...`, `go build ./...`,
`go test -race -count=1 ./...`, `make lint` (staticcheck ist auf dieser Maschine
oft nicht installiert und wird vom Makefile dann bewusst übersprungen — kein
Abbruch nötig). Für sicherheitsrelevante Änderungen zusätzlich `gitleaks` über
die Commit-Range prüfen (Baseline-Fixtures sind bekanntes Rauschen, s.u.).

- `-race` gehört seit dem Shared-Store-PR (#103) zum Standardlauf für Pakete mit
  Locking/Concurrency (`internal/sync`, `internal/teamaudit`), nicht nur `go test ./...`.
- Neue Logik bekommt table-driven Go-Tests, nicht nur Happy-Path.

## Autonome Läufe ohne echte Infra

Fehlt in einem autonomen Lauf externe Infrastruktur (echte GitHub-Org-Repos,
fremde GPG-Keys) — **nicht danach fragen, nicht abbrechen.** Stattdessen: lokal
generierte Test-GPG-Identitäten + lokale/temporäre bare Git-Repos als Test-Fixtures
bauen, die reale Provisionierung als Runbook dokumentieren
(`docs/SHARED-TEAM-RUNBOOK.md`). So sind Phase 3-6 des Shared-Store-Tickets
tatsächlich fertig geworden, ohne je auf echte `jasp/*`-Repos zu warten.

## Vorhandene Primitive wiederverwenden, nicht neu bauen

- `internal/sync/sync.go` — Mounts mit eigenem Git-Remote (`LayoutPerOrg`,
  `DefaultStoreMount`); `internal/sync/shared.go` erweitert das um Shared-Mounts
  (Locking, atomare Writes, Path-Traversal-Guards, Retry-on-non-fast-forward).
- `internal/audit/audit.go` — `Entry{SecretPath,Org,ActorKind,ActorDetail(agent_label),
  Reason,Host,Result,ts,seq}`; `internal/teamaudit/` baut die signierte
  Team-Variante darauf auf, nicht als Parallelimplementierung.
- `internal/caller/caller.go` — `Detail{Kind,AgentLabel,Reason}`; AI-Signale sind
  nicht downgradebar — jede neue Caller-Erkennung muss das respektieren.
- `cmd/mys/cmd_bw_import.go` — Bitwarden-Bridge über den `mys/<org>`-Namespace,
  verweigert AI-Callern grundsätzlich; diese Sperre gilt unabhängig vom
  Shared-Store-AI-Policy-Fail-Closed (das betrifft nur Reads, nicht Import).
- `internal/recipient/`, `internal/teamkeys/` — Recipient- bzw.
  Team-Key-/Name-Map-Verwaltung; mount-scoped foreign recipients (Phase 2) liegen
  in `internal/recipient/`, nicht als eigenes Paket.

## Branch- und Commit-Hygiene

- Nie auf `main` committen; Feature-Branch von `origin/main`.
- Gezielt `git add <pfade>`, nie `git add -A`/`git add .` — sonst zieht ein
  liegengebliebenes `HANDOFF.md` in den PR.
- Secrets nie in Logs, Terminal-Output ohne `--reveal` oder Commit-Messages —
  auch nicht in Tests: nur generierte Test-Keys, nie echte Werte.

## Reviewer-Gate für sicherheitsrelevante PRs

PR #103 (Shared-Store + Audit) lief mit drei unabhängigen Reviewer-Ketten
(Security, Data-Flow, Quality) vor dem Merge — Muster für zukünftige
security-sensitive Änderungen an diesem Repo, nicht nur der Standard-Ein-Pass-Gate.
