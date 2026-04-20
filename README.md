# my-secrets

Lokaler Credential-Manager für macOS mit Audit-Log, Org-Scoping und
Claude-Code-Integration via MCP.

## Was das ist

Ein schlankes Go-Binary (`mys`), das die [gopass](https://github.com/gopasspw/gopass)-Bibliothek um drei Dinge erweitert:

1. **Ein SQLite-Audit-Log.** Jeder Lese-, Schreib-, Such- und Löschvorgang
   landet als Zeile — inklusive des vollen Parent-Process-Kontexts und
   erkannter KI-Umgebungsvariablen.
2. **Scope-Policy.** Eine YAML-Datei legt fest, welche Actor-Klasse
   (`human`, `ai`, `claude-code`, `script`) welche Pfad-Globs sehen darf.
   Ein AI-Aufruf auf `private/**` scheitert hart, ein Mensch bekommt
   alles.
3. **Drei Eintrittspunkte — ein Audit-Pfad.** Interaktives CLI, eingebettete
   Web-UI (`127.0.0.1`, read-only) und MCP-Server über stdio laufen alle
   durch dieselbe `app`-Orchestrierungsschicht. Für Claude Code ist der
   MCP-Server die einzige sanktionierte Tür zum Store.

## Voraussetzungen

| Tool                 | Brew-Paket                           | Zweck                        |
| -------------------- | ------------------------------------ | ---------------------------- |
| Go ≥ 1.22            | `brew install go`                    | Build                        |
| gopass ≥ 1.15        | `brew install gopass`                | Storage-Backend              |
| GnuPG ≥ 2.2          | `brew install gnupg`                 | Krypto (Private Key im Keychain) |
| pinentry-touchid *   | siehe unten                          | Touch-ID-Unlock (optional)   |

\* Der Homebrew-Tap `jorgelbg/tap` lässt sich auf manchen Systemen wegen
eines Ruby-`type_member`-Bugs nicht adden. In dem Fall das Binary direkt
bauen:

```bash
git clone https://github.com/jorgelbg/pinentry-touchid /tmp/ptid && \
  cd /tmp/ptid && go build -o $(brew --prefix)/bin/pinentry-touchid .
```

Ohne `pinentry-touchid` funktioniert alles — du bekommst dann den
Standard-`pinentry`-Prompt statt Touch ID.

## Install

**TL;DR — one-shot:**

```bash
git clone https://github.com/SaschaHenning/my-secrets ~/Code/my-secrets
cd ~/Code/my-secrets
./install.sh
```

Das Skript installiert alle Homebrew-Pakete, baut das Binary, legt es
nach `/usr/local/bin`, initialisiert gopass (falls nötig), führt
`mys init --install-skill` aus und trägt den MCP-Server in
`~/.claude/settings.json` ein. `mys install-skill` existiert weiterhin
als eigenständiger Befehl für manuelles Nachinstallieren.

Für den **manuellen Weg**, alle Voraussetzungen, Update-/Deinstall-Schritte
und Troubleshooting siehe [`INSTALL.md`](INSTALL.md).

**Claude Code**: Nach der Installation findet Claude den MCP-Server
automatisch beim nächsten Session-Start. Alle Zugriffe laufen dann über
`creds_list` / `creds_search` / `creds_get` und landen als
`actor_kind=ai` im Audit-Log.

## Schnellstart

```bash
# Secret anlegen
echo "ghp_xxx" | mys add jasp/github-token \
  --kind api_key --user sascha --url https://github.com \
  --github SaschaHenning/my-secrets --tags infra,ci

# Suchen
mys search github

# Lesen (maskiert)
mys get jasp/github-token

# Lesen mit Klartext-Passwort
mys get jasp/github-token --reveal

# Nur ein Feld holen
mys get jasp/github-token --field password --reveal

# Als ENV-Export
mys get jasp/github-token --format env --reveal

# Rotieren
echo "new-pw" | mys rotate jasp/github-token

# Löschen
mys rm jasp/github-token

# Audit-Log
mys audit tail --limit 30
mys audit tail --actor ai
mys audit verify                          # prüft Hash-Lücken
```

## TOTP / 2FA

TOTP-Seeds (die Basis jeder „Authenticator-App") sind die zweitgrößte
Credential-Klasse nach Passwörtern — und die schmerzhafteste, wenn das
Telefon verloren geht. `my-secrets` speichert Seeds verschlüsselt im
gopass-Store und generiert den aktuellen Code deterministisch aus der
lokalen Uhr.

```bash
# Direkt aus dem QR-Code-URI hinzufügen (wie Google Authenticator ihn liest)
mys totp add jasp/github \
  "otpauth://totp/GitHub:sascha?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"

# Oder nur ein Base32-Seed, Metadaten via Flags
mys totp add jasp/aws JBSWY3DPEHPK3PXP --issuer AWS --label ops

# Aktuellen Code holen
mys totp jasp/github
#
# jasp/github (GitHub:sascha)
# 487 291     (19s left)

# Watch-Modus: aktualisiert sekündlich, Abbruch mit Ctrl-C
mys totp jasp/github --watch
```

`mys get jasp/github` zeigt die TOTP-Metadaten (Issuer, Label,
Algorithmus, Digits, Period) und maskiert den Seed. Nur `--reveal`
druckt ihn im Klartext.

Jede `mys totp <path>`-Code-Generierung erzeugt eine Audit-Zeile mit
`action=totp_generate` und `reason=window=<index>` (RFC-6238-Zeitfenster),
so dass wiederholte Aufrufe im selben 30-s-Fenster erkennbar bleiben.
Die Scope-Policy greift identisch zu `mys get`: AI-Aufrufer kommen nicht
an `private/**`.

## Checking your setup: `mys doctor`

Ein einzelner Befehl, der elf Checks durchläuft und beantwortet: „Ist
meine Installation in Ordnung?"

```bash
mys doctor                         # Textausgabe
mys doctor --json                  # maschinenlesbar (CI-tauglich)
mys doctor --only policy,audit-gaps
```

Exit-Code ist ≠ 0, sobald ein Check `[FAIL]` meldet. Der
`rotation-overdue`-Check kann nur WARNen, nie FAILen — ein überfälliges
Secret ist ein Stupser, kein Blocker.

**Geprüft werden:**

| #  | ID                  | Kriterium                                          |
|----|---------------------|----------------------------------------------------|
| 1  | `store`             | `~/.password-store` oder `$PASSWORD_STORE_DIR`     |
| 2  | `gpg-key`           | mindestens ein GPG-Secret-Key                      |
| 3  | `recipients`        | ≥ 2 gopass-Recipients (1 = WARN, „kein Backup")   |
| 4  | `git-remote`        | `gopass git remote -v` liefert einen Remote        |
| 5  | `sync-age`          | letzter Fetch ≤ 7 Tage = PASS, ≤ 30 = WARN         |
| 6  | `audit-writable`    | Audit-DB lässt sich öffnen + beschreiben           |
| 7  | `audit-gaps`        | `audit.Verify` findet keine Lücken                 |
| 8  | `signed-chain`      | wenn `MYS_AUDIT_SIGN=1`: Hash-Kette stimmt         |
| 9  | `paperkey-backup`   | `~/.local/share/my-secrets/backups.json` ≥ 1 Eintrag |
| 10 | `policy`            | `scope-policy.yaml` existiert & parst sauber       |
| 11 | `rotation-overdue`  | keine Einträge jenseits ihres `rotate_after`-Horizonts |

**Sample-Output** (leere HOME-Umgebung, demonstriert alle Status-Werte):

```
mys doctor — 2026-04-20 16:43:01

[FAIL] gopass store exists — store directory missing: …/.password-store
         -> run `gopass setup` to initialise the store
[FAIL] GPG secret key available — gpg --list-secret-keys failed: exit status 2
[WARN] gopass git remote — no git remote configured
         -> configure a remote with `gopass git remote add origin <url>`
[WARN] last sync age — 12 days ago (ref=HEAD)
         -> run: mys sync push
[PASS] audit DB writable — temp DB open+write ok
[PASS] audit log gaps — no gaps (142 rows)
[SKIP] signed audit chain — signed mode not enabled (MYS_AUDIT_SIGN unset)
[WARN] paperkey backup recorded — no paperkey backup recorded
         -> create one with `mys paperkey backup`
[WARN] scope policy file — missing at …/scope-policy.yaml (using baked-in defaults)
         -> run `mys init` to write the default policy

Summary: 2 PASS / 4 WARN / 3 FAIL / 1 SKIP
```

Jeder `mys doctor`-Lauf schreibt eine einzelne Aggregat-Zeile
(`action=doctor`, `reason=pass=… warn=… fail=… skip=…`) ins Audit-Log.

## Rotation reminders

Damit kein Passwort stillschweigend drei Jahre alt wird, kann jedes
sensible Secret einen Rotations-Horizont tragen. Das Tooling hebt
überfällige Einträge hervor — Rotation wird damit Gewohnheit statt
Gedächtnisleistung.

**Policy beim Anlegen setzen:**

```bash
echo "ghp_xxx" | mys add jasp/github-token --rotate-after 90d
```

Erlaubt sind `Nd` (Tage), `Nw` (Wochen), `Nm` (Monate = 30 Tage) und
`Ny` (Jahre = 365 Tage). Eine leere Policy heißt „opt-out" — der
Eintrag erscheint niemals in `--stale` oder `--rotating-in`.

**Stale Einträge auflisten:**

```bash
mys ls --stale                     # alles überfällige
mys ls --rotating-in 7d            # nächste Wochenrunde
mys ls --stale --rotating-in 30d   # kombiniert (AND)
```

`--stale` erweitert die Ausgabe um Alter und Policy:

```
jasp/github-token  112d old  rotate_after=90d
```

**Beim Rotieren wird der Zeitstempel automatisch gesetzt:**

```bash
echo "new-pw" | mys rotate jasp/github-token
# rotate_after bleibt erhalten, rotated_at wird auf jetzt gesetzt.
```

**In `mys doctor`:** Der `rotation-overdue`-Check zählt stale Einträge
und meldet WARN (nie FAIL). Pfade werden bewusst nicht aufgelistet —
die Ausgabe bleibt kompakt; `mys ls --stale` zeigt die Details.

Einträge mit Policy aber ohne Rotations-Historie (z. B. nach einem
Import) werden sanfter gemeldet: „rotation policy set but no rotation
history". `mys rotate <path>` stempelt dann den ersten Zeitstempel.

## Key-Backup

Der Private Key, der den ganzen Store entschlüsselt, ist die „Krone". Geht
er verloren, sind **alle** Secrets weg — auf jedem Gerät, für immer.
Deshalb gibt es `mys key backup`:

```bash
# Paperkey: kompakte Druckausgabe des Secret Keys.
mys key backup --paper --out key.paper
lp key.paper                                          # ausdrucken + wegschließen

# ASCII-armored, symmetrisch verschlüsselt (AES256): sicher für USB-Sticks.
mys key backup --armored --symmetric --out key.asc.gpg

# Was ist schon gesichert?
mys key backup --status
```

Diese Backups sind **persönlich**: sie rekonstruieren den Key, dem der
ganze Store gehört. Niemals mit Kolleginnen teilen — für Team-Sharing
gibt es `mys bw-export`. Metadaten jedes Backups landen in
`~/.local/share/my-secrets/backups.json` (niemals Key-Material) und als
`action=key_backup`-Zeile im Audit-Log.

## Web-UI

```bash
mys web --port 7823
# → http://127.0.0.1:7823
```

Read-only. Zeigt nur Pfade, Metadaten, Audit-Log — **niemals**
Passwort-Werte. Bindet ausschließlich auf das Loopback-Interface.

Screenshots siehe [`docs/screenshots/`](docs/screenshots).

## Org-Scoping

Orgs = Top-Level-Ordner im gopass-Store. `~/.config/my-secrets/scope-policy.yaml`:

```yaml
actors:
  human:
    allow: ["**"]
  script:
    allow: ["**"]
  ai:
    allow: ["jasp/**", "zuhause/**"]
    deny:  ["private/**"]
  claude-code:
    allow: ["jasp/**", "zuhause/**"]
    deny:  ["private/**"]
```

`deny` schlägt `allow`. Fehlt ein Actor aus der Datei, gilt die Default-Policy
(siehe `internal/policy/policy.go`).

## Caller-Erkennung

`mys` klassifiziert den Aufrufer als `human`, `ai` oder `script` anhand von:

1. Explizitem Flag `--requester {claude-code|human|ai|script}` (Top-Priorität)
2. Env-Variablen: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CURSOR`, …
3. Parent-Process-Kette (`ps`-Walk bis PID 1)
4. TTY-Präsenz (interaktiv = human)

Die gesamte Detail-Struktur (PID-Chain, Env-Flags, TTY-Status) landet als
JSON im Audit-Log unter `actor_detail`.

## Bitwarden-Export

```bash
mys bw-export --org jasp --out jasp-backup.json
```

Schreibt eine Bitwarden-kompatible JSON-Datei, die du bei Bedarf manuell
in Bitwarden importieren kannst. Einseitig — kein Live-Sync.

## Syncing across your own devices

`my-secrets` ist ein **persönlicher** Credential-Manager. Der eingebaute
Git-Sync dient ausschließlich der Redundanz zwischen deinen eigenen
Geräten — **nicht** dem Teilen mit Kolleg:innen. Für Team-Secrets ist
Bitwarden (oder ein vergleichbarer Tresor mit personalisiertem Login)
das richtige Werkzeug; ein gemeinsam genutzter GPG-Key würde das
Audit-Log unbrauchbar machen.

```bash
# Einmalig: GitHub-Repo anlegen, gopass-Remote setzen, initialer Push
mys sync setup

# Im CI / non-interaktiv (Defaults: single-repo, SSH):
mys sync setup --yes

# Alltag
mys sync push      # alle konfigurierten Stores hochladen
mys sync pull      # nur herunterziehen (auf dem Zweitgerät)
mys sync status    # zeigt letzten Sync + Remote-Erreichbarkeit
```

Der Wizard fragt zuerst, ob du einen einzigen Store oder ein Repo pro
Org willst. Er erzeugt über `gh repo create --private` ein privates
GitHub-Repo (ein `gh auth login` muss vorher gelaufen sein), verdrahtet
den gopass-Remote und führt einen ersten Sync aus. Der Zustand landet
in `~/.config/my-secrets/sync.yaml`; jede Sync-Aktion schreibt eine
Zeile ins Audit-Log (`action=sync_push|sync_pull|sync_setup`).

### Auto-Sync nach Schreiboperationen

Sobald `mys sync setup` einmal gelaufen ist, wird nach jedem
erfolgreichen `mys add`, `mys rotate` und `mys rm` automatisch ein
`gopass sync` ausgelöst — du musst dich nicht mehr an `mys sync push`
erinnern, wenn dein mentales Modell „Änderung landet sofort auf GitHub"
ist. Der Push läuft synchron mit 5 Sekunden Timeout; schlägt er fehl
(offline, Netzwerkfehler), bleibt der lokale Commit erhalten, `mys`
druckt eine Warnung auf stderr und schreibt eine Audit-Zeile mit
`action=sync_push, result=error`. Der Exit-Code ist trotzdem `0`, weil
die Schreiboperation selbst geglückt ist.

Opt-out:

```bash
# Für diesen einen Aufruf:
mys add --no-sync jasp/foo

# Global (z. B. beim Rollout oder im Offline-Modus):
export MYS_AUTO_SYNC=0
```

Gültige „aus"-Werte für `MYS_AUTO_SYNC`: `0`, `false`, `off`, `no`
(case-insensitive). Alles andere (einschließlich „unset") bedeutet
eingeschaltet.

## Projektstruktur

```
my-secrets/
├── cmd/mys/           # CLI/MCP/Web Entry-Point
├── internal/
│   ├── store/         # gopass-Bibliothek-Wrapper
│   ├── audit/         # Append-only SQLite Log
│   ├── caller/        # PPID/Env-Klassifikation
│   ├── policy/        # YAML-Scope-Policy
│   ├── app/           # Orchestrator (caller → policy → store → audit)
│   ├── mcp/           # JSON-RPC 2.0 über stdio
│   └── web/           # Localhost HTTP UI (embed.FS)
├── skills/my-secrets/ # Claude-Code-Skill
├── docs/              # Architektur, Security, Test-Report, Plan
└── scripts/           # E2E-Setup-Skripte
```

## Entwicklung

```bash
make build              # Binary
make test               # Unit-Tests
make vet                # go vet
make e2e                # startet Test-Store und fährt Szenarien durch
make run-web            # dev web UI
```

## Sicherheit

Siehe [`docs/SECURITY.md`](docs/SECURITY.md) — Bedrohungsmodell, was
„maschinengebunden" hier wirklich heißt, bekannte Grenzen.

## Architektur

Siehe [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Komponenten,
Datenfluss, Design-Entscheidungen. Die ursprüngliche Drei-Ansatz-Abwägung
steht in [`docs/plan.html`](docs/plan.html).

## Troubleshooting

**`mys init` sagt „gopass store not initialised"**
→ `gopass setup` davor laufen lassen (einmalig). Anschließend `mys init`.

**`mys get` hängt beim GPG-Passphrase-Prompt**
→ `gpg-agent` läuft nicht oder `pinentry` findet kein Display.
`echo "" | gpg --clearsign` einmal testen, dann GUI-`pinentry`
installieren: `brew install pinentry-mac`.

**Audit-DB sagt `database is locked`**
→ Passiert bei gleichzeitigem Schreiben von vielen Prozessen. MVP nutzt
SQLite im WAL-Mode, ein paar parallele CLI-Aufrufe sind ok. Bei n8n-Bulk-
Workflows den Zugriff serialisieren.

**Claude liest direkt aus `~/.password-store`**
→ Der Skill verbietet das explizit. Sollte es trotzdem passieren: im Claude-
Project `.claude/settings.json` den Dateipfad blockieren.

## Lizenz

MIT. Siehe `LICENSE` (TBD).
