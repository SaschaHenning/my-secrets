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
