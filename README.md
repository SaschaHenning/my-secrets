# my-secrets

Lokaler Credential-Manager für macOS mit Audit-Log, Org-Scoping und Claude-Code-Integration.

## Kurzbeschreibung

Ein schlanker Wrapper um [gopass](https://github.com/gopasspw/gopass), der:

- Secrets lokal und maschinengebunden verschlüsselt speichert (GPG-Key im macOS-Keychain, Touch-ID via `pinentry-touchid`)
- jeden Zugriff (Read und Write) in einer Audit-DB protokolliert
- erkennt, ob ein Zugriff von einem Menschen, Claude Code oder einem Agent kommt
- Org-Scoping durchsetzt (ein Projekt in `~/Code/JASP-*` kann nur auf `jasp/`-Secrets zugreifen)
- eine kleine Web-UI auf `localhost` für Audit-Log und Secret-Browser bereitstellt
- per MCP-Server die einzige Eintrittstür für KI-Zugriffe ist
- optional Secrets nach Bitwarden exportiert (einseitig, explizit)

## Architektur

Siehe [`docs/plan.html`](docs/plan.html) für die vollständige Planungsübersicht mit drei evaluierten Architekturansätzen und Begründung der gewählten Lösung.

**Kurzfassung der gewählten Lösung (Ansatz C, Library-Variante):**

```
┌─────────────────────────────────────────────────────────────┐
│ Clients                                                     │
│  Mensch-CLI      Claude Skill (MCP)     Scripts / n8n       │
└───────┬──────────────────┬─────────────────────┬───────────┘
        └──────────────────┼─────────────────────┘
                           ▼
                ┌──────────────────────┐
                │ mys (Go Binary)      │  ← einziger Eintritt
                │ + MCP-Server         │
                │  • gopass-Library    │
                │  • Caller-Erkennung  │
                │  • Scope-Policy      │
                │  • Audit-Writer      │
                │  • Web-UI            │
                └───┬──────────────┬───┘
                    ▼              ▼
          ┌────────────────┐  ┌──────────────┐
          │ gopass store   │  │ audit.sqlite │
          │ (GPG, Git)     │  └──────────────┘
          └────────┬───────┘
                   ▼
          ┌────────────────┐
          │ macOS Keychain │
          │ + Touch-ID     │
          └────────────────┘
```

## Stack

- **Go** — Single-Binary für CLI, MCP-Server und Web-UI
- **gopass** (Library-Import, keine Subprocess-Calls) — Storage + GPG
- **SQLite** — Audit-Log
- **macOS Keychain + pinentry-touchid** — Master-Key-Handling, Biometrie
- **MCP (Model Context Protocol)** — KI-Schnittstelle über stdio

## Status

MVP in Entwicklung. Siehe [Issues](https://github.com/SaschaHenning/my-secrets/issues).

## Projektstruktur

```
my-secrets/
├── cmd/mys/            # CLI + MCP-Server + Web-UI Entry-Points
├── internal/
│   ├── store/          # gopass-Library-Wrapper
│   ├── audit/          # SQLite-Audit-Writer
│   ├── caller/         # PPID/Env-Detection
│   ├── policy/         # Org-Scoping-Enforcement
│   ├── mcp/            # MCP-Server-Handler
│   └── web/            # Web-UI-Server
├── docs/plan.html      # Planungsübersicht
├── CLAUDE.md           # Claude-Code-Instruktionen
└── .claude/shared-rules.md -> ../JASP-Shared/AI-Rules/CLAUDE.md
```
