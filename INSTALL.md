# Installation — für Kollegen

Schritt-für-Schritt-Anleitung für ein frisches macOS-Setup.

## TL;DR

```bash
git clone https://github.com/SaschaHenning/my-secrets ~/Code/my-secrets
cd ~/Code/my-secrets
./install.sh
```

Das Skript prüft Voraussetzungen, installiert Homebrew-Pakete, baut das
Binary, legt es nach `/usr/local/bin`, richtet gopass ein, initialisiert
my-secrets und registriert den MCP-Server in `~/.claude/settings.json`.

Wenn du es manuell machen willst, siehe unten.

---

## Voraussetzungen

| Tool | Version | Herkunft |
| --- | --- | --- |
| macOS | 12 oder neuer | — |
| Homebrew | beliebig | https://brew.sh |
| Xcode Command Line Tools | für `git`, `make` | `xcode-select --install` |
| Claude Code | optional, für MCP-Integration | https://claude.com/claude-code |

## Schritt 1 · Homebrew-Pakete

```bash
brew install go gopass gnupg
```

| Paket | Wofür |
| --- | --- |
| `go` (≥ 1.22) | Bauen des Binaries |
| `gopass` (≥ 1.15) | Storage-Backend — wir importieren gopass als Library, aber das CLI brauchst du für die einmalige Store-Initialisierung |
| `gnupg` | Krypto-Backend; stellt `gpg-agent` bereit |

### Optional: Touch-ID-Unlock

Für biometrische Freigabe beim GPG-Entsperren:

```bash
# Versuch 1 — Homebrew-Tap
brew install jorgelbg/tap/pinentry-touchid

# Wenn das wegen eines Homebrew-Ruby-Bugs („undefined method 'type_member'")
# scheitert, Binary direkt bauen:
git clone https://github.com/jorgelbg/pinentry-touchid /tmp/ptid
cd /tmp/ptid
go build -o "$(brew --prefix)/bin/pinentry-touchid" .
```

Anschließend in `~/.gnupg/gpg-agent.conf`:

```
pinentry-program /opt/homebrew/bin/pinentry-touchid
```

Ohne `pinentry-touchid` funktioniert alles — du bekommst dann den
Standard-`pinentry`-Prompt (Passphrase im Keychain gespeichert).

## Schritt 2 · Repo klonen und bauen

```bash
git clone https://github.com/SaschaHenning/my-secrets ~/Code/my-secrets
cd ~/Code/my-secrets
make build
```

Das erzeugt `bin/mys` (~28 MB, statisch gelinkt).

## Schritt 3 · Binary installieren

```bash
sudo cp bin/mys /usr/local/bin/
mys --version   # Sanity-Check
```

Alternativ: Symlink auf das Build-Artefakt, damit `git pull + make build`
automatisch nachzieht:

```bash
sudo ln -sf "$PWD/bin/mys" /usr/local/bin/mys
```

## Schritt 4 · gopass initialisieren

Wenn du noch keinen gopass-Store hast, jetzt einmalig:

```bash
gopass setup
```

Der Assistent fragt:
- Nach einem GPG-Key (oder erzeugt einen neuen).
- Nach dem Store-Pfad (Default: `~/.password-store`).
- Ob ein Git-Remote dranhängen soll (für Backup/Sync) — optional.

Wenn du schon `gopass` nutzt oder einen alten `pass`-Store hast, wird
der erkannt.

## Schritt 5 · my-secrets initialisieren (inkl. Claude-Skill)

```bash
mys init --install-skill
```

Das schreibt:
- `~/.config/my-secrets/scope-policy.yaml` — YAML mit Default-Regeln (AI-Caller dürfen `jasp/**` und `zuhause/**`, nicht `private/**`).
- `~/.local/share/my-secrets/audit.sqlite` — append-only SQLite-Log.
- `~/.claude/skills/my-secrets` — Symlink auf das Skill-Verzeichnis im Repo.

Policy und Audit mit Mode `0o600` / Verzeichnis `0o700`. Claude lädt den
Skill beim nächsten Session-Start.

Wer das Init und den Skill getrennt fahren will (z.B. Skill später
nachziehen), kann stattdessen weiterhin zweistufig vorgehen:

```bash
mys init                  # nur Policy + Audit
mys install-skill         # später Skill nachinstallieren (alternative)
```

## Schritt 6 · MCP-Server in Claude registrieren

Datei `~/.claude/settings.json` um folgenden Block ergänzen (oder das
`install.sh` hat es schon für dich gemacht):

```json
{
  "mcpServers": {
    "my-secrets": {
      "command": "mys",
      "args": ["mcp"]
    }
  }
}
```

Ab jetzt: Claude Code kann nur noch über die MCP-Tools
`creds_list` / `creds_search` / `creds_get` auf Secrets zugreifen.
Jeder Zugriff landet als `actor_kind=ai` im Audit-Log.

## Verifikation

```bash
# Ein Secret anlegen
echo "test-pw" | mys add zuhause/test --kind password --user me

# Lesen (Password standardmäßig maskiert)
mys get zuhause/test

# Audit-Log anschauen
mys audit tail

# Web-UI auf http://127.0.0.1:7823
mys web
```

In Claude Code: frag die Session „zeig mir creds_list aus my-secrets".
Claude sollte mit der Liste antworten und der Audit-Log bekommt einen
Eintrag mit `actor_kind=ai`.

## Update

```bash
cd ~/Code/my-secrets
git pull
make build
sudo cp bin/mys /usr/local/bin/
# Falls der Symlink-Pfad oben genutzt wurde, erübrigt sich der letzte Schritt.
```

Policy und Audit-Log bleiben beim Update unangetastet.

## Deinstallation

```bash
cd ~/Code/my-secrets
./uninstall.sh
```

Entfernt:
- `/usr/local/bin/mys`
- `~/.claude/skills/my-secrets` (Symlink)
- MCP-Server-Eintrag aus `~/.claude/settings.json`

Nicht entfernt (das musst du explizit tun):
- `~/.password-store` (gopass-Store mit allen Secrets)
- `~/.local/share/my-secrets/audit.sqlite` (Audit-Log)
- `~/.config/my-secrets/scope-policy.yaml` (Policy)
- GPG-Keys im Keychain

## Troubleshooting

**`mys init` sagt „gopass store not initialised"**
→ Vorher `gopass setup` laufen lassen. Siehe Schritt 4.

**`mys get` hängt beim GPG-Passphrase-Prompt**
→ `gpg-agent` läuft nicht oder findet kein Display. Einmal
`echo "" | gpg --clearsign` testen. Wenn das scheitert:
`brew install pinentry-mac` + in `~/.gnupg/gpg-agent.conf`
`pinentry-program /opt/homebrew/bin/pinentry-mac` eintragen.

**`brew install jorgelbg/tap/pinentry-touchid` scheitert mit „type_member"**
→ Homebrew-Ruby-Bug. Siehe „Optional: Touch-ID-Unlock" oben für den manuellen Bau.

**Audit-DB sagt `database is locked`**
→ Bei vielen parallelen Aufrufen. Serialisiere Bulk-Jobs (z.B. in n8n,
nicht gleichzeitig 50 `mys get` starten).

**Claude Code sieht den MCP-Server nicht**
→ Session neu starten. Einträge in `~/.claude/settings.json` unter
`mcpServers` werden nur beim Start gelesen. Prüfen mit `cat ~/.claude/settings.json`.

**Policy ändern**
→ `~/.config/my-secrets/scope-policy.yaml` editieren. Kein Neustart nötig;
mys lädt sie bei jedem Aufruf neu. Unbekannte oder vertippte Actor-Keys
führen zu `deny` (fail-closed).

**Wie sehe ich, was Claude im letzten Gespräch gemacht hat?**
→ `mys audit tail --actor ai` oder im Browser `mys web` und dort auf
„Audit Log" → Actor-Filter auf „ai".

## Für Team-Setups

my-secrets ist ein Single-Mac-Tool. Für echtes Team-Sharing weiterhin
Bitwarden nutzen; mys kann nach Bitwarden exportieren:

```bash
mys bw-export --org jasp --out jasp.bw.json --reveal --i-understand
```

Die JSON-Datei importierst du manuell in Bitwarden.
