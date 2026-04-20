# Installation — für Kollegen

Schritt-für-Schritt-Anleitung für ein frisches macOS-Setup.

## TL;DR

Komplett von Null (kein GPG-Key, kein gopass-Store, kein my-secrets):

```bash
brew install gopass pinentry-mac
git clone https://github.com/SaschaHenning/my-secrets ~/Code/my-secrets
cd ~/Code/my-secrets
make build && sudo cp bin/mys /usr/local/bin/
mys init --install-skill
```

Das reicht. `mys init` generiert den GPG-Key, initialisiert den
gopass-Store, setzt `pinentry-mac` in Gang, legt Policy + Audit-DB
an und verlinkt den Claude-Skill.

Oder komplett automatisiert via Installer:

```bash
git clone https://github.com/SaschaHenning/my-secrets ~/Code/my-secrets
cd ~/Code/my-secrets
./install.sh
```

Das Skript prüft Voraussetzungen, installiert Homebrew-Pakete, baut das
Binary, legt es nach `/usr/local/bin`, ruft `mys init --install-skill`
(das erledigt inzwischen auch GPG-Key + gopass-Store) und trägt den
MCP-Server in `~/.claude/settings.json` ein.

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
brew install jorgelbg/tap/pinentry-mac

# Wenn das wegen eines Homebrew-Ruby-Bugs („undefined method 'type_member'")
# scheitert, Binary direkt bauen:
git clone https://github.com/jorgelbg/pinentry-mac /tmp/ptid
cd /tmp/ptid
go build -o "$(brew --prefix)/bin/pinentry-mac" .
```

Anschließend in `~/.gnupg/gpg-agent.conf`:

```
pinentry-program /opt/homebrew/bin/pinentry-mac
```

Ohne `pinentry-mac` funktioniert alles — du bekommst dann den
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

## Schritt 4 · my-secrets initialisieren (GPG-Key, gopass-Store, Policy, Skill)

Ein einzelner Befehl bootstrappt alles:

```bash
mys init --install-skill
```

Er läuft als sechsstufiger Runner und bringt die Maschine in einen
arbeitsfähigen Zustand:

1. **GPG-Key** — vorhandenen Secret-Key suchen; wenn keiner da ist,
   einen Ed25519/Curve25519-Key erzeugen (Name + Email aus
   `git config --global user.name|user.email`, bei Bedarf interaktiv
   nachfragen).
2. **gopass-Store** — `gopass init` gegen den gerade ermittelten
   Fingerprint, wenn `~/.password-store/.gpg-id` noch fehlt.
3. **pinentry-mac** — falls das Binary auf PATH liegt, wird der
   Eintrag in `~/.gnupg/gpg-agent.conf` gesetzt und `gpg-agent`
   neugestartet. Sonst: kurzer Hinweis, kein Abbruch.
4. **Policy + Audit-DB** — schreibt
   `~/.config/my-secrets/scope-policy.yaml` (Default-Regeln: AI-Caller
   dürfen `jasp/**` und `zuhause/**`, nicht `private/**`) und legt
   `~/.local/share/my-secrets/audit.sqlite` an.
5. **Claude-Skill** — nur wenn `--install-skill` gesetzt. Neu: im
   interaktiven Modus fragt `mys init`, ob der Skill **global**
   (`~/.claude/skills/my-secrets`, empfohlen) oder **lokal**
   (`<CWD>/.claude/skills/my-secrets`) installiert werden soll.
6. **git sync** (optional) — nur mit `--with-sync`: ruft den gleichen
   Wizard wie `mys sync setup`.

Re-Runs sind idempotent: existierende Keys werden wiederverwendet, der
gopass-Store nicht neu initialisiert, gpg-agent.conf nicht dupliziert,
Policy und Audit-DB nicht überschrieben.

Flags:

```bash
# Non-interactive (CI, fresh Mac):
mys init --yes                          # fehlt user.name/email in git config → Fehler
mys init --yes --no-passphrase          # Key ohne Passphrase (via pinentry-mac)

# Explizite Angaben:
mys init --name "Sascha" --email garry@jasp.eu

# Skill direkt mit einziehen:
mys init --install-skill                 # global (default)
mys init --install-skill --skill-scope local

# Alles auf einmal:
mys init --yes --install-skill --with-sync
```

Wer das in kleinere Schritte trennen will:

```bash
mys init                  # Key + Store + Policy + Audit
mys install-skill         # Skill nachinstallieren (global)
mys install-skill --scope local  # Skill nur im aktuellen Projekt
mys sync setup            # git sync separat
```

## Schritt 5 · MCP-Server in Claude registrieren

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

**`mys init` bricht bei der GPG-Key-Generierung ab**
→ Prüfe `gpg --list-secret-keys`. Häufige Ursachen: `gpg-agent` ohne
gültigen `pinentry`-Pfad, oder ein existierender Key mit blockierender
Passphrase-Eingabe. `brew install pinentry-mac` und
`pinentry-program /opt/homebrew/bin/pinentry-mac` in
`~/.gnupg/gpg-agent.conf` lösen 95 % der Fälle.

**`mys init` bricht mit „cannot derive name/email in --yes mode" ab**
→ Im `--yes`-Modus müssen `git config --global user.name` und
`user.email` gesetzt sein, oder `--name`/`--email` explizit übergeben
werden.

**`mys get` hängt beim GPG-Passphrase-Prompt**
→ `gpg-agent` läuft nicht oder findet kein Display. Einmal
`echo "" | gpg --clearsign` testen. Wenn das scheitert:
`brew install pinentry-mac` + in `~/.gnupg/gpg-agent.conf`
`pinentry-program /opt/homebrew/bin/pinentry-mac` eintragen.

**`brew install jorgelbg/tap/pinentry-mac` scheitert mit „type_member"**
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
