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
   durch dieselbe `app`-Orchestrierungsschicht. Für Claude Code ist MCP der
   bevorzugte Standardweg; Shell-/Skript-Kontexte dürfen nur die `mys`-CLI
   mit auditierter, consumer-sicherer Ausgabe nutzen. Direkte Store-Backends
   bleiben tabu.

## Voraussetzungen

| Tool                 | Brew-Paket                           | Zweck                        |
| -------------------- | ------------------------------------ | ---------------------------- |
| Go ≥ 1.22            | `brew install go`                    | Build                        |
| gopass ≥ 1.15        | `brew install gopass`                | Storage-Backend              |
| GnuPG ≥ 2.2          | `brew install gnupg`                 | Krypto (Private Key im Keychain) |
| pinentry-mac *   | siehe unten                          | Touch-ID-Unlock (optional)   |

\* Der Homebrew-Tap `jorgelbg/tap` lässt sich auf manchen Systemen wegen
eines Ruby-`type_member`-Bugs nicht adden. In dem Fall das Binary direkt
bauen:

```bash
git clone https://github.com/jorgelbg/pinentry-mac /tmp/ptid && \
  cd /tmp/ptid && go build -o $(brew --prefix)/bin/pinentry-mac .
```

Ohne `pinentry-mac` funktioniert alles — du bekommst dann den
Standard-`pinentry`-Prompt statt Touch ID.

## Install

### Zero-to-ready in one command

Auf einer frischen Maschine ohne GPG-Key, ohne gopass-Store, ohne
irgendwas:

```bash
brew install gopass pinentry-mac
mys init --install-skill
```

Das reicht. `mys init` erzeugt einen Ed25519-GPG-Key (Name/Email aus
`git config --global` abgeleitet), initialisiert den gopass-Store, trägt
`pinentry-mac` in `~/.gnupg/gpg-agent.conf` ein, legt Policy + Audit-
DB an und verlinkt den Claude-Skill nach `~/.claude/skills/my-secrets`.
Danach funktionieren `mys add`, `mys get`, `mys doctor` sofort.

Voll non-interactive (CI / Skript):

```bash
mys init --yes --install-skill --with-sync
```

Im `--yes`-Modus werden `git config user.name` / `user.email` als
Defaults genommen; fehlen sie, bricht der Befehl ab statt zu fragen.
`--no-passphrase` überspringt die Passphrase-Abfrage — sinnvoll, wenn
`pinentry-mac` die Authentisierung übernimmt.

**TL;DR — one-shot install via Skript:**

```bash
git clone https://github.com/SaschaHenning/my-secrets ~/Code/my-secrets
cd ~/Code/my-secrets
./install.sh
```

Das Skript installiert alle Homebrew-Pakete, baut das Binary, legt es
nach `~/bin` (ohne sudo), ruft `mys init --install-skill` auf (das erledigt
inzwischen auch GPG-Key + gopass-Init) und trägt den MCP-Server in
`~/.claude/settings.json` ein. `mys install-skill` existiert weiterhin
als eigenständiger Befehl für manuelles Nachinstallieren — neu auch mit
`--scope local`, um den Skill nur im aktuellen Projektcheckout zu
verlinken.

Für den **manuellen Weg**, alle Voraussetzungen, Update-/Deinstall-Schritte
und Troubleshooting siehe [`INSTALL.md`](INSTALL.md).

**Claude Code**: Nach der Installation findet Claude den MCP-Server
automatisch beim nächsten Session-Start. Alle Zugriffe laufen dann über
`creds_list` / `creds_search` / `creds_get` und landen als
`actor_kind=ai` im Audit-Log.

## Schnellstart

```bash
# Secret anlegen
echo "ghp_xxx" | mys add work/github-token \
  --kind api_key --user you --url https://github.com \
  --github SaschaHenning/my-secrets --tags infra,ci

# Suchen
mys search github

# Lesen (maskiert)
mys get work/github-token

# Lesen mit Klartext-Passwort
mys get work/github-token --reveal

# Nur ein Feld holen
mys get work/github-token --field password --reveal

# Als ENV-Export
mys get work/github-token --format env --reveal

# Rotieren
echo "new-pw" | mys rotate work/github-token

# Löschen
mys rm work/github-token

# Audit-Log
mys audit tail --limit 30
mys audit tail --actor ai
mys audit verify                          # prüft Hash-Lücken
```

### Consumer-safe output

`mys get <path>` is for humans: it prints a labelled, multi-line record and
masks the password by default. Do not feed that text into `curl`, `DATABASE_URL`,
`Authorization`, or other machine consumers.

Use one of the narrow output modes instead:

```bash
# raw password value for a single process argument/env var
TOKEN="$(mys get work/github-token --field password --reveal)"

# shell env assignments for source/eval workflows
mys get work/github-token --format env --reveal

# machine-readable setup diagnostics
mys doctor --json
```

If `mys` is not on `PATH`, use the installed absolute path or run
`mys doctor` first; do not fall back to `gopass`, `bw`, `op`, `security`, or
direct password-store reads. `mys doctor` also strips known gopass banner noise
from its own probes, so prefer it when debugging setup/PATH problems.

## TOTP / 2FA

TOTP-Seeds (die Basis jeder „Authenticator-App") sind die zweitgrößte
Credential-Klasse nach Passwörtern — und die schmerzhafteste, wenn das
Telefon verloren geht. `my-secrets` speichert Seeds verschlüsselt im
gopass-Store und generiert den aktuellen Code deterministisch aus der
lokalen Uhr.

```bash
# Direkt aus dem QR-Code-URI hinzufügen (wie Google Authenticator ihn liest)
mys totp add work/github \
  "otpauth://totp/GitHub:you?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"

# Oder nur ein Base32-Seed, Metadaten via Flags
mys totp add work/aws JBSWY3DPEHPK3PXP --issuer AWS --label ops

# Aktuellen Code holen
mys totp work/github
#
# work/github (GitHub:you)
# 487 291     (19s left)

# Watch-Modus: aktualisiert sekündlich, Abbruch mit Ctrl-C
mys totp work/github --watch
```

`mys get work/github` zeigt die TOTP-Metadaten (Issuer, Label,
Algorithmus, Digits, Period) und maskiert den Seed. Nur `--reveal`
druckt ihn im Klartext.

Jede `mys totp <path>`-Code-Generierung erzeugt eine Audit-Zeile mit
`action=totp_generate` und `reason=window=<index>` (RFC-6238-Zeitfenster),
so dass wiederholte Aufrufe im selben 30-s-Fenster erkennbar bleiben.
Die Scope-Policy greift identisch zu `mys get`: AI-Aufrufer kommen nicht
an `private/**`.

## Domains und strukturierte Felder

Jeder Eintrag kann jenseits von `username` / `password` eine **Domain** und
eine Map von **Custom Fields** tragen. Die Domain wird aus `--url` automatisch
abgeleitet, wenn sie nicht explizit gesetzt ist; Felder haben frei wählbare
Keys, die dem Schema `^[a-z][a-z0-9_]{0,30}$` folgen müssen. Das Domain-
Matching kennt vier Tiers — exact, subdomain, substring und Levenshtein-
Fuzzy — damit auch Tippfehler und Teil-URLs den richtigen Eintrag finden.

```bash
# Speichern mit Domain + zwei strukturierten Feldern
mys add work/aws --domain aws.amazon.com \
  --field account_id=123 --field region=eu-central-1

# Subdomain-Treffer
mys ls --domain amazon.com             # findet alle Amazon-Einträge

# Fuzzy-Vorschlag bei Typo
mys ls --domain jazp.eu --similar      # schlägt jasp.eu als Typo-Korrektur vor

# Feld-Filter
mys ls --field region=eu-central-1     # AND-Filter über Fields-Map

# Einzelnes Custom-Feld lesen
mys get work/aws --field account_id    # druckt "123"
```

Für KI-Caller liefert der MCP-Server zusätzlich ein `similar[]`-Array mit
`tier` und `hint`, sobald `creds_search` keine direkten Treffer hat oder
`include_similar` explizit gesetzt ist — Passwörter tauchen darin niemals
auf, sondern nur Pfad, Tier und Begründung.

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
         -> create one with `mys key backup --paper`
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
echo "ghp_xxx" | mys add work/github-token --rotate-after 90d
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
work/github-token  112d old  rotate_after=90d
```

**Beim Rotieren wird der Zeitstempel automatisch gesetzt:**

```bash
echo "new-pw" | mys rotate work/github-token
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
nutzt du einen expliziten Shared-Mount mit einem eigenen Public Key pro
Person oder einen Tresor mit personalisiertem Login. Metadaten jedes
Backups landen in
`~/.local/share/my-secrets/backups.json` (niemals Key-Material) und als
`action=key_backup`-Zeile im Audit-Log.

## Web-UI

```bash
mys web --port 7823
# → http://127.0.0.1:7823
```

Login einmal (Touch ID, sonst macOS-Passwort). Die Startseite bietet
sofort ein Suchfeld (tippen + Enter → gefilterte Entries) und eine
Liste der zuletzt benutzten Einträge mit Ein-Klick-Passwort-Kopie.

Unter `/entries` gibt es einen Secrets-Browser als Tabelle: alle
sichtbaren Einträge laden sofort, gruppiert nach Org, mit Metadaten
(Kind, Tags, Domain, Username — immer sichtbar) und „zuletzt gelesen" je
Zeile. Das Suchfeld filtert **live im Browser**, ohne Seiten-Reload.
Jede Zeile hat zwei Kopier-Buttons: Nutzername und Passwort, beide
direkt aus der Liste. Werte bleiben sonst **immer maskiert**.

**Ganz ohne Maus:** tippen filtert; `↓`/`↑` wählt einen Treffer,
`Enter` kopiert dessen Passwort (oder den obersten Treffer, wenn keiner
markiert ist), `⇧ Enter` öffnet die Detailseite, `⌥ Enter` kopiert den
Nutzernamen, `Esc` setzt die Suche zurück. Auf der Detailseite bringt
`Esc` einen zurück zur Liste. Typischer Ablauf: App öffnen → Touch ID →
tippen → `Enter`.

**Reveal ist session-gebunden:** einmal eingeloggt, deckt/kopiert man
Werte ohne erneute Abfrage — bewusst so, weil die Konsole
(`mys get --reveal`) ohnehin ungebremst und mächtiger ist, eine
Pro-Reveal-Biometrie im lokalen Loopback-UI also nur Reibung ohne echten
Sicherheitsgewinn wäre. Was bleibt: die Scope-Policy prüft jeden Reveal
(verbotene Pfade → 403), und jeder Reveal erzeugt exakt dieselbe
`get`-Audit-Zeile wie `mys get --reveal`. „Zuletzt gelesen"/„zuletzt
benutzt" stammen ausschließlich aus diesen `get`-Zeilen — reines Browsen
zählt nicht als Lesen. Bindet ausschließlich auf das Loopback-Interface.

Die Detailseite zeigt außerdem eine „Historie"-Sektion mit den letzten
Git-Commits, die die verschlüsselte Datei des Eintrags verändert haben
(Hash, Zeitpunkt, Commit-Message aus dem gopass-Store selbst) — nützlich,
um zu sehen, wann ein Secret zuletzt geändert wurde, unabhängig vom
Audit-Log. Kein Entschlüsseln dafür nötig; fehlt `git` auf dem `PATH`
oder gibt es noch keine Historie, bleibt die Sektion einfach leer.

Screenshots siehe [`docs/screenshots/`](docs/screenshots).

### Als App aus dem Dock/Launchpad starten

Die Web-UI ist eine installierbare PWA: Chrome/Edge bieten „App
installieren" an, Safari „Zum Dock hinzufügen". `start_url` ist `/` —
nach dem Touch-ID-Login landest du sofort auf der Startseite mit
fokussiertem Suchfeld und „Zuletzt benutzt" (lädt instant, entschlüsselt
nichts; der Entries-Cache wird beim Serverstart im Hintergrund
vorgewärmt, damit auch die volle Liste und die Suche schnell sind).
Ein `?next=`-Parameter sorgt dafür, dass ein Tiefenlink (z. B. direkt zu
einem Eintrag) den Login-Umweg übersteht.

Damit ein Klick auf das App-Icon nicht auf „Verbindung abgelehnt" trifft
— `mys web` läuft normalerweise nur, solange du es manuell im Terminal
gestartet hast, und beendet sich nach 30 Minuten Inaktivität selbst —
gibt es einen Autostart via macOS LaunchAgent:

```bash
mys web install              # startet mys web beim Login, per Autostart
mys web status                # zeigt an, ob der LaunchAgent aktiv ist
mys web uninstall              # entfernt ihn wieder
```

`KeepAlive` ist bewusst unbedingt gesetzt: launchd startet den Prozess
auch nach dem regulären Idle-Shutdown sofort neu — das Sicherheitsverhalten
bleibt dabei unverändert, denn die Login-Session selbst läuft weiterhin
nach 30 Minuten Inaktivität ab; nur der Server-*Prozess* schläft nie
mehr dauerhaft ein, sodass der Port für den nächsten Klick immer
erreichbar ist. Jeder Neustart verlangt wieder Touch ID.

## Org-Scoping

Orgs = Top-Level-Ordner im gopass-Store. `~/.config/my-secrets/scope-policy.yaml`:

```yaml
actors:
  human:
    allow: ["**"]
  script:
    allow: ["**"]
  ai:
    allow: ["work/**", "home/**"]
    deny:  ["private/**"]
  claude-code:
    allow: ["work/**", "home/**"]
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

## Git-Sync: persönliche und explizit geteilte Mounts

### Persönlicher Store: nur deine eigenen Geräte

`mys sync setup` richtet weiterhin ausschließlich die Redundanz deines
**persönlichen** Stores zwischen deinen eigenen Geräten ein. Auch
`mys recipient add` ohne `--mount` ist nur für deine eigenen zusätzlichen
Geräte oder Hardware-Tokens gedacht. Füge dem persönlichen Store niemals
den Key einer anderen Person hinzu.

```bash
# Einmalig: GitHub-Repo anlegen, gopass-Remote setzen, initialer Push
mys sync setup

# Im CI / non-interaktiv (Defaults: single-repo, Protokoll via
# `gh auth status`, mit HTTPS-Fallback wenn SSH nicht erreichbar):
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

Die Web-UI (`/`) zeigt denselben letzten Sync-Zeitpunkt pro Remote an —
gelesen direkt aus `sync.yaml`, ohne Netzwerk-Check beim Seitenaufruf
(die Erreichbarkeitsprüfung bleibt `mys sync status` auf der CLI
vorbehalten).

### Shared-Mount: eigene GPG-Keys pro Teammitglied

Ein Team-Store ist ein **zusätzlicher**, ausdrücklich als `shared`
markierter gopass-Mount. Er verwendet keinen gemeinsam genutzten GPG-Key:
Jedes Teammitglied steuert seinen eigenen Public Key bei, und die
`.gpg-id` des Mounts enthält das exakte Team-Key-Set.

Die bevorzugte, wiederverwendbare Quelle dafür ist `team-keys.yaml`.
Sie wird zusammen mit optionalen armored Public-Key-Dateien im
Shared-Repo versioniert:

```yaml
version: 1
members:
  - name: Alice Example
    fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567
    email: alice@example.org
    public_key: keys/alice.asc
  - name: Bob Example
    fingerprint: 89ABCDEF0123456789ABCDEF0123456789ABCDEF
    email: bob@example.org
    public_key: keys/bob.asc
```

`name`, `fingerprint` und `email` sind Pflichtfelder. `public_key` ist
optional und muss relativ zum Verzeichnis der Manifestdatei liegen.
Mindestens einer der aufgeführten Keys muss auf der ausführenden Maschine
auch als Secret Key vorhanden sein, damit sie den neuen Mount benutzen
kann.

```bash
# Shared-Mount aus einem Team-Key-Manifest provisionieren. Ohne --remote
# wird das private GitHub-Repo über --owner/--repo angelegt oder angebunden.
mys sync shared setup \
  --mount jasp \
  --team-keys ./team-keys.yaml \
  --owner jasp \
  --repo mys-store-shared

# Alternativ einen vorhandenen Remote direkt angeben:
mys sync shared setup \
  --mount jasp \
  --team-keys ./team-keys.yaml \
  --remote /path/to/mys-store-shared.git

# Bootstrap-Alternative, wenn alle Public Keys bereits importiert sind:
mys sync shared setup \
  --mount jasp \
  --fingerprint 0123456789ABCDEF0123456789ABCDEF01234567 \
  --fingerprint 89ABCDEF0123456789ABCDEF0123456789ABCDEF \
  --remote /path/to/mys-store-shared.git
```

`--team-keys` und `--fingerprint` schließen einander aus. Die explizite
Fingerprint-Variante ist für bereits importierte Keys gedacht und legt
keine Identitäts-Map an; spätere Foreign-Team-Adds verlangen deshalb
trotzdem eine gültige `team-keys.yaml` im Live-Mount. Optional stehen
`--path`, `--https` und `--yes` zur Verfügung. Shared-Setup ist für
AI-Caller hart gesperrt; `--yes` überspringt nur die Rückfrage einer
menschlichen Ausführung. Der
Provisioner importiert angegebene Public-Key-Dateien, hängt den Mount an,
gleicht `.gpg-id` auf die gewählte Team-Key-Quelle ab, commitet ein
vorhandenes Manifest samt Key-Dateien, pusht den Remote und speichert den
Mount mit `shared: true` in
`~/.config/my-secrets/sync.yaml`. Ein bereits als persönlich
konfigurierter Mount lässt sich nicht stillschweigend in einen
Shared-Mount umdeuten.

Danach kann die Recipient-Verwaltung gezielt auf den Mount zeigen:

```bash
mys recipient list --mount jasp
mys recipient add ./keys/carol.asc --mount jasp
mys recipient remove <FINGERPRINT> --mount jasp
```

Ohne `--mount` bleibt das bisherige Verhalten für den persönlichen
Default-Store unverändert; dort bleiben Warnung und Bestätigung die
Schutzschranken für die Zusage des Menschen, nur einen eigenen Key
hinzuzufügen. Der neue mount-spezifische Team-Pfad akzeptiert einen
fremden Key dagegen nur für einen konfigurierten Shared-Mount. `add`
zeigt vor der Änderung den Fingerprint und verlangt die menschliche
Bestätigung; AI-Caller werden für `add` und `remove` weiterhin hart
abgewiesen. Ist ein neuer Fingerprint noch nicht in `team-keys.yaml`
enthalten, warnt der Befehl, statt die Aufnahme hart abzulehnen. Ergänze
das Manifest zeitnah: Beim nächsten Provisionierungsabgleich ist es
wieder die maßgebliche Quelle für das exakte Recipient-Set. Entsprechend
muss ein dauerhaft entferntes Mitglied auch aus `team-keys.yaml`
verschwinden; andernfalls fügt ein späterer Provisionierungsabgleich
seinen Key wieder hinzu.

### Trust Model und aktueller Ausbauzustand

Shared-Mounts aus Tier A sind **advisory**, nicht erzwingbar auditiert.
Jeder eingetragene Recipient kann die verschlüsselten Dateien lokal mit
nacktem `gpg` oder `gopass` außerhalb von `mys` entschlüsseln; dabei
entsteht keine Audit-Zeile. Das aktuelle Audit bleibt außerdem eine
lokale SQLite-Datenbank pro Maschine. Das Shared-Repo schafft in dieser
Ausbaustufe Team-Verfügbarkeit und eine Fingerprint-zu-Identität-Map,
aber noch keinen zentralen oder beweisbaren „wer hat was gelesen"-Nachweis.

In diesem Stand sind nur Tier-A-Phase 1 (Shared-Mount-Provisionierung)
und Phase 2 (mount-spezifische Recipient-Verwaltung) umgesetzt.
Bitwarden-Seeding, ein signiertes Team-Read-Audit, fail-closed
Shared-Policy und der Revocation-/Rotations-Runbook aus den Phasen 3–6
sind noch nicht implementiert. Beim Entfernen eines Team-Keys muss man
weiterhin davon ausgehen, dass die Person alle bisher zugänglichen
Secrets gelesen oder alte Ciphertext-Kopien behalten haben könnte;
betroffene Secrets müssen deshalb rotiert werden.

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

Dieser schreibgekoppelte Auto-Sync gilt nur für persönliche Remotes.
Shared-Mounts werden dabei bewusst übersprungen; ihre Provisionierung
pusht ihre eigenen Änderungen, und `mys sync push` / `mys sync pull`
lassen sich für einen expliziten manuellen Abgleich aller konfigurierten
Remotes verwenden.

Opt-out:

```bash
# Für diesen einen Aufruf:
mys add --no-sync work/foo

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
│   ├── history/       # Git-Log pro Eintrag (shellt zu `git`, mount-aware)
│   ├── sync/          # Git-Remotes + Shared-Mount-Provisionierung
│   ├── recipient/     # Mount-spezifische GPG-Recipients
│   ├── teamkeys/      # Striktes `team-keys.yaml`-Manifest
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
→ Neu: `mys init` bootstrappt Key + Store selbst. Sollte der Befehl
trotzdem abbrechen, prüfe `gpg --list-secret-keys` (mindestens ein
Secret-Key wird erwartet) und ob `gopass` auf PATH ist.

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
