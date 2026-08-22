# Entscheidungen

Dauerhafte Festlegungen mit Datum und Begründung. `HANDOFF.md` ist nur die
Übergabe an die nächste Sitzung (≤ 80 Zeilen, wird ersetzt, nie ergänzt); was hier
steht, soll sie überleben. Muster und Fallen stehen in `wisdom.md`. Verworfene
Alternativen stehen mit dabei — ohne sie wird eine Entscheidung beim nächsten Mal
neu aufgerollt.

## 2026-07-24 — Geteilter Team-Store bleibt Tier A (git-basiert, offline, kein Server)

Der Shared-Store + das Read-Audit (PR #103) sind reine Git-Primitive: ein
gopass-Mount pro Team, ein GPG-Recipient pro Mitglied, signierte Audit-Events in
einem separaten Repo.

Verworfen: **Tier B / Broker** — ein Server mit durchsetzbarer per-Nutzer-Zugriffskontrolle.
Wäre die einzige Variante mit echter (nicht nur advisory) Durchsetzung, aber
Infrastruktur-Aufwand, den der Auftrag nicht deckte. Tier B bleibt als spätere
Option in `docs/SHARED-TEAM-RUNBOOK.md` benannt, falls durchsetzbare Kontrolle
je gebraucht wird.

## 2026-07-24 — Nutzeridentität = GPG-Signing-Key-Fingerprint

`team-keys.yaml` bildet Fingerprint → Name/E-Mail ab; das Audit identifiziert
Nutzer über den Signing-Key, nicht über einen selbstgemeldeten Namen.

Verworfen: Name/E-Mail als Primärschlüssel — nicht kryptographisch an den Schreiber
gebunden, ließe sich im Audit-Eintrag selbst fälschen. Der Fingerprint ist die
einzige Angabe, die die Signatur tatsächlich bestätigt.

## 2026-07-24 — Signiertes Read-Audit ist advisory, nicht enforceable

Jeder Recipient (Key in `.gpg-id`) kann ein Secret mit nacktem `gpg`/`pass`/`gopass`
lesen, ohne dass ein Audit-Eintrag entsteht. Tier A liefert ehrliche
Nachvollziehbarkeit für regelkonforme Clients (inklusive KI-Agent-Attribution),
aber keinen Schutz gegen einen umgehenden oder kompromittierten Nutzer. Dieser
Caveat steht bewusst im PR-Text und im Runbook, nicht nur im Code-Kommentar.

Verworfen: den Fakt zu verschweigen oder das Audit als „Kontrolle" zu vermarkten —
hätte dem Team ein falsches Sicherheitsgefühl gegeben. Vollständige Durchsetzung
bräuchte Tier B (siehe oben).

## 2026-07-24 — KI darf Shared-Secrets lesen, aber nur mit erfolgreichem Pflicht-Audit-Write (fail-closed)

Ein Read im Shared-Mount gelingt nur, wenn der signierte Audit-Eintrag geschrieben
werden konnte. Die vorhandene AI-Caller-Sperre von `bw-import` bleibt unabhängig
davon bestehen (Bitwarden-Import ist kein Read-Pfad).

Verworfen zwei Alternativen: (a) KI-Zugriff auf den Shared-Store grundsätzlich
sperren — hätte den eigentlichen Zweck (Team-Secrets für KI-Agenten nutzbar zu
machen) unterlaufen; (b) Audit best-effort/optional statt fail-closed — hätte
genau die Lücke offengelassen, die das Audit eigentlich schließen soll.

## 2026-07-24 — Audit-Ablage: separates Repo, Remote konfigurierbar

Default ist ein eigenes privates Repo für Audit-Events (append-only NDJSON pro
Nutzer), getrennt vom Secret-Store selbst; der Remote-Pfad ist aber ein
Config-Key, kein Hardcode.

Verworfen: Audit-Events im selben Repo wie die Secrets ablegen — vermischt
Zugriffs-Log und Zugriffs-Ziel und macht das Audit-Repo selbst zu einem
lohnenden Angriffsziel auf die Secrets.
