# Mitwirken

<a href="../CONTRIBUTING.md">English</a> · <b>Deutsch</b>
<br /><br />

Danke, dass du dir die Zeit nimmst. Das Projekt ist klein, deshalb sind die Regeln kurz.

## Bevor du Code schreibst

**Mach zuerst ein Issue auf** — für alles ausser Tippfehlern und offensichtlichen Bugs. Dieses
Projekt trifft Sicherheitsabwägungen mit Absicht, und manche sehen wie ein Fehler aus, bis man den
Grund kennt. Die Begründungen liegen als Entscheidungsdokumente in [`backlog/`](../backlog/) —
bitte lies die passende, bevor du vorschlägst, sie umzustossen.

## Ablauf

- Arbeite auf einem **Feature-Branch**, nicht auf `main`.
- Fahre vor dem Push die volle Suite: `scripts/check.sh`. Sie muss grün sein, und zwar **zweimal
  hintereinander** — ein Test, der beim zweiten Lauf rot wird, ist kaputt, nicht der Code.
- Doku und `CHANGELOG.md` wandern im **selben Commit** mit der Änderung, die sie beschreiben.
- Halte Commits fokussiert. Ein Änderungsgrund pro Commit.

## Was die Suite prüft

Neben den Go-Tests erzwingt die Suite Repo-Hygiene: Pflichtdateien, per SHA gepinnte GitHub-Actions,
Workflow-Berechtigungen, Changelog-Struktur und dass die deutschen und englischen Dokumente dieselbe
Gestalt behalten. Schlägt die Hygiene an, behebe die Ursache — arbeite nicht am Check vorbei.

## Sicherheitsrelevante Änderungen

Alles, was Schlüsselbehandlung, Authentifizierung, Autorisierung oder die Aufzeichnung berührt,
braucht einen Test, der das behobene Problem gefunden hätte. Wenn du eine Schwachstelle gefunden
hast, folge bitte [SECURITY.de.md](SECURITY.de.md), statt einen Pull Request zu öffnen.

## Verhaltenskodex

Mit deiner Teilnahme stimmst du dem [Verhaltenskodex](CODE_OF_CONDUCT.de.md) zu.
<br /><br />
<p align="right"><img src="../docs/FlyingCerts.png" alt="FlyingCerts" width="60" height="60"></p>
