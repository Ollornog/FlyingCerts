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

## Der Doku-Schnellpfad

Eine Änderung, die **ausschließlich** Doku berührt, braucht weder die Go-Toolchain noch die
Test-CA. Die CI lässt beides weg und fährt stattdessen die Hygiene — zweimal, denn die
Wiederholbarkeit gilt auf jedem Pfad:

```bash
scripts/check.sh --nur-hygiene      # ~0,3 s statt ~50 s
```

Entschieden wird in `scripts/_nur_doku.sh`, dort steht zu jeder Grenze der Grund: `*.md` überall,
`docs/`, `i18n/`, `backlog/`, `LICENSE` gelten als Doku; alles andere bedeutet volle Suite, auch
`go.mod`, `examples/` und die Workflows selbst.

Zwei Dinge sind Absicht. **Die Hygiene fällt nie weg**: eine Dienst-Subdomain, ein Heimatpfad oder
ein Kundenname in einer README ist derselbe Verstoß wie einer im Code — Doku darf den kurzen Weg
nehmen, *weil* die Hygiene mitfährt, nicht weil Doku harmlos wäre. Und **im Zweifel läuft die volle
Suite**: leerer Diff, fehlender Basis-Commit, flacher Klon, Force-Push, manueller
`workflow_dispatch` — alles ergibt „nicht nur Doku".

Die Entscheidung sitzt auf **Schritt**-Bedingungen innerhalb des bestehenden Jobs, nie auf
`paths-ignore`. Ein per Pfadfilter unterdrückter Workflow legt seinen Check gar nicht an — er
bleibt auf `Pending` stehen und blockiert den Pull Request dauerhaft.

## Sicherheitsrelevante Änderungen

Alles, was Schlüsselbehandlung, Authentifizierung, Autorisierung oder die Aufzeichnung berührt,
braucht einen Test, der das behobene Problem gefunden hätte. Wenn du eine Schwachstelle gefunden
hast, folge bitte [SECURITY.de.md](SECURITY.de.md), statt einen Pull Request zu öffnen.

## Verhaltenskodex

Mit deiner Teilnahme stimmst du dem [Verhaltenskodex](CODE_OF_CONDUCT.de.md) zu.
<br /><br />
<p align="right"><img src="../docs/FlyingCerts.png" alt="FlyingCerts" width="60" height="60"></p>
