---
id: ADR-11
type: Decision
title: Restlaufzeiten werden nie auf ganze Tage gerundet
status: erledigt
tags: [betrieb, zeit]
created: 2026-09-19
---

## Kontext

Wann ist ein Zertifikat „bald faellig"? Die nachliegende Rechnung ist „Tage bis Ablauf".

CertMate rechnete genau so — und schnitt dabei ab. Jedes Zertifikat mit weniger als 24 Stunden
Restlaufzeit galt als **abgelaufen**, obwohl es gueltig war
([#829](https://github.com/fabriziosalmi/certmate/issues/829)). Der Erneuerungsplaner hielt es
daraufhin fuer dauerhaft faellig. Betroffen sind genau die kurzlebigen Zertifikate — und die
werden mehr, nicht weniger: Let's Encrypt bietet 6-Tage-Zertifikate an und verkuerzt die
Regellaufzeiten schrittweise.

## Wahl

Restlaufzeiten werden **als Dauer** gerechnet und verglichen, nie als Anzahl ganzer Tage. Kein
Abschneiden, keine Umwandlung in Tage fuer eine Entscheidung. Tage sind allenfalls eine Angabe
fuer Menschen — und dann gerundet dargestellt, nicht gerundet gerechnet.

## Konsequenzen

- Der Erneuerungszeitpunkt richtet sich nach ARI, wo die CA es anbietet, sonst nach einem
  **Anteil der Laufzeit** ([ADR-7](ADR-7-kein-weg-zurueck-nach-ablauf.md)) — beides bleibt bei
  einer Laufzeit von sechs Tagen ebenso richtig wie bei neunzig.
- Ein Test fuehrt ein Zertifikat mit wenigen Stunden Restlaufzeit; es darf weder als abgelaufen
  gelten noch eine Dauerschleife ausloesen.
